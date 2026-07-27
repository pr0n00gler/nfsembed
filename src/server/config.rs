use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::net::TcpListener;

use super::{Nfs4Limits, PortmapperSockets};
use crate::vfs::{ExportId, IdentityMapper, MigrationCoordinator, Nfs4FsLocations, StableScope, StableStateStore};

/// Protocol versions accepted by one server instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolSet {
    V3,
    V4,
    V3AndV4,
}

impl ProtocolSet {
    pub const fn includes_v3(self) -> bool {
        matches!(self, Self::V3 | Self::V3AndV4)
    }

    pub const fn includes_v4(self) -> bool {
        matches!(self, Self::V4 | Self::V3AndV4)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthPolicy {
    #[default]
    AuthSys,
    Anonymous,
    AuthSysOrAnonymous,
}

/// RPCSEC_GSS service used by a security flavor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RpcGssService {
    None,
    Integrity,
    Privacy,
    ChannelProtection,
}

/// One RPC authentication flavor advertised through NFSv4 SECINFO.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RpcSecurityFlavor {
    AuthNone,
    AuthSys,
    RpcSecGss {
        mechanism: Vec<u8>,
        qop: u32,
        service: RpcGssService,
    },
}

/// Stable NFSv4 `fsid4` identity for one exported filesystem.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileSystemId {
    pub major: u64,
    pub minor: u64,
}

impl FileSystemId {
    pub const fn new(major: u64, minor: u64) -> Self {
        Self { major, minor }
    }
}

/// Lifetime promised by filehandles issued for an export.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FileHandlePolicy {
    /// Authenticated handles include the current boot identity.
    Volatile,
    /// Handle keys and export identity are recovered from fenced stable state.
    Persistent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackTarget {
    pub network_id: String,
    pub universal_address: String,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CallbackError {
    #[error("callback target is invalid")]
    InvalidTarget,
    #[error("callback attempt timed out")]
    Timeout,
    #[error("callback transport is unavailable: {0}")]
    Unavailable(String),
    #[error("callback RPC failed: {0}")]
    Protocol(String),
}

/// One connected callback channel. Implementations must serialize calls for
/// transports that cannot safely multiplex RPC requests.
#[async_trait]
pub trait CallbackTransport: Send + Sync + 'static {
    async fn call(&self, encoded_rpc_call: Bytes, timeout: Duration) -> Result<Bytes, CallbackError>;
}

/// Application-overridable callback connection establishment.
#[async_trait]
pub trait CallbackConnector: Send + Sync + 'static {
    async fn connect(&self, target: &CallbackTarget) -> Result<Arc<dyn CallbackTransport>, CallbackError>;
}

/// Canonical binding exported by a secure lower-layer channel.
///
/// `canonical` must begin with `prefix`, followed by `:`, as required by
/// RFC 5056. The bytes after the colon are owned by the channel provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcChannelBinding {
    prefix: Vec<u8>,
    canonical: Bytes,
    confidentiality: bool,
}

impl RpcChannelBinding {
    pub fn new(
        prefix: impl Into<Vec<u8>>,
        canonical: impl Into<Bytes>,
        confidentiality: bool,
    ) -> Result<Self, ChannelBindingError> {
        let prefix = prefix.into();
        let canonical = canonical.into();
        if prefix.is_empty()
            || prefix.len() > 256
            || prefix.iter().any(|byte| *byte == b':' || !byte.is_ascii_graphic())
            || canonical.len() <= prefix.len()
            || canonical.len() > 64 * 1024
            || !canonical.starts_with(&prefix)
            || canonical.get(prefix.len()) != Some(&b':')
        {
            return Err(ChannelBindingError::Invalid);
        }
        Ok(Self {
            prefix,
            canonical,
            confidentiality,
        })
    }

    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn provides_confidentiality(&self) -> bool {
        self.confidentiality
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelBindingError {
    #[error("secure-channel binding is invalid")]
    Invalid,
    #[error("secure-channel binding is unavailable: {0}")]
    Unavailable(String),
}

/// Supplies binding material for the already-established lower-layer
/// connection. Returning `None` explicitly says the TCP channel is not
/// securely bound and therefore cannot use `rpc_gss_svc_channel_prot`.
#[async_trait]
pub trait ChannelBindingProvider: Send + Sync + 'static {
    async fn channel_binding(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Result<Option<RpcChannelBinding>, ChannelBindingError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeytabSource {
    Path(PathBuf),
    Bytes(Bytes),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KerberosCredentials {
    pub service_principal: String,
    pub keytab: KeytabSource,
}

impl KerberosCredentials {
    pub fn from_path(service_principal: impl Into<String>, keytab: impl Into<PathBuf>) -> Self {
        Self {
            service_principal: service_principal.into(),
            keytab: KeytabSource::Path(keytab.into()),
        }
    }

    pub fn from_bytes(service_principal: impl Into<String>, keytab: impl Into<Bytes>) -> Self {
        Self {
            service_principal: service_principal.into(),
            keytab: KeytabSource::Bytes(keytab.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DelegationPolicy {
    #[default]
    Disabled,
    Conservative {
        max_read_delegations: usize,
        max_write_delegations: usize,
        persistent: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SecurityPolicyError {
    #[error("a security policy must contain at least one flavor")]
    Empty,
    #[error("a security policy cannot contain duplicate flavors")]
    Duplicate,
    #[error("an RPCSEC_GSS mechanism identifier cannot be empty")]
    EmptyGssMechanism,
}

/// Ordered per-export security flavors.
///
/// Ordering is preserved in SECINFO replies, allowing an application to put
/// its preferred flavor first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityPolicy {
    flavors: Vec<RpcSecurityFlavor>,
}

impl SecurityPolicy {
    pub fn new(flavors: impl IntoIterator<Item = RpcSecurityFlavor>) -> Result<Self, SecurityPolicyError> {
        let flavors: Vec<_> = flavors.into_iter().collect();
        if flavors.is_empty() {
            return Err(SecurityPolicyError::Empty);
        }
        if flavors.iter().any(|flavor| {
            matches!(
                flavor,
                RpcSecurityFlavor::RpcSecGss {
                    mechanism,
                    ..
                } if mechanism.is_empty()
            )
        }) {
            return Err(SecurityPolicyError::EmptyGssMechanism);
        }
        if flavors
            .iter()
            .enumerate()
            .any(|(index, flavor)| flavors[..index].contains(flavor))
        {
            return Err(SecurityPolicyError::Duplicate);
        }
        Ok(Self { flavors })
    }

    pub fn auth_sys() -> Self {
        Self {
            flavors: vec![RpcSecurityFlavor::AuthSys],
        }
    }

    pub fn anonymous() -> Self {
        Self {
            flavors: vec![RpcSecurityFlavor::AuthNone],
        }
    }

    pub fn auth_sys_or_anonymous() -> Self {
        Self {
            flavors: vec![RpcSecurityFlavor::AuthSys, RpcSecurityFlavor::AuthNone],
        }
    }

    pub fn flavors(&self) -> &[RpcSecurityFlavor] {
        &self.flavors
    }

    pub fn allows(&self, flavor: &RpcSecurityFlavor) -> bool {
        self.flavors.contains(flavor)
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::auth_sys()
    }
}

/// Configuration for one independently backed export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportConfig {
    export_id: ExportId,
    path: String,
    fsid: FileSystemId,
    security_policy: SecurityPolicy,
    filehandle_policy: FileHandlePolicy,
}

impl ExportConfig {
    /// Creates a fully identified export.
    ///
    /// The filesystem identity and policies are deliberately required at the
    /// registration boundary. They affect wire-visible identity, security
    /// negotiation, and filehandle recovery, so the library must not infer
    /// them from an export ID or silently select policy defaults.
    pub fn new(
        export_id: ExportId,
        path: impl Into<String>,
        fsid: FileSystemId,
        security_policy: SecurityPolicy,
        filehandle_policy: FileHandlePolicy,
    ) -> Self {
        Self {
            export_id,
            path: path.into(),
            fsid,
            security_policy,
            filehandle_policy,
        }
    }

    pub fn with_fsid(mut self, fsid: FileSystemId) -> Self {
        self.fsid = fsid;
        self
    }

    pub fn with_security_policy(mut self, security_policy: SecurityPolicy) -> Self {
        self.security_policy = security_policy;
        self
    }

    pub fn with_filehandle_policy(mut self, policy: FileHandlePolicy) -> Self {
        self.filehandle_policy = policy;
        self
    }

    pub fn export_id(&self) -> ExportId {
        self.export_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn fsid(&self) -> FileSystemId {
        self.fsid
    }

    pub fn security_policy(&self) -> &SecurityPolicy {
        &self.security_policy
    }

    pub fn filehandle_policy(&self) -> FileHandlePolicy {
        self.filehandle_policy
    }
}

/// Caller-bound sockets consumed by `NfsServer::start` or `NfsServer::serve`.
pub struct ServerSockets {
    nfs: Vec<TcpListener>,
    mount: Option<TcpListener>,
    portmapper: Option<PortmapperSockets>,
}

impl ServerSockets {
    pub fn new(nfs: TcpListener) -> Self {
        Self {
            nfs: vec![nfs],
            mount: None,
            portmapper: None,
        }
    }

    /// Adds another NFS TCP endpoint backed by the same server state.
    pub fn with_nfs_listener(mut self, listener: TcpListener) -> Self {
        self.nfs.push(listener);
        self
    }

    /// Supplies the dedicated MOUNTv3 TCP endpoint.
    ///
    /// MOUNT is not multiplexed onto NFS listeners. When this listener is
    /// absent, the server does not expose the MOUNT program.
    pub fn with_mount_listener(mut self, listener: TcpListener) -> Self {
        self.mount = Some(listener);
        self
    }

    pub fn with_portmapper(mut self, portmapper: PortmapperSockets) -> Self {
        self.portmapper = Some(portmapper);
        self
    }

    pub fn nfs_listeners(&self) -> &[TcpListener] {
        &self.nfs
    }

    pub fn mount_listener(&self) -> Option<&TcpListener> {
        self.mount.as_ref()
    }

    pub(crate) fn into_parts(self) -> (Vec<TcpListener>, Option<TcpListener>, Option<PortmapperSockets>) {
        (self.nfs, self.mount, self.portmapper)
    }
}

impl From<TcpListener> for ServerSockets {
    fn from(listener: TcpListener) -> Self {
        Self::new(listener)
    }
}

impl fmt::Debug for ServerSockets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerSockets")
            .field(
                "nfs_addrs",
                &self
                    .nfs
                    .iter()
                    .filter_map(|listener| listener.local_addr().ok())
                    .collect::<Vec<_>>(),
            )
            .field("mount_addr", &self.mount.as_ref().and_then(|listener| listener.local_addr().ok()))
            .field("has_portmapper", &self.portmapper.is_some())
            .finish()
    }
}

/// How an NFSv4 server handles crash/restart recovery.
#[derive(Clone)]
pub enum Nfs4RecoveryMode {
    /// Keeps state only for the current process and rejects every reclaim after
    /// a restart. Intended for tests and explicitly ephemeral deployments.
    InMemoryRejectReclaims,
    /// Uses a fenced, application-owned store to honor valid reclaims.
    Durable(Arc<dyn StableStateStore>),
}

impl fmt::Debug for Nfs4RecoveryMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InMemoryRejectReclaims => formatter.write_str("InMemoryRejectReclaims"),
            Self::Durable(_) => formatter.write_str("Durable(..)"),
        }
    }
}

/// Required stateful-service configuration for NFSv4.0.
#[derive(Clone)]
pub struct Nfs4Config {
    recovery: Nfs4RecoveryMode,
    identity_mapper: Arc<dyn IdentityMapper>,
    migration: Option<Arc<dyn MigrationCoordinator>>,
    stable_scope: StableScope,
    lease_duration: Duration,
    grace_duration: Duration,
    callback_attempt_timeout: Duration,
    callback_connector: Option<Arc<dyn CallbackConnector>>,
    channel_binding_provider: Option<Arc<dyn ChannelBindingProvider>>,
    kerberos_credentials: Option<KerberosCredentials>,
    delegation_policy: DelegationPolicy,
    public_filehandle_path: String,
    namespace_locations: BTreeMap<ExportId, Nfs4FsLocations>,
    limits: Nfs4Limits,
}

impl Nfs4Config {
    const DEFAULT_SCOPE: &'static [u8] = b"nfsembed/default";
    const DEFAULT_LEASE: Duration = Duration::from_secs(90);
    const DEFAULT_GRACE: Duration = Duration::from_secs(90);
    const DEFAULT_CALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

    /// Creates an ephemeral server that rejects all restart reclaims.
    pub fn in_memory(
        identity_mapper: Arc<dyn IdentityMapper>,
        migration: Option<Arc<dyn MigrationCoordinator>>,
    ) -> Self {
        Self::new(Nfs4RecoveryMode::InMemoryRejectReclaims, identity_mapper, migration)
    }

    /// Creates a recoverable server. Durable mode cannot be represented
    /// without a stable store.
    pub fn durable(
        store: Arc<dyn StableStateStore>,
        identity_mapper: Arc<dyn IdentityMapper>,
        migration: Option<Arc<dyn MigrationCoordinator>>,
    ) -> Self {
        Self::new(Nfs4RecoveryMode::Durable(store), identity_mapper, migration)
    }

    fn new(
        recovery: Nfs4RecoveryMode,
        identity_mapper: Arc<dyn IdentityMapper>,
        migration: Option<Arc<dyn MigrationCoordinator>>,
    ) -> Self {
        Self {
            recovery,
            identity_mapper,
            migration,
            stable_scope: StableScope::from(Self::DEFAULT_SCOPE),
            lease_duration: Self::DEFAULT_LEASE,
            grace_duration: Self::DEFAULT_GRACE,
            callback_attempt_timeout: Self::DEFAULT_CALLBACK_TIMEOUT,
            callback_connector: None,
            channel_binding_provider: None,
            kerberos_credentials: None,
            delegation_policy: DelegationPolicy::default(),
            public_filehandle_path: "/".to_owned(),
            namespace_locations: BTreeMap::new(),
            limits: Nfs4Limits::default(),
        }
    }

    pub fn with_stable_scope(mut self, scope: StableScope) -> Self {
        self.stable_scope = scope;
        self
    }

    pub fn with_lease_duration(mut self, duration: Duration) -> Self {
        self.lease_duration = duration;
        self
    }

    pub fn with_grace_duration(mut self, duration: Duration) -> Self {
        self.grace_duration = duration;
        self
    }

    pub fn with_callback_attempt_timeout(mut self, duration: Duration) -> Self {
        self.callback_attempt_timeout = duration;
        self
    }

    pub fn with_callback_connector(mut self, connector: Arc<dyn CallbackConnector>) -> Self {
        self.callback_connector = Some(connector);
        self
    }

    pub fn with_channel_binding_provider(mut self, provider: Arc<dyn ChannelBindingProvider>) -> Self {
        self.channel_binding_provider = Some(provider);
        self
    }

    pub fn with_kerberos_credentials(mut self, credentials: KerberosCredentials) -> Self {
        self.kerberos_credentials = Some(credentials);
        self
    }

    pub fn with_delegation_policy(mut self, policy: DelegationPolicy) -> Self {
        self.delegation_policy = policy;
        self
    }

    pub fn with_public_filehandle_path(mut self, path: impl Into<String>) -> Self {
        self.public_filehandle_path = path.into();
        self
    }

    pub fn with_namespace_locations(mut self, export_id: ExportId, locations: Nfs4FsLocations) -> Self {
        self.namespace_locations.insert(export_id, locations);
        self
    }

    pub fn with_limits(mut self, limits: Nfs4Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn recovery_mode(&self) -> &Nfs4RecoveryMode {
        &self.recovery
    }

    pub fn stable_store(&self) -> Option<&Arc<dyn StableStateStore>> {
        match &self.recovery {
            Nfs4RecoveryMode::InMemoryRejectReclaims => None,
            Nfs4RecoveryMode::Durable(store) => Some(store),
        }
    }

    pub fn identity_mapper(&self) -> &Arc<dyn IdentityMapper> {
        &self.identity_mapper
    }

    pub fn migration_coordinator(&self) -> Option<&Arc<dyn MigrationCoordinator>> {
        self.migration.as_ref()
    }

    pub fn stable_scope(&self) -> &StableScope {
        &self.stable_scope
    }

    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    pub fn grace_duration(&self) -> Duration {
        self.grace_duration
    }

    pub fn callback_attempt_timeout(&self) -> Duration {
        self.callback_attempt_timeout
    }

    pub fn callback_connector(&self) -> Option<&Arc<dyn CallbackConnector>> {
        self.callback_connector.as_ref()
    }

    pub fn channel_binding_provider(&self) -> Option<&Arc<dyn ChannelBindingProvider>> {
        self.channel_binding_provider.as_ref()
    }

    pub fn kerberos_credentials(&self) -> Option<&KerberosCredentials> {
        self.kerberos_credentials.as_ref()
    }

    pub fn delegation_policy(&self) -> DelegationPolicy {
        self.delegation_policy
    }

    pub fn public_filehandle_path(&self) -> &str {
        &self.public_filehandle_path
    }

    pub fn namespace_locations(&self) -> &BTreeMap<ExportId, Nfs4FsLocations> {
        &self.namespace_locations
    }

    pub fn limits(&self) -> &Nfs4Limits {
        &self.limits
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.stable_scope.as_bytes().is_empty() || self.stable_scope.as_bytes().len() > 1024 {
            return Err("NFSv4 stable scope must contain between 1 and 1024 bytes");
        }
        if self.lease_duration.is_zero() || self.grace_duration.is_zero() || self.callback_attempt_timeout.is_zero() {
            return Err("NFSv4 lease, grace, and callback durations must be greater than zero");
        }
        if self.lease_duration.subsec_nanos() != 0
            || self.grace_duration.subsec_nanos() != 0
            || self.lease_duration.as_secs() == 0
            || self.grace_duration.as_secs() == 0
        {
            return Err("NFSv4 lease and grace durations must be whole positive seconds");
        }
        if self.lease_duration.as_secs() > u32::MAX as u64 || self.grace_duration.as_secs() > u32::MAX as u64 {
            return Err("NFSv4 lease and grace durations exceed the wire range");
        }
        if self.grace_duration < self.lease_duration {
            return Err("NFSv4 grace duration must be at least the lease duration");
        }
        if !canonical_absolute_path(&self.public_filehandle_path) {
            return Err("NFSv4 public filehandle path must be absolute and canonical");
        }
        if let Some(credentials) = &self.kerberos_credentials {
            if credentials.service_principal.is_empty() || credentials.service_principal.as_bytes().contains(&0) {
                return Err("Kerberos service principal is invalid");
            }
            match &credentials.keytab {
                KeytabSource::Path(path) if path.as_os_str().is_empty() => return Err("Kerberos keytab path is empty"),
                KeytabSource::Bytes(bytes) if bytes.is_empty() => return Err("Kerberos keytab is empty"),
                _ => {},
            }
        }
        if matches!(
            self.delegation_policy,
            DelegationPolicy::Conservative {
                max_read_delegations: 0,
                ..
            } | DelegationPolicy::Conservative {
                max_write_delegations: 0,
                ..
            }
        ) {
            return Err("NFSv4 delegation limits must be greater than zero");
        }
        if matches!(self.delegation_policy, DelegationPolicy::Conservative { persistent: true, .. })
            && !matches!(&self.recovery, Nfs4RecoveryMode::Durable(_))
        {
            return Err("persistent delegations require durable fenced state");
        }
        self.limits.validate()
    }
}

impl fmt::Debug for Nfs4Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Nfs4Config")
            .field("recovery", &self.recovery)
            .field("migration", &self.migration.is_some())
            .field("stable_scope", &self.stable_scope)
            .field("lease_duration", &self.lease_duration)
            .field("grace_duration", &self.grace_duration)
            .field("callback_attempt_timeout", &self.callback_attempt_timeout)
            .field("callback_connector", &self.callback_connector.is_some())
            .field("channel_binding_provider", &self.channel_binding_provider.is_some())
            .field("kerberos_credentials", &self.kerberos_credentials.is_some())
            .field("delegation_policy", &self.delegation_policy)
            .field("public_filehandle_path", &self.public_filehandle_path)
            .field("namespace_locations", &self.namespace_locations)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn canonical_absolute_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && !path.as_bytes().contains(&0)
            && !path.ends_with('/')
            && !path.split('/').skip(1).any(|component| {
                component.is_empty() || component == "." || component == ".." || component.len() > 255
            }))
}
