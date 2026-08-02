mod builder;
mod config;
mod connection;
mod handle;
mod limits;
pub(crate) mod migration;
mod portmapper;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

pub use builder::NfsServerBuilder;
pub use config::{
    AuthPolicy, CallbackConnector, CallbackError, CallbackTarget, CallbackTransport, ChannelBindingError,
    ChannelBindingProvider, DelegationPolicy, ExportConfig, FileHandlePolicy, FileSystemId, KerberosCredentials,
    KeytabSource, Nfs4Config, Nfs4RecoveryMode, ProtocolSet, RpcChannelBinding, RpcGssService, RpcSecurityFlavor,
    SecurityPolicy, SecurityPolicyError, ServerSockets,
};
use connection::{serve_connection, ConnectionState, ListenerRole};
pub use handle::{EndpointInfo, NfsServerHandle};
pub use limits::{Nfs4Limits, ServerLimits};
pub use migration::{MigrationBundle, MigrationBundleError, MigrationBundleLimits, MigrationControlError, MigrationId};
pub use portmapper::PortmapperSockets;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, Semaphore};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{timeout_at, Instant};

use crate::handles::{HandleCodec, HandleCodecSet, HandleLifetime};
use crate::replay::{ReplayCache, ReplayError};
use crate::rpc::codec::{DecodeError, EncodeError};
use crate::rpc::record::RecordError;
use crate::vfs::VirtualFileSystem;

pub(crate) struct ExecutionTracker {
    tasks: Mutex<JoinSet<()>>,
    active: AtomicUsize,
    draining: std::sync::atomic::AtomicBool,
    closed: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    failure: StdMutex<Option<JoinError>>,
}

impl ExecutionTracker {
    fn new() -> Self {
        Self {
            tasks: Mutex::new(JoinSet::new()),
            active: AtomicUsize::new(0),
            draining: std::sync::atomic::AtomicBool::new(false),
            closed: std::sync::atomic::AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
            failure: StdMutex::new(None),
        }
    }

    pub(crate) async fn spawn<F>(self: &Arc<Self>, future: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.closed.load(Ordering::Acquire) {
            return Err(ServerError::ShuttingDown);
        }
        let mut tasks = self.tasks.lock().await;
        self.reap_ready(&mut tasks);
        if self.closed.load(Ordering::Acquire)
            || (self.draining.load(Ordering::Acquire) && self.active.load(Ordering::Acquire) == 0)
        {
            return Err(ServerError::ShuttingDown);
        }
        self.active.fetch_add(1, Ordering::AcqRel);
        let active = ActiveExecution { tracker: self.clone() };
        tasks.spawn(async move {
            let _active = active;
            future.await;
        });
        Ok(())
    }

    async fn wait(&self) -> Result<(), JoinError> {
        self.draining.store(true, Ordering::Release);
        loop {
            let notified = self.notify.notified();
            {
                let mut tasks = self.tasks.lock().await;
                self.reap_ready(&mut tasks);
            }
            if self.active.load(Ordering::Acquire) == 0 {
                // No live tracked parent remains that could admit a nested
                // child. It is now safe to hold the task mutex until Tokio
                // publishes and joins every terminal result; an atomic count
                // transition alone is not a synchronization guarantee for a
                // late panic result.
                let mut tasks = self.tasks.lock().await;
                if self.active.load(Ordering::Acquire) != 0 {
                    drop(tasks);
                    continue;
                }
                while let Some(result) = tasks.join_next().await {
                    self.record_result(result);
                }
                if let Some(error) = self.failure.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
                    return Err(error);
                }
                return Ok(());
            }
            notified.await;
        }
    }

    async fn abort_all(&self) {
        self.closed.store(true, Ordering::Release);
        self.draining.store(true, Ordering::Release);
        self.tasks.lock().await.abort_all();
    }

    fn reap_ready(&self, tasks: &mut JoinSet<()>) {
        while let Some(result) = tasks.try_join_next() {
            self.record_result(result);
        }
    }

    fn record_result(&self, result: Result<(), JoinError>) {
        if let Err(error) = result {
            tracing::warn!(error = %error, "request execution task failed");
            let mut failure = self.failure.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if failure.is_none() {
                *failure = Some(error);
            }
        }
    }
}

struct ActiveExecution {
    tracker: Arc<ExecutionTracker>,
}

impl Drop for ActiveExecution {
    fn drop(&mut self) {
        if self.tracker.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.notify.notify_one();
        }
    }
}

#[derive(Clone)]
pub(crate) struct ExportState {
    pub vfs: Arc<dyn VirtualFileSystem>,
    pub id: crate::vfs::ExportId,
    pub path: String,
    pub fsid: FileSystemId,
    pub security_policy: SecurityPolicy,
    pub filehandle_policy: FileHandlePolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("invalid server configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Decode(DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error("replay waiter closed")]
    ReplayWaiterClosed(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("server task failed: {0}")]
    Task(JoinError),
    #[error("server is shutting down")]
    ShuttingDown,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("request timed out")]
    RequestTimeout,
    #[error("NFSv4 stable state failed: {0}")]
    StableState(String),
    #[error("RPCSEC_GSS initialization failed: {0}")]
    Gss(String),
    #[error("NFSv4 state initialization failed: {0}")]
    Nfs4State(String),
    #[error("NFSv4 migration initialization failed: {0}")]
    Migration(String),
    #[error("operating-system random source failed: {0}")]
    Entropy(#[from] rand::Error),
}

pub struct NfsServer {
    protocols: ProtocolSet,
    exports: Arc<Vec<ExportState>>,
    limits: ServerLimits,
    nfs4_config: Option<Nfs4Config>,
    auth_policy: AuthPolicy,
}

impl NfsServer {
    pub fn builder(protocols: ProtocolSet) -> NfsServerBuilder {
        NfsServerBuilder::new(protocols)
    }

    pub(crate) fn from_builder(builder: NfsServerBuilder) -> Result<Self, ServerError> {
        Ok(Self {
            protocols: builder.protocols,
            exports: Arc::new(builder.exports),
            limits: builder.limits,
            nfs4_config: builder.nfs4_config,
            auth_policy: builder.auth_policy,
        })
    }

    pub fn protocols(&self) -> ProtocolSet {
        self.protocols
    }

    pub fn nfs4_config(&self) -> Option<&Nfs4Config> {
        self.nfs4_config.as_ref()
    }

    pub async fn start(&self, sockets: ServerSockets) -> Result<NfsServerHandle, ServerError> {
        let (listeners, mount, portmapper) = sockets.into_parts();
        self.start_inner(listeners, mount, portmapper).await
    }

    async fn start_inner(
        &self,
        listeners: Vec<TcpListener>,
        mount: Option<TcpListener>,
        portmapper: Option<PortmapperSockets>,
    ) -> Result<NfsServerHandle, ServerError> {
        if mount.is_some() && !self.protocols.includes_v3() {
            return Err(ServerError::InvalidConfiguration("MOUNT sockets require NFSv3"));
        }
        let nfs_addresses = listeners.iter().map(TcpListener::local_addr).collect::<Result<Vec<_>, _>>()?;
        let primary_addr = *nfs_addresses
            .first()
            .ok_or(ServerError::InvalidConfiguration("at least one NFS listener is required"))?;
        let mount_address = mount.as_ref().map(TcpListener::local_addr).transpose()?;
        validate_mount_address(&nfs_addresses, mount_address)?;
        let mount_port = mount_address.map(|address| address.port());
        let endpoint_infos = self.endpoint_infos(&nfs_addresses, mount_port);
        let portmapper = portmapper
            .map(|sockets| sockets.prepare(primary_addr.port(), mount_port, self.protocols))
            .transpose()?;
        let portmapper_addr = portmapper.as_ref().map(|portmapper| portmapper.local_addr);
        let listeners = listener_roles(listeners, mount);
        let (shutdown, receive) = watch::channel(false);
        let (state, executions, migration) = self.connection_state().await?;
        let deadline = self.limits.graceful_shutdown_timeout;
        let task = tokio::spawn(async move { run(listeners, portmapper, receive, state, executions, deadline).await });
        let handle = NfsServerHandle::new(endpoint_infos, portmapper_addr, shutdown, task);
        Ok(match migration {
            Some(migration) => handle.with_migration(migration),
            None => handle,
        })
    }

    pub async fn serve<F>(&self, sockets: ServerSockets, shutdown_signal: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send,
    {
        let (listeners, mount, portmapper) = sockets.into_parts();
        self.serve_inner(listeners, mount, portmapper, shutdown_signal).await
    }

    async fn serve_inner<F>(
        &self,
        listeners: Vec<TcpListener>,
        mount: Option<TcpListener>,
        portmapper: Option<PortmapperSockets>,
        shutdown_signal: F,
    ) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send,
    {
        if mount.is_some() && !self.protocols.includes_v3() {
            return Err(ServerError::InvalidConfiguration("MOUNT sockets require NFSv3"));
        }
        let nfs_addresses = listeners.iter().map(TcpListener::local_addr).collect::<Result<Vec<_>, _>>()?;
        let primary_addr = *nfs_addresses
            .first()
            .ok_or(ServerError::InvalidConfiguration("at least one NFS listener is required"))?;
        let mount_address = mount.as_ref().map(TcpListener::local_addr).transpose()?;
        validate_mount_address(&nfs_addresses, mount_address)?;
        let mount_port = mount_address.map(|address| address.port());
        let portmapper = portmapper
            .map(|sockets| sockets.prepare(primary_addr.port(), mount_port, self.protocols))
            .transpose()?;
        let listeners = listener_roles(listeners, mount);
        let (shutdown, receive) = watch::channel(false);
        let signal_task = async move {
            shutdown_signal.await;
            let _ = shutdown.send(true);
        };
        let (state, executions, _migration) = self.connection_state().await?;
        tokio::pin!(signal_task);
        let server = run(listeners, portmapper, receive, state, executions, self.limits.graceful_shutdown_timeout);
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result,
            _ = &mut signal_task => server.await,
        }
    }

    fn endpoint_infos(&self, nfs_addresses: &[SocketAddr], mount_port: Option<u16>) -> Vec<EndpointInfo> {
        let versions: &[crate::vfs::ProtocolVersion] = match self.protocols {
            ProtocolSet::V3 => &[crate::vfs::ProtocolVersion::V3],
            ProtocolSet::V4 => &[crate::vfs::ProtocolVersion::V4],
            ProtocolSet::V3AndV4 => &[crate::vfs::ProtocolVersion::V3, crate::vfs::ProtocolVersion::V4],
        };
        nfs_addresses
            .iter()
            .flat_map(|address| {
                self.exports.iter().flat_map(move |export| {
                    versions.iter().copied().map(move |version| EndpointInfo {
                        version,
                        address: *address,
                        export_path: export.path.clone(),
                        nfs_port: address.port(),
                        mount_port: (version == crate::vfs::ProtocolVersion::V3).then_some(mount_port).flatten(),
                    })
                })
            })
            .collect()
    }

    async fn connection_state(
        &self,
    ) -> Result<(Arc<ConnectionState>, Arc<ExecutionTracker>, Option<Arc<migration::MigrationControl>>), ServerError>
    {
        let executions = Arc::new(ExecutionTracker::new());
        let nfs4_limits = self
            .nfs4_config
            .as_ref()
            .map_or_else(Nfs4Limits::default, |config| config.limits().clone());
        let mut nfs4_namespace = crate::nfs4::namespace::PseudoNamespace::new(nfs4_limits.max_state_objects)
            .map_err(|_| ServerError::InvalidConfiguration("NFSv4 pseudo-filesystem limit is invalid"))?;
        if self.protocols.includes_v4() {
            for export in self.exports.iter() {
                nfs4_namespace
                    .add_export(&export.path, export.id)
                    .map_err(|_| ServerError::InvalidConfiguration("NFSv4 pseudo-filesystem cannot contain exports"))?;
            }
        }
        let nfs4_public_filehandle_node = if self.protocols.includes_v4() {
            let path = self
                .nfs4_config
                .as_ref()
                .expect("NFSv4 protocol selection requires NFSv4 configuration")
                .public_filehandle_path();
            nfs4_namespace.resolve_absolute_path(path).map_err(|_| {
                ServerError::InvalidConfiguration(
                    "NFSv4 public filehandle path does not identify a pseudo-filesystem node",
                )
            })?
        } else {
            crate::nfs4::namespace::NamespaceNodeId::ROOT
        };
        let nfs4_lease_seconds = self
            .nfs4_config
            .as_ref()
            .map_or(90, |config| u32::try_from(config.lease_duration().as_secs()).unwrap_or(u32::MAX));
        let (
            logical_handles,
            volatile_handles,
            stable_journal,
            runtime_boot_tag,
            runtime_write_verifier,
            runtime_recovered,
            delegation_reservation_scope,
        ) = match self.nfs4_config.as_ref().map(Nfs4Config::recovery_mode) {
            Some(Nfs4RecoveryMode::Durable(store)) => {
                let limits = crate::nfs4::stable::StableJournalLimits {
                    max_records: nfs4_limits.max_state_objects,
                    max_batch_mutations: nfs4_limits.max_state_objects.saturating_add(1),
                    max_key_bytes: nfs4_limits.max_client_owner_size.saturating_add(64),
                    max_payload_bytes: nfs4_limits.max_state_payload_size,
                };
                let started_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
                    .unwrap_or_else(|error| -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX));
                let journal = crate::nfs4::stable::StableJournal::initialize(
                    store.clone(),
                    self.nfs4_config
                        .as_ref()
                        .expect("durable recovery has NFSv4 config")
                        .stable_scope()
                        .clone(),
                    started_at,
                    limits,
                )
                .await
                .map_err(|error| ServerError::StableState(error.to_string()))?;
                let logical_handles = journal.handle_codec();
                let volatile_handles = HandleCodec::try_random()?;
                let runtime_boot_tag = journal.boot().boot_tag;
                let runtime_write_verifier = journal.boot().verifier;
                let runtime_recovered = Some(journal.recovery().clone());
                let delegation_reservation_scope = journal.fence_token().clone();
                (
                    logical_handles,
                    volatile_handles,
                    Some(Arc::new(Mutex::new(journal))),
                    runtime_boot_tag,
                    runtime_write_verifier,
                    runtime_recovered,
                    delegation_reservation_scope,
                )
            },
            _ => {
                let logical_handles = HandleCodec::try_random()?;
                let volatile_handles = HandleCodec::try_random()?;
                let mut runtime_write_verifier = [0; 8];
                OsRng.try_fill_bytes(&mut runtime_write_verifier)?;
                let mut runtime_boot_tag =
                    u32::from_be_bytes(runtime_write_verifier[..4].try_into().expect("four-byte prefix"));
                if runtime_boot_tag == 0 || runtime_boot_tag == u32::MAX {
                    runtime_boot_tag = 1;
                }
                let delegation_reservation_scope = crate::vfs::StableFenceToken::new(runtime_write_verifier.to_vec());
                (
                    logical_handles,
                    volatile_handles,
                    None,
                    runtime_boot_tag,
                    runtime_write_verifier,
                    None,
                    delegation_reservation_scope,
                )
            },
        };
        let handles = HandleCodecSet::new(
            logical_handles,
            volatile_handles,
            self.exports.iter().map(|export| {
                (
                    export.id,
                    match export.filehandle_policy {
                        FileHandlePolicy::Volatile => HandleLifetime::Volatile,
                        FileHandlePolicy::Persistent => HandleLifetime::Persistent,
                    },
                )
            }),
        );
        let nfs4_runtime = crate::nfs4::runtime::Nfs4Runtime::new(crate::nfs4::runtime::RuntimeConfig {
            lease_duration: self
                .nfs4_config
                .as_ref()
                .map_or(std::time::Duration::from_secs(90), Nfs4Config::lease_duration),
            grace_duration: self
                .nfs4_config
                .as_ref()
                .map_or(std::time::Duration::from_secs(90), Nfs4Config::grace_duration),
            limits: nfs4_limits.clone(),
            boot_tag: runtime_boot_tag,
            write_verifier: runtime_write_verifier,
            stable_journal: stable_journal.clone(),
            recovered: runtime_recovered.clone(),
        })
        .map_err(|error| ServerError::Nfs4State(error.to_string()))?;
        let delegation_clock: Arc<dyn crate::nfs4::callback::CallbackClock> =
            Arc::new(crate::nfs4::callback::SystemCallbackClock::default());
        let delegation_client_state = crate::nfs4::delegation::DelegationClientState::new();
        let mut nfs4_delegations = std::collections::HashMap::with_capacity(self.exports.len());
        for export in self.exports.iter() {
            let supports_delegations = export
                .vfs
                .nfs4_capabilities()
                .is_some_and(|capabilities| capabilities.delegations);
            let policy = if supports_delegations {
                self.nfs4_config
                    .as_ref()
                    .map_or(DelegationPolicy::Disabled, Nfs4Config::delegation_policy)
            } else {
                DelegationPolicy::Disabled
            };
            let persistent = matches!(policy, DelegationPolicy::Conservative { persistent: true, .. });
            if !matches!(policy, DelegationPolicy::Disabled) {
                export
                    .vfs
                    .nfs4_fence_delegation_reservations(&delegation_reservation_scope)
                    .await
                    .map_err(|error| ServerError::Nfs4State(error.to_string()))?;
            }
            let manager = crate::nfs4::delegation::DelegationManager::with_boot_tag_stable_state_and_scope(
                export.vfs.clone(),
                policy,
                self.nfs4_config
                    .as_ref()
                    .map_or(std::time::Duration::from_secs(90), Nfs4Config::lease_duration),
                delegation_clock.clone(),
                runtime_boot_tag,
                stable_journal.clone().filter(|_| persistent),
                runtime_recovered.as_ref().filter(|_| persistent),
                Some(export.id),
                delegation_reservation_scope.clone(),
                delegation_client_state.clone(),
            )
            .map_err(|error| ServerError::Nfs4State(error.to_string()))?;
            nfs4_delegations.insert(export.id, Arc::new(manager));
        }
        let nfs4_delegations = Arc::new(nfs4_delegations);
        let migration = match self.nfs4_config.as_ref().and_then(Nfs4Config::migration_coordinator) {
            Some(coordinator) => {
                let journal = stable_journal
                    .clone()
                    .ok_or(ServerError::InvalidConfiguration("NFSv4 migration requires durable fenced state"))?;
                let limits = MigrationBundleLimits {
                    max_encoded_bytes: nfs4_limits.max_state_payload_size,
                    max_records: nfs4_limits.max_state_objects.saturating_sub(1).max(1),
                    max_key_bytes: nfs4_limits.max_client_owner_size.saturating_add(64),
                    max_record_payload_bytes: nfs4_limits.max_state_payload_size,
                    max_coordinator_token_bytes: nfs4_limits.max_client_owner_size.max(1),
                };
                Some(
                    migration::MigrationControl::new(
                        coordinator.clone(),
                        journal,
                        nfs4_runtime.clone(),
                        nfs4_delegations.clone(),
                        self.exports.iter().map(|export| migration::MigrationExportIdentity {
                            export_id: export.id,
                            fsid: export.fsid,
                            persistent_handles: export.filehandle_policy == FileHandlePolicy::Persistent,
                        }),
                        limits,
                    )
                    .await
                    .map_err(|error| ServerError::Migration(error.to_string()))?,
                )
            },
            None => None,
        };
        let (gss_contexts, nfs4_callback_gss_initiator) =
            match self.nfs4_config.as_ref().and_then(Nfs4Config::kerberos_credentials) {
                Some(credentials) => {
                    let provider = match &credentials.keytab {
                        KeytabSource::Path(path) => {
                            crate::rpc::gss::SspiGssProvider::from_keytab_path(
                                credentials.service_principal.clone(),
                                path.clone(),
                            )
                            .await
                        },
                        KeytabSource::Bytes(bytes) => crate::rpc::gss::SspiGssProvider::from_keytab_bytes(
                            credentials.service_principal.clone(),
                            bytes.clone(),
                        ),
                    }
                    .map_err(|error| ServerError::Gss(error.to_string()))?;
                    let mut wire_limits = crate::rpc::gss::GssLimits::default();
                    wire_limits.max_token_bytes = wire_limits.max_token_bytes.min(self.limits.max_rpc_record_size);
                    wire_limits.max_protected_body_bytes =
                        wire_limits.max_protected_body_bytes.min(self.limits.max_rpc_record_size);
                    let registry = crate::rpc::gss::GssContextRegistry::new(
                        Arc::new(provider),
                        crate::rpc::gss::GssContextLimits {
                            max_contexts: nfs4_limits.max_clients,
                            sequence_window: 128,
                            wire: wire_limits,
                        },
                    )
                    .map_err(|error| ServerError::Gss(error.to_string()))?;
                    let initiator: Arc<dyn crate::rpc::gss::GssInitiatorProvider> = match &credentials.keytab {
                        KeytabSource::Path(path) => Arc::new(
                            crate::rpc::gss::SspiGssInitiator::from_keytab_path(
                                credentials.service_principal.clone(),
                                path.clone(),
                            )
                            .await
                            .map_err(|error| ServerError::Gss(error.to_string()))?,
                        ),
                        KeytabSource::Bytes(bytes) => Arc::new(
                            crate::rpc::gss::SspiGssInitiator::from_keytab_bytes(
                                credentials.service_principal.clone(),
                                bytes.clone(),
                            )
                            .map_err(|error| ServerError::Gss(error.to_string()))?,
                        ),
                    };
                    (Some(Arc::new(registry)), Some(initiator))
                },
                None => (None, None),
            };
        let open_pin_capacity = nfs4_limits.max_state_objects.saturating_add(self.limits.max_inflight_requests);
        let nfs4_open_pins = crate::nfs4::open_pins::OpenPinManager::new(&self.exports, open_pin_capacity)
            .map_err(ServerError::InvalidConfiguration)?;
        let state = Arc::new(ConnectionState {
            protocols: self.protocols,
            exports: self.exports.clone(),
            limits: self.limits.clone(),
            nfs4_limits,
            nfs4_namespace: Arc::new(nfs4_namespace),
            nfs4_public_filehandle_node,
            nfs4_lease_seconds,
            nfs4_runtime,
            nfs4_open_pins,
            nfs4_delegations,
            migration: migration.clone(),
            stable_journal,
            gss_contexts,
            nfs4_identity_mapper: self.nfs4_config.as_ref().map(|config| config.identity_mapper().clone()),
            nfs4_namespace_locations: Arc::new(
                self.nfs4_config
                    .as_ref()
                    .map_or_else(BTreeMap::new, |config| config.namespace_locations().clone()),
            ),
            nfs4_callback_connector: self.nfs4_config.as_ref().and_then(Nfs4Config::callback_connector).cloned(),
            nfs4_callback_attempt_timeout: self
                .nfs4_config
                .as_ref()
                .map_or(std::time::Duration::from_secs(5), Nfs4Config::callback_attempt_timeout),
            nfs4_callback_gss_initiator,
            channel_binding_provider: self
                .nfs4_config
                .as_ref()
                .and_then(Nfs4Config::channel_binding_provider)
                .cloned(),
            auth_policy: self.auth_policy,
            handles,
            write_verifier: runtime_write_verifier,
            replay: Arc::new(ReplayCache::new(
                self.limits.replay_cache_capacity,
                self.limits.replay_cache_max_bytes,
                self.limits.replay_cache_ttl,
            )),
            requests: Arc::new(Semaphore::new(self.limits.max_inflight_requests)),
            request_buffers: Arc::new(Semaphore::new(self.limits.max_buffered_request_bytes)),
            reply_buffers: Arc::new(Semaphore::new(self.limits.max_buffered_reply_bytes)),
            executions: Arc::downgrade(&executions),
            mounts: Arc::new(Mutex::new(Vec::new())),
        });
        Ok((state, executions, migration))
    }
}

fn validate_mount_address(nfs_addresses: &[SocketAddr], mount_address: Option<SocketAddr>) -> Result<(), ServerError> {
    if let Some(mount_address) = mount_address {
        if nfs_addresses.iter().any(|address| !socket_hosts_match(*address, mount_address)) {
            return Err(ServerError::InvalidConfiguration(
                "the MOUNTv3 listener IP address must match every NFS listener IP address",
            ));
        }
    }
    Ok(())
}

fn socket_hosts_match(left: SocketAddr, right: SocketAddr) -> bool {
    match (left, right) {
        (SocketAddr::V4(left), SocketAddr::V4(right)) => left.ip() == right.ip(),
        (SocketAddr::V6(left), SocketAddr::V6(right)) => left.ip() == right.ip() && left.scope_id() == right.scope_id(),
        _ => false,
    }
}

fn listener_roles(
    nfs_listeners: Vec<TcpListener>,
    mount_listener: Option<TcpListener>,
) -> Vec<(TcpListener, ListenerRole)> {
    let mut listeners = Vec::with_capacity(nfs_listeners.len() + usize::from(mount_listener.is_some()));
    listeners.extend(nfs_listeners.into_iter().map(|listener| (listener, ListenerRole::Nfs)));
    if let Some(listener) = mount_listener {
        listeners.push((listener, ListenerRole::Mount));
    }
    listeners
}

async fn run(
    listeners: Vec<(TcpListener, ListenerRole)>,
    prepared_portmapper: Option<portmapper::PreparedPortmapper>,
    mut shutdown: watch::Receiver<bool>,
    state: Arc<ConnectionState>,
    executions: Arc<ExecutionTracker>,
    graceful_deadline: std::time::Duration,
) -> Result<(), ServerError> {
    let connections = Arc::new(Semaphore::new(state.limits.max_connections));
    let mut services = JoinSet::new();
    for (listener, role) in listeners {
        services.spawn(run_listener(listener, role, shutdown.clone(), state.clone(), connections.clone()));
    }
    if let Some(portmapper) = prepared_portmapper {
        services.spawn(portmapper::run_portmapper(
            portmapper,
            shutdown.clone(),
            connections.clone(),
            state.limits.clone(),
        ));
    }
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            Some(result) = services.join_next(), if !services.is_empty() => {
                let result = result.map_err(ServerError::Task)?;
                if *shutdown.borrow() {
                    break;
                }
                return result;
            }
        }
    }
    // The budget covers graceful shutdown work, not normal server uptime.
    let shutdown_deadline = Instant::now() + graceful_deadline;
    match timeout_at(shutdown_deadline, async {
        while let Some(result) = services.join_next().await {
            result.map_err(ServerError::Task)??;
        }
        executions.wait().await.map_err(ServerError::Task)
    })
    .await
    {
        Ok(Ok(())) => {},
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            services.abort_all();
            while services.join_next().await.is_some() {}
            executions.abort_all().await;
            let _ = executions.wait().await;
            // Some backend and state transitions are not yet independently
            // cancellation-shielded. Once the graceful drain deadline
            // expires, a forced task abort can therefore leave their durable
            // outcome indeterminate. Report an unclean shutdown immediately
            // and, most importantly, never write the stable clean-shutdown
            // marker.
            return Err(ServerError::RequestTimeout);
        },
    }

    timeout_at(shutdown_deadline, async {
        state.nfs4_runtime.wait_critical().await;
        state.nfs4_open_pins.wait_critical().await;
        state.nfs4_open_pins.reconcile_committing(&state.nfs4_runtime);
        loop {
            state.nfs4_open_pins.accept_runtime_releases(&state.nfs4_runtime);
            if state.nfs4_open_pins.pending_work() == 0 && state.nfs4_runtime.pending_pin_releases().is_empty() {
                break;
            }
            state.nfs4_open_pins.maintain(&state.nfs4_runtime).await;
            tokio::task::yield_now().await;
        }

        // Active delegations and failed rollback/release work own backend
        // reservations. Extract all active state without deleting durable
        // recovery records, then drain the bounded cleanup outboxes before a
        // clean-shutdown marker can be written.
        for (export_id, manager) in state.nfs4_delegations.iter() {
            let progress = manager.shutdown_cleanup().await;
            if let Some(error) = progress.first_error {
                tracing::warn!(
                    export_id = export_id.0,
                    pending = progress.pending,
                    error = %error,
                    "NFSv4 delegation shutdown cleanup requires retry"
                );
            }
        }
        loop {
            let mut pending = 0usize;
            for (export_id, manager) in state.nfs4_delegations.iter() {
                let manager_pending = manager.pending_cleanup();
                pending = pending.saturating_add(manager_pending);
                if manager_pending == 0 {
                    continue;
                }
                let progress = manager.maintain_cleanup().await;
                if let Some(error) = progress.first_error {
                    tracing::warn!(
                        export_id = export_id.0,
                        pending = progress.pending,
                        error = %error,
                        "NFSv4 delegation shutdown cleanup retry failed"
                    );
                }
            }
            if pending == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| ServerError::RequestTimeout)?;

    if let Some(journal) = &state.stable_journal {
        timeout_at(shutdown_deadline, async {
            journal
                .lock()
                .await
                .mark_clean_shutdown()
                .await
                .map_err(|error| ServerError::StableState(error.to_string()))
        })
        .await
        .map_err(|_| ServerError::RequestTimeout)??;
    }
    Ok(())
}

async fn run_listener(
    listener: TcpListener,
    role: ListenerRole,
    mut shutdown: watch::Receiver<bool>,
    state: Arc<ConnectionState>,
    connections: Arc<Semaphore>,
) -> Result<(), ServerError> {
    let local_addr = listener.local_addr()?;
    let mut tasks = JoinSet::new();
    tracing::debug!(address = %local_addr, service = role.label(), "RPC listener started");
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::warn!(error = %error, "connection task failed");
            }
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, client_addr) = accepted?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(client = %client_addr, "connection rejected: limit reached");
                        continue;
                    }
                };
                let active_connections = state.limits.max_connections - connections.available_permits();
                let state = state.clone();
                let connection_shutdown = shutdown.clone();
                tasks.spawn(async move {
                    tracing::debug!(client = %client_addr, active_connections, "connection opened");
                    if let Err(error) = serve_connection(stream, client_addr, role, state, connection_shutdown).await {
                        tracing::debug!(
                            client = %client_addr,
                            active_connections,
                            error = %error,
                            "connection closed with error"
                        );
                    } else {
                        tracing::debug!(client = %client_addr, active_connections, "connection closed");
                    }
                    permit
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(error = %error, "connection task failed");
                }
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    tracing::debug!(address = %local_addr, service = role.label(), "RPC listener stopped");
    Ok(())
}

impl std::fmt::Debug for NfsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsServer")
            .field("protocols", &self.protocols)
            .field(
                "exports",
                &self
                    .exports
                    .iter()
                    .map(|export| (&export.id, &export.path, &export.security_policy))
                    .collect::<Vec<_>>(),
            )
            .field("limits", &self.limits)
            .field("nfs4_config", &self.nfs4_config)
            .field("auth_policy", &self.auth_policy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::rpc::codec::{Decoder, Encoder};
    use crate::rpc::record::{read_record, write_record, RecordLimits};
    use crate::vfs::{
        CreatedObject, FileAttributes, FileType, Nfs4Capabilities, Nfs4FsLocation, Nfs4FsLocations, NfsError, NfsName,
        NfsTime, NumericIdentityMapper, ObjectKey, RequestContext, VfsCapabilities, VirtualFileSystem,
    };

    const RPC_SUCCESS: u32 = 0;
    const RPC_PROG_UNAVAIL: u32 = 1;

    #[tokio::test]
    async fn execution_tracker_drain_allows_nested_tracked_admission() {
        let tracker = Arc::new(ExecutionTracker::new());
        let parent_entered = Arc::new(tokio::sync::Notify::new());
        let release_parent = Arc::new(tokio::sync::Notify::new());
        tracker
            .spawn({
                let tracker = tracker.clone();
                let parent_entered = parent_entered.clone();
                let release_parent = release_parent.clone();
                async move {
                    parent_entered.notify_one();
                    release_parent.notified().await;
                    tracker.spawn(async {}).await.unwrap();
                }
            })
            .await
            .unwrap();
        parent_entered.notified().await;

        let waiter = tokio::spawn({
            let tracker = tracker.clone();
            async move { tracker.wait().await }
        });
        tokio::task::yield_now().await;
        release_parent.notify_one();

        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("nested execution drain must not deadlock")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn execution_tracker_reports_panics_to_the_shutdown_drain() {
        let tracker = Arc::new(ExecutionTracker::new());
        tracker
            .spawn(async {
                panic!("injected tracked execution panic");
            })
            .await
            .unwrap();

        let error = tracker.wait().await.expect_err("tracked panic must make shutdown unclean");
        assert!(error.is_panic());
    }

    #[tokio::test]
    async fn execution_tracker_abort_drains_even_if_task_was_never_polled() {
        let tracker = Arc::new(ExecutionTracker::new());
        tracker.spawn(std::future::pending()).await.unwrap();
        tracker.abort_all().await;

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), tracker.wait())
            .await
            .expect("aborted unpolled task must release its active charge");
        assert!(result.is_err(), "forced cancellation is a tracked task failure");
    }

    #[tokio::test]
    async fn execution_tracker_forced_abort_rejects_late_admission() {
        let tracker = Arc::new(ExecutionTracker::new());
        tracker.spawn(std::future::pending()).await.unwrap();

        tracker.abort_all().await;
        assert!(tracker.spawn(std::future::pending()).await.is_err());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), tracker.wait())
            .await
            .expect("forced abort must drain the cancelled child");
    }

    struct TestVfs {
        root_id: u64,
        export_id: crate::vfs::ExportId,
    }

    struct DelegationFenceVfs {
        inner: TestVfs,
        fence_calls: Arc<StdMutex<Vec<crate::vfs::StableFenceToken>>>,
        fence_error: Option<NfsError>,
    }

    struct UnavailableCallbackConnector;

    #[async_trait]
    impl CallbackConnector for UnavailableCallbackConnector {
        async fn connect(&self, _target: &CallbackTarget) -> Result<Arc<dyn CallbackTransport>, CallbackError> {
            Err(CallbackError::Unavailable("unused test connector".to_owned()))
        }
    }

    fn export_config(export_id: crate::vfs::ExportId, path: impl Into<String>) -> ExportConfig {
        ExportConfig::new(
            export_id,
            path,
            FileSystemId::new(0, u64::from(export_id.0)),
            SecurityPolicy::auth_sys(),
            FileHandlePolicy::Volatile,
        )
    }

    fn root_attributes(file_id: u64) -> FileAttributes {
        FileAttributes {
            file_type: FileType::Directory,
            mode: 0o755,
            links: 2,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: None,
            fs_id: 1,
            file_id,
            change_id: file_id.into(),
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        }
    }

    #[async_trait]
    impl VirtualFileSystem for TestVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_ONLY
        }

        fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
            Some(Nfs4Capabilities {
                persistent_object_ids: true,
                ..Nfs4Capabilities::READ_ONLY
            })
        }

        fn root(&self) -> ObjectKey {
            ObjectKey {
                file_id: self.root_id,
                generation: 1,
            }
        }

        async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            if object == self.root() && context.export_id == self.export_id {
                Ok(root_attributes(self.root_id))
            } else {
                Err(NfsError::NotFound)
            }
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            Err(NfsError::NotFound)
        }

        async fn lookup_parent(
            &self,
            context: &RequestContext,
            directory: ObjectKey,
        ) -> Result<CreatedObject, NfsError> {
            if directory == self.root() && context.export_id == self.export_id {
                Ok(CreatedObject {
                    object: directory,
                    attributes: Some(root_attributes(self.root_id)),
                })
            } else {
                Err(NfsError::NotFound)
            }
        }
    }

    #[async_trait]
    impl VirtualFileSystem for DelegationFenceVfs {
        fn capabilities(&self) -> VfsCapabilities {
            self.inner.capabilities()
        }

        fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
            Some(Nfs4Capabilities {
                delegations: true,
                ..self.inner.nfs4_capabilities().expect("test VFS supports NFSv4")
            })
        }

        fn root(&self) -> ObjectKey {
            self.inner.root()
        }

        async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            self.inner.getattr(context, object).await
        }

        async fn lookup(
            &self,
            context: &RequestContext,
            parent: ObjectKey,
            name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            self.inner.lookup(context, parent, name).await
        }

        async fn lookup_parent(
            &self,
            context: &RequestContext,
            directory: ObjectKey,
        ) -> Result<CreatedObject, NfsError> {
            self.inner.lookup_parent(context, directory).await
        }

        async fn nfs4_fence_delegation_reservations(
            &self,
            scope: &crate::vfs::StableFenceToken,
        ) -> Result<(), NfsError> {
            self.fence_calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(scope.clone());
            match self.fence_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    fn delegation_test_server(
        fence_calls: Arc<StdMutex<Vec<crate::vfs::StableFenceToken>>>,
        fence_error: Option<NfsError>,
    ) -> NfsServer {
        let export_id = crate::vfs::ExportId(1);
        let config = Nfs4Config::in_memory(Arc::new(NumericIdentityMapper::new("local")), None)
            .with_callback_connector(Arc::new(UnavailableCallbackConnector))
            .with_delegation_policy(DelegationPolicy::Conservative {
                max_read_delegations: 1,
                max_write_delegations: 1,
                persistent: false,
            });
        NfsServer::builder(ProtocolSet::V4)
            .add_export_owned(
                export_config(export_id, "/"),
                DelegationFenceVfs {
                    inner: TestVfs { root_id: 1, export_id },
                    fence_calls,
                    fence_error,
                },
            )
            .nfs4(config)
            .build()
            .unwrap()
    }

    fn auth_sys_call(xid: u32, program: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
        let mut credential = Encoder::new();
        credential.write_u32(0);
        credential.write_opaque(b"test").unwrap();
        credential.write_u32(1000);
        credential.write_u32(1000);
        credential.write_u32(0);

        let mut call = Encoder::new();
        call.write_u32(xid);
        call.write_u32(0);
        call.write_u32(2);
        call.write_u32(program);
        call.write_u32(version);
        call.write_u32(procedure);
        call.write_u32(crate::rpc::auth::AUTH_SYS);
        call.write_opaque(&credential.into_bytes()).unwrap();
        call.write_u32(crate::rpc::auth::AUTH_NONE);
        call.write_u32(0);
        call.write_fixed(args);
        call.into_bytes()
    }

    fn accepted_body(reply: &[u8]) -> Decoder<'_> {
        let mut decoder = Decoder::new(reply);
        let _xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), 1);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert_eq!(decoder.read_u32().unwrap(), crate::rpc::auth::AUTH_NONE);
        assert!(decoder.read_opaque("verifier", 400).unwrap().is_empty());
        assert_eq!(decoder.read_u32().unwrap(), 0);
        decoder
    }

    fn accepted_status(reply: &[u8]) -> u32 {
        let mut decoder = Decoder::new(reply);
        let _xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), 1);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert_eq!(decoder.read_u32().unwrap(), crate::rpc::auth::AUTH_NONE);
        assert!(decoder.read_opaque("verifier", 400).unwrap().is_empty());
        decoder.read_u32().unwrap()
    }

    #[test]
    fn nfs4_selection_requires_explicit_recovery_config() {
        let export = || TestVfs {
            root_id: 1,
            export_id: crate::vfs::ExportId(1),
        };
        assert!(NfsServer::builder(ProtocolSet::V4)
            .add_export_owned(export_config(crate::vfs::ExportId(1), "/"), export())
            .build()
            .is_err());

        let config = Nfs4Config::in_memory(Arc::new(NumericIdentityMapper::new("local")), None);
        let server = NfsServer::builder(ProtocolSet::V4)
            .add_export_owned(export_config(crate::vfs::ExportId(1), "/"), export())
            .nfs4(config)
            .build()
            .unwrap();
        assert_eq!(server.protocols(), ProtocolSet::V4);
        assert!(matches!(server.nfs4_config().unwrap().recovery_mode(), Nfs4RecoveryMode::InMemoryRejectReclaims));
        assert!(server.nfs4_config().unwrap().stable_store().is_none());
    }

    #[tokio::test]
    async fn delegation_enabled_startup_initialization_fences_reservations_with_nonempty_scope() {
        let fence_calls = Arc::new(StdMutex::new(Vec::new()));
        let server = delegation_test_server(fence_calls.clone(), None);

        server.connection_state().await.unwrap();

        let calls = fence_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].as_bytes().is_empty());
    }

    #[tokio::test]
    async fn delegation_fence_error_fails_connection_state_initialization() {
        let fence_calls = Arc::new(StdMutex::new(Vec::new()));
        let server = delegation_test_server(fence_calls.clone(), Some(NfsError::Io));

        let result = server.connection_state().await;

        let error = match result {
            Err(ServerError::Nfs4State(error)) => error,
            Err(error) => panic!("unexpected connection-state error: {error}"),
            Ok(_) => panic!("delegation fence failure must abort connection-state initialization"),
        };
        assert_eq!(error, NfsError::Io.to_string());
        let calls = fence_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].as_bytes().is_empty());
    }

    #[tokio::test]
    async fn durable_restart_preserves_only_persistent_export_handles() {
        let store = Arc::new(crate::nfs4::stable::tests::DurableFakeStore::default());
        let scope = crate::vfs::StableScope::from(&b"server-handle-lifetime-restart"[..]);
        let build_server = || {
            let persistent_id = crate::vfs::ExportId(1);
            let volatile_id = crate::vfs::ExportId(2);
            NfsServer::builder(ProtocolSet::V3AndV4)
                .add_export_owned(
                    ExportConfig::new(
                        persistent_id,
                        "/persistent",
                        FileSystemId::new(0, 1),
                        SecurityPolicy::auth_sys(),
                        FileHandlePolicy::Persistent,
                    ),
                    TestVfs {
                        root_id: 11,
                        export_id: persistent_id,
                    },
                )
                .add_export_owned(
                    ExportConfig::new(
                        volatile_id,
                        "/volatile",
                        FileSystemId::new(0, 2),
                        SecurityPolicy::auth_sys(),
                        FileHandlePolicy::Volatile,
                    ),
                    TestVfs {
                        root_id: 22,
                        export_id: volatile_id,
                    },
                )
                .nfs4(
                    Nfs4Config::durable(store.clone(), Arc::new(NumericIdentityMapper::new("local")), None)
                        .with_stable_scope(scope.clone()),
                )
                .build()
                .unwrap()
        };
        let persistent_id = crate::vfs::ExportId(1);
        let volatile_id = crate::vfs::ExportId(2);
        let persistent_object = ObjectKey {
            file_id: 11,
            generation: 1,
        };
        let volatile_object = ObjectKey {
            file_id: 22,
            generation: 1,
        };

        let first = build_server();
        let (first_state, first_executions, first_migration) = first.connection_state().await.unwrap();
        let persistent_handle = first_state.handles.encode(persistent_id, persistent_object).unwrap();
        let volatile_handle = first_state.handles.encode(volatile_id, volatile_object).unwrap();
        let persistent_routed_handle = first_state
            .handles
            .encode_target(crate::handles::HandleTarget::Backend {
                export_id: persistent_id,
                object: persistent_object,
                namespace_node: None,
            })
            .unwrap();
        let volatile_routed_handle = first_state
            .handles
            .encode_target(crate::handles::HandleTarget::Backend {
                export_id: volatile_id,
                object: volatile_object,
                namespace_node: None,
            })
            .unwrap();
        let first_write_verifier = first_state.write_verifier;
        drop(first_migration);
        drop(first_executions);
        drop(first_state);
        drop(first);

        let restarted = build_server();
        let (restarted_state, _executions, _migration) = restarted.connection_state().await.unwrap();
        assert_eq!(restarted_state.handles.decode(persistent_id, &persistent_handle), Ok(persistent_object));
        assert_eq!(
            restarted_state.handles.decode(volatile_id, &volatile_handle),
            Err(crate::handles::HandleError::StaleInstance)
        );
        assert_eq!(
            restarted_state.handles.decode_target(&persistent_routed_handle),
            Ok(crate::handles::HandleTarget::Backend {
                export_id: persistent_id,
                object: persistent_object,
                namespace_node: None,
            })
        );
        assert_eq!(
            restarted_state.handles.decode_target(&volatile_routed_handle),
            Err(crate::handles::HandleError::StaleInstance)
        );
        assert_ne!(restarted_state.write_verifier, first_write_verifier);
    }

    #[test]
    fn nfs4_namespace_locations_are_bounded_and_structurally_validated() {
        let config = Nfs4Config::in_memory(Arc::new(NumericIdentityMapper::new("local")), None)
            .with_namespace_locations(
                crate::vfs::ExportId(1),
                Nfs4FsLocations {
                    fs_root: vec!["export".to_owned()],
                    locations: vec![Nfs4FsLocation {
                        servers: Vec::new(),
                        root_path: vec!["export".to_owned()],
                    }],
                },
            );
        let result = NfsServer::builder(ProtocolSet::V4)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .nfs4(config)
            .build();

        assert!(matches!(result, Err(ServerError::InvalidConfiguration(_))));
    }

    #[tokio::test]
    async fn embedded_server_starts_replies_and_stops() {
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .build()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = server.start(ServerSockets::new(listener)).await.unwrap();
        let info = handle.endpoint_info();
        assert_ne!(info.nfs_port, 0);

        let mut client = TcpStream::connect(info.address).await.unwrap();
        let null_call = auth_sys_call(7, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 0, &[]);
        write_record(&mut client, &null_call, 1024).await.unwrap();
        let reply = read_record(
            &mut client,
            RecordLimits {
                max_record_size: 1024,
                max_fragment_size: 1024,
                max_fragments: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(&reply[..4], &7u32.to_be_bytes());
        assert_eq!(&reply[20..24], &0u32.to_be_bytes());
        drop(client);

        handle.shutdown().await.unwrap();
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn graceful_shutdown_budget_starts_when_shutdown_is_requested() {
        let limits = ServerLimits {
            graceful_shutdown_timeout: std::time::Duration::from_secs(5),
            ..ServerLimits::default()
        };
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .limits(limits)
            .build()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = server.start(ServerSockets::new(listener)).await.unwrap();

        // Advancing beyond the configured grace period models a long-lived
        // server without spending wall-clock time. Its full shutdown budget
        // must still be available once shutdown is actually requested.
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test]
    async fn nfs_and_mount_listeners_reject_each_others_programs() {
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .build()
            .unwrap();
        let nfs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount_address = mount_listener.local_addr().unwrap();
        let handle = server
            .start(ServerSockets::new(nfs_listener).with_mount_listener(mount_listener))
            .await
            .unwrap();
        let info = handle.endpoint_info();
        assert_eq!(info.mount_port, Some(mount_address.port()));

        let limits = RecordLimits {
            max_record_size: 1024,
            max_fragment_size: 1024,
            max_fragments: 1,
        };
        let mut nfs = TcpStream::connect(info.address).await.unwrap();
        let mut mount = TcpStream::connect(mount_address).await.unwrap();

        let mount_on_nfs = auth_sys_call(20, crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, 0, &[]);
        write_record(&mut nfs, &mount_on_nfs, 1024).await.unwrap();
        assert_eq!(accepted_status(&read_record(&mut nfs, limits).await.unwrap()), RPC_PROG_UNAVAIL);

        let nfs_on_mount = auth_sys_call(21, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 0, &[]);
        write_record(&mut mount, &nfs_on_mount, 1024).await.unwrap();
        assert_eq!(accepted_status(&read_record(&mut mount, limits).await.unwrap()), RPC_PROG_UNAVAIL);

        let nfs_null = auth_sys_call(22, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 0, &[]);
        write_record(&mut nfs, &nfs_null, 1024).await.unwrap();
        assert_eq!(accepted_status(&read_record(&mut nfs, limits).await.unwrap()), RPC_SUCCESS);

        let mount_null = auth_sys_call(23, crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, 0, &[]);
        write_record(&mut mount, &mount_null, 1024).await.unwrap();
        assert_eq!(accepted_status(&read_record(&mut mount, limits).await.unwrap()), RPC_SUCCESS);

        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test]
    async fn absent_mount_listener_is_not_advertised_or_exposed() {
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .build()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = server.start(ServerSockets::new(listener)).await.unwrap();
        assert_eq!(handle.endpoint_info().mount_port, None);

        let mut client = TcpStream::connect(handle.endpoint_info().address).await.unwrap();
        let call = auth_sys_call(24, crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, 0, &[]);
        write_record(&mut client, &call, 1024).await.unwrap();
        let reply = read_record(
            &mut client,
            RecordLimits {
                max_record_size: 1024,
                max_fragment_size: 1024,
                max_fragments: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(accepted_status(&reply), RPC_PROG_UNAVAIL);

        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test]
    async fn endpoint_info_rejects_a_mount_listener_on_an_incompatible_address() {
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .build()
            .unwrap();
        let nfs = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let result = server.start(ServerSockets::new(nfs).with_mount_listener(mount)).await;
        assert!(matches!(result, Err(ServerError::InvalidConfiguration(_))));
    }

    #[tokio::test]
    async fn mount_handle_drives_getattr_and_rejects_forgery() {
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/"),
                TestVfs {
                    root_id: 1,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .build()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount_address = mount_listener.local_addr().unwrap();
        let handle = server
            .start(ServerSockets::new(listener).with_mount_listener(mount_listener))
            .await
            .unwrap();
        let mut client = TcpStream::connect(handle.endpoint_info().address).await.unwrap();
        let mut mount_client = TcpStream::connect(mount_address).await.unwrap();
        let limits = RecordLimits {
            max_record_size: 2048,
            max_fragment_size: 2048,
            max_fragments: 1,
        };

        let mut mount_args = Encoder::new();
        mount_args.write_opaque(b"/").unwrap();
        let mount_call = auth_sys_call(
            10,
            crate::mount3::types::PROGRAM,
            crate::mount3::types::VERSION,
            1,
            &mount_args.into_bytes(),
        );
        write_record(&mut mount_client, &mount_call, 2048).await.unwrap();
        let mount_reply = read_record(&mut mount_client, limits).await.unwrap();
        let mut body = accepted_body(&mount_reply);
        assert_eq!(body.read_u32().unwrap(), 0);
        let root_handle = body.read_opaque("handle", 64).unwrap();
        assert_eq!(body.read_u32().unwrap(), 1);
        assert_eq!(body.read_u32().unwrap(), crate::rpc::auth::AUTH_SYS);
        body.finish().unwrap();

        let dump_call = auth_sys_call(13, crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, 2, &[]);
        write_record(&mut mount_client, &dump_call, 2048).await.unwrap();
        let dump_reply = read_record(&mut mount_client, limits).await.unwrap();
        let mut dump = accepted_body(&dump_reply);
        assert!(dump.read_bool().unwrap());
        assert!(!dump.read_string("mount host", 64).unwrap().is_empty());
        assert_eq!(dump.read_string("mount path", 1024).unwrap(), b"/");
        assert!(!dump.read_bool().unwrap());
        dump.finish().unwrap();

        let mut getattr_args = Encoder::new();
        getattr_args.write_opaque(&root_handle).unwrap();
        let getattr_call =
            auth_sys_call(11, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 1, &getattr_args.into_bytes());
        write_record(&mut client, &getattr_call, 2048).await.unwrap();
        let getattr_reply = read_record(&mut client, limits).await.unwrap();
        let mut body = accepted_body(&getattr_reply);
        assert_eq!(body.read_u32().unwrap(), 0);
        assert_eq!(body.read_u32().unwrap(), 2);

        let mut write_args = Encoder::new();
        write_args.write_opaque(&root_handle).unwrap();
        write_args.write_u64(0);
        write_args.write_u32(1);
        write_args.write_u32(0);
        write_args.write_opaque(&[1]).unwrap();
        let write_call =
            auth_sys_call(15, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 7, &write_args.into_bytes());
        write_record(&mut client, &write_call, 2048).await.unwrap();
        let write_reply = read_record(&mut client, limits).await.unwrap();
        assert_eq!(accepted_body(&write_reply).read_u32().unwrap(), 30);

        let mut forged = root_handle;
        forged[15] ^= 1;
        let mut forged_args = Encoder::new();
        forged_args.write_opaque(&forged).unwrap();
        let forged_call =
            auth_sys_call(12, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 1, &forged_args.into_bytes());
        write_record(&mut client, &forged_call, 2048).await.unwrap();
        let forged_reply = read_record(&mut client, limits).await.unwrap();
        assert_eq!(accepted_body(&forged_reply).read_u32().unwrap(), 10001);

        let mut unmount_args = Encoder::new();
        unmount_args.write_opaque(b"/").unwrap();
        let unmount_call = auth_sys_call(
            14,
            crate::mount3::types::PROGRAM,
            crate::mount3::types::VERSION,
            3,
            &unmount_args.into_bytes(),
        );
        write_record(&mut mount_client, &unmount_call, 2048).await.unwrap();
        let unmount_reply = read_record(&mut mount_client, limits).await.unwrap();
        accepted_body(&unmount_reply).finish().unwrap();

        drop(client);
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }

    #[tokio::test]
    async fn repeated_instances_have_independent_ports_and_state() {
        for _ in 0..3 {
            let server = NfsServer::builder(ProtocolSet::V3)
                .add_export_owned(
                    export_config(crate::vfs::ExportId(1), "/"),
                    TestVfs {
                        root_id: 1,
                        export_id: crate::vfs::ExportId(1),
                    },
                )
                .build()
                .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let handle = server.start(ServerSockets::new(listener)).await.unwrap();
            assert_ne!(handle.endpoint_info().nfs_port, 0);
            handle.shutdown().await.unwrap();
            handle.wait().await.unwrap();
        }
    }

    #[tokio::test]
    async fn independent_exports_route_contexts_and_handles() {
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export_owned(
                export_config(crate::vfs::ExportId(1), "/one"),
                TestVfs {
                    root_id: 11,
                    export_id: crate::vfs::ExportId(1),
                },
            )
            .add_export_owned(
                export_config(crate::vfs::ExportId(2), "/two"),
                TestVfs {
                    root_id: 22,
                    export_id: crate::vfs::ExportId(2),
                },
            )
            .build()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mount_address = mount_listener.local_addr().unwrap();
        let handle = server
            .start(ServerSockets::new(listener).with_mount_listener(mount_listener))
            .await
            .unwrap();
        assert_eq!(handle.endpoint_infos().len(), 2);
        assert_eq!(handle.endpoint_infos()[0].export_path, "/one");
        assert_eq!(handle.endpoint_infos()[1].export_path, "/two");
        let mut client = TcpStream::connect(handle.endpoint_info().address).await.unwrap();
        let mut mount_client = TcpStream::connect(mount_address).await.unwrap();
        let limits = RecordLimits {
            max_record_size: 2048,
            max_fragment_size: 2048,
            max_fragments: 1,
        };
        let mut file_handles = Vec::new();
        for (xid, path) in [(30, b"/one".as_slice()), (31, b"/two".as_slice())] {
            let mut mount_args = Encoder::new();
            mount_args.write_opaque(path).unwrap();
            let call = auth_sys_call(
                xid,
                crate::mount3::types::PROGRAM,
                crate::mount3::types::VERSION,
                1,
                &mount_args.into_bytes(),
            );
            write_record(&mut mount_client, &call, 2048).await.unwrap();
            let reply = read_record(&mut mount_client, limits).await.unwrap();
            let mut body = accepted_body(&reply);
            assert_eq!(body.read_u32().unwrap(), 0);
            file_handles.push(body.read_opaque("handle", 64).unwrap());
        }
        assert_ne!(file_handles[0], file_handles[1]);

        for (xid, file_handle) in [(32, &file_handles[0]), (33, &file_handles[1])] {
            let mut args = Encoder::new();
            args.write_opaque(file_handle).unwrap();
            let call =
                auth_sys_call(xid, crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, 1, &args.into_bytes());
            write_record(&mut client, &call, 2048).await.unwrap();
            let reply = read_record(&mut client, limits).await.unwrap();
            assert_eq!(accepted_body(&reply).read_u32().unwrap(), 0);
        }

        drop(client);
        handle.shutdown().await.unwrap();
        handle.wait().await.unwrap();
    }
}
