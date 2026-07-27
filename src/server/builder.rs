use std::sync::Arc;

use super::{
    AuthPolicy, DelegationPolicy, ExportConfig, ExportState, FileHandlePolicy, Nfs4Config, Nfs4RecoveryMode, NfsServer,
    ProtocolSet, ServerError, ServerLimits,
};
use crate::nfs4::locations::{
    FileSystemLocationRecord, LocationPurpose, LocationRegistry, LocationRegistryLimits, PlacementMigrationStatus,
};
use crate::vfs::{Nfs4LocationState, VirtualFileSystem};

pub struct NfsServerBuilder {
    pub(crate) protocols: ProtocolSet,
    pub(crate) exports: Vec<ExportState>,
    pub(crate) limits: ServerLimits,
    pub(crate) nfs4_config: Option<Nfs4Config>,
    pub(crate) auth_policy: AuthPolicy,
}

impl NfsServerBuilder {
    pub(crate) fn new(protocols: ProtocolSet) -> Self {
        Self {
            protocols,
            exports: Vec::new(),
            limits: ServerLimits::default(),
            nfs4_config: None,
            auth_policy: AuthPolicy::default(),
        }
    }

    /// Adds one independent export backed by a virtual filesystem.
    pub fn add_export(mut self, config: ExportConfig, vfs: Arc<dyn VirtualFileSystem>) -> Self {
        self.exports.push(ExportState {
            vfs,
            id: config.export_id(),
            path: config.path().to_owned(),
            fsid: config.fsid(),
            security_policy: config.security_policy().clone(),
            filehandle_policy: config.filehandle_policy(),
        });
        self
    }

    /// Convenience for adding a statically typed backend.
    pub fn add_export_owned(self, config: ExportConfig, vfs: impl VirtualFileSystem) -> Self {
        self.add_export(config, Arc::new(vfs))
    }

    pub fn limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Supplies the required stateful-service configuration for a protocol set
    /// that includes NFSv4.
    pub fn nfs4(mut self, config: Nfs4Config) -> Self {
        self.nfs4_config = Some(config);
        self
    }

    /// Sets the NFSv3 authentication policy. Per-export NFSv4 flavors are
    /// configured through [`ExportConfig`].
    pub fn auth_policy(mut self, auth_policy: AuthPolicy) -> Self {
        self.auth_policy = auth_policy;
        self
    }

    pub fn build(self) -> Result<NfsServer, ServerError> {
        self.limits.validate().map_err(ServerError::InvalidConfiguration)?;
        if self.exports.is_empty() {
            return Err(ServerError::InvalidConfiguration("at least one export is required"));
        }
        match (self.protocols.includes_v4(), self.nfs4_config.as_ref()) {
            (true, None) => {
                return Err(ServerError::InvalidConfiguration("NFSv4 protocol selection requires Nfs4Config"));
            },
            (false, Some(_)) => {
                return Err(ServerError::InvalidConfiguration(
                    "Nfs4Config requires a protocol selection that includes NFSv4",
                ));
            },
            (_, Some(config)) => config.validate().map_err(ServerError::InvalidConfiguration)?,
            _ => {},
        }
        for (index, export) in self.exports.iter().enumerate() {
            validate_export_path(&export.path, self.protocols.includes_v4())?;
            if self.exports[..index].iter().any(|other| {
                other.id == export.id || other.path.as_bytes() == export.path.as_bytes() || other.fsid == export.fsid
            }) {
                return Err(ServerError::InvalidConfiguration("export IDs, paths, and filesystem IDs must be unique"));
            }
            if self.protocols.includes_v4() {
                let Some(capabilities) = export.vfs.nfs4_capabilities() else {
                    return Err(ServerError::InvalidConfiguration(
                        "every NFSv4 export must explicitly declare NFSv4 capabilities",
                    ));
                };
                if !capabilities.lookup_parent || !capabilities.authoritative_change_ids {
                    return Err(ServerError::InvalidConfiguration(
                        "NFSv4 exports require LOOKUPP and authoritative change IDs",
                    ));
                }
                if !export.vfs.capabilities().read_only
                    && (!capabilities.atomic_open
                        || !capabilities.retains_unlinked_objects
                        || !capabilities.durable_non_write_mutations)
                {
                    return Err(ServerError::InvalidConfiguration(
                        "read-write NFSv4 exports require atomic OPEN, retained unlinked objects, and durable non-WRITE mutations",
                    ));
                }
                if export.filehandle_policy == FileHandlePolicy::Persistent && !capabilities.persistent_object_ids {
                    return Err(ServerError::InvalidConfiguration(
                        "persistent NFSv4 filehandles require stable backend object identities",
                    ));
                }
            }
            if export.filehandle_policy == FileHandlePolicy::Persistent
                && !matches!(
                    self.nfs4_config.as_ref().map(Nfs4Config::recovery_mode),
                    Some(Nfs4RecoveryMode::Durable(_))
                )
            {
                return Err(ServerError::InvalidConfiguration(
                    "persistent filehandles require durable fenced NFSv4 state",
                ));
            }
        }
        if let Some(config) = &self.nfs4_config {
            if config.migration_coordinator().is_some() {
                if !matches!(config.recovery_mode(), Nfs4RecoveryMode::Durable(_)) {
                    return Err(ServerError::InvalidConfiguration("NFSv4 migration requires durable fenced state"));
                }
                if self
                    .exports
                    .iter()
                    .any(|export| export.filehandle_policy != FileHandlePolicy::Persistent)
                {
                    return Err(ServerError::InvalidConfiguration(
                        "NFSv4 migration requires persistent filehandles on every export",
                    ));
                }
            }
            if config
                .namespace_locations()
                .keys()
                .any(|export_id| !self.exports.iter().any(|export| export.id == *export_id))
            {
                return Err(ServerError::InvalidConfiguration("NFSv4 namespace locations reference an unknown export"));
            }
            let mut location_registry = LocationRegistry::new(LocationRegistryLimits::default())
                .map_err(|_| ServerError::InvalidConfiguration("NFSv4 namespace location limits are invalid"))?;
            for (export_id, locations) in config.namespace_locations() {
                let purposes = vec![LocationPurpose::Replica; locations.locations.len()];
                location_registry
                    .insert(
                        *export_id,
                        FileSystemLocationRecord::new(
                            Nfs4LocationState::Present(locations.clone()),
                            purposes,
                            PlacementMigrationStatus::None,
                        ),
                    )
                    .map_err(|_| {
                        ServerError::InvalidConfiguration(
                            "NFSv4 namespace locations are malformed or exceed configured bounds",
                        )
                    })?;
            }
            let requires_kerberos = self.exports.iter().any(|export| {
                export
                    .security_policy
                    .flavors()
                    .iter()
                    .any(|flavor| matches!(flavor, super::RpcSecurityFlavor::RpcSecGss { .. }))
            });
            if requires_kerberos && config.kerberos_credentials().is_none() {
                return Err(ServerError::InvalidConfiguration(
                    "RPCSEC_GSS security policies require Kerberos credentials",
                ));
            }
            let requires_channel_binding = self.exports.iter().any(|export| {
                export.security_policy.flavors().iter().any(|flavor| {
                    matches!(
                        flavor,
                        super::RpcSecurityFlavor::RpcSecGss {
                            service: super::RpcGssService::ChannelProtection,
                            ..
                        }
                    )
                })
            });
            if requires_channel_binding && config.channel_binding_provider().is_none() {
                return Err(ServerError::InvalidConfiguration(
                    "RPCSEC_GSS channel protection requires a secure-channel binding provider",
                ));
            }
            if let DelegationPolicy::Conservative { persistent, .. } = config.delegation_policy() {
                if config.callback_connector().is_none() {
                    return Err(ServerError::InvalidConfiguration("NFSv4 delegations require a callback connector"));
                }
                if persistent && !matches!(config.recovery_mode(), Nfs4RecoveryMode::Durable(_)) {
                    return Err(ServerError::InvalidConfiguration(
                        "persistent delegations require durable fenced NFSv4 state",
                    ));
                }
                if persistent
                    && self.exports.iter().any(|export| {
                        let capabilities =
                            export.vfs.nfs4_capabilities().expect("NFSv4 capabilities were validated above");
                        capabilities.delegations && !capabilities.persistent_object_ids
                    })
                {
                    return Err(ServerError::InvalidConfiguration(
                        "persistent delegations require stable backend object identities",
                    ));
                }
            }
        }
        NfsServer::from_builder(self)
    }
}

fn validate_export_path(path: &str, nfs4: bool) -> Result<(), ServerError> {
    if path.as_bytes().contains(&0) || path.len() > 1024 {
        return Err(ServerError::InvalidConfiguration("export path is invalid"));
    }
    if !path.starts_with('/') || (path.len() > 1 && path.ends_with('/')) {
        return Err(ServerError::InvalidConfiguration(
            "export path must be absolute and must not have a trailing slash",
        ));
    }
    if nfs4
        && path != "/"
        && path
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == ".." || component.len() > 255)
    {
        return Err(ServerError::InvalidConfiguration(
            "NFSv4 export path components must contain 1 to 255 bytes and cannot be dot components",
        ));
    }
    Ok(())
}
