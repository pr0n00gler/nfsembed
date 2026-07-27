use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use super::{ChangeInfo, CreateMode, CreatedObject, ExportId, NfsError, ObjectKey, SetAttributes};

/// Backend features needed by the NFSv4.0 protocol adapter.
///
/// Returning a value from [`super::VirtualFileSystem::nfs4_capabilities`]
/// explicitly opts an export into NFSv4. A backend should only set a flag
/// when it can provide that semantic atomically.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nfs4Capabilities {
    pub lookup_parent: bool,
    pub atomic_open: bool,
    pub retains_unlinked_objects: bool,
    pub authoritative_change_ids: bool,
    /// Every successful non-WRITE mutation is stable before its future
    /// returns. This is mandatory for read-write NFSv4 exports.
    pub durable_non_write_mutations: bool,
    pub acls: bool,
    /// Supports the NFSv4 named-attribute namespace.
    ///
    /// A backend that enables this must return [`super::FileType::AttributeDirectory`]
    /// from `nfs4_named_attribute_directory` and
    /// [`super::FileType::NamedAttribute`] for every object reached through
    /// that directory. It must also implement
    /// [`super::VirtualFileSystem::nfs4_named_attribute_parent`] for those
    /// named attributes.
    pub named_attributes: bool,
    pub quotas: bool,
    pub delegations: bool,
    pub persistent_object_ids: bool,
    pub fs_locations: bool,
}

impl Nfs4Capabilities {
    /// Capabilities expected from a fully read-write NFSv4.0 backend.
    pub const READ_WRITE: Self = Self {
        lookup_parent: true,
        atomic_open: true,
        retains_unlinked_objects: true,
        authoritative_change_ids: true,
        durable_non_write_mutations: true,
        acls: false,
        named_attributes: false,
        quotas: false,
        delegations: false,
        persistent_object_ids: false,
        fs_locations: false,
    };

    /// Capabilities expected from a read-only NFSv4.0 backend.
    pub const READ_ONLY: Self = Self {
        lookup_parent: true,
        atomic_open: false,
        retains_unlinked_objects: false,
        authoritative_change_ids: true,
        durable_non_write_mutations: false,
        acls: false,
        named_attributes: false,
        quotas: false,
        delegations: false,
        persistent_object_ids: false,
        fs_locations: false,
    };
}

/// Protocol-neutral parameters for an atomic NFSv4 OPEN lookup/create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4OpenRequest {
    /// Data access that the backend must authorize atomically with lookup or
    /// creation. NFS share-deny reservations remain protocol state managed by
    /// the server.
    pub access: Nfs4OpenAccess,
    /// `None` means lookup-only. `Some` requires lookup/create to be one
    /// atomic backend operation.
    pub create: Option<Nfs4OpenCreate>,
    pub truncate_existing: bool,
}

/// Namespace state observed by a side-effect-free NFSv4 OPEN preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4OpenPreflight {
    pub target: Nfs4OpenTarget,
    /// Authoritative change information for the parent directory at the
    /// preflight snapshot. `atomic` must be true, and `before` and `after`
    /// must be equal because preflight itself cannot mutate the namespace.
    pub change_info: ChangeInfo,
}

/// Target discovered while validating an NFSv4 OPEN request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Nfs4OpenTarget {
    Existing(CreatedObject),
    Missing,
}

impl Nfs4OpenTarget {
    pub const fn expectation(&self) -> Nfs4OpenExpectation {
        match self {
            Self::Existing(created) => Nfs4OpenExpectation::Existing(created.object),
            Self::Missing => Nfs4OpenExpectation::Missing,
        }
    }
}

/// Compare-and-swap condition for the mutating phase of NFSv4 OPEN.
///
/// The backend must test this condition and perform the full OPEN
/// authorization and optional mutation in one atomic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Nfs4OpenExpectation {
    /// The name must still identify this exact stable backend object.
    Existing(ObjectKey),
    /// The name must still be absent.
    Missing,
}

/// Server-owned identity and pin disposition for one atomic NFSv4 OPEN.
///
/// `operation_id` is unique within one running server/backend instance. A
/// backend uses it as an idempotency key until
/// [`super::VirtualFileSystem::nfs4_finish_open_operation`] retires the
/// outcome. `pin_id` is independently idempotent and identifies the resulting
/// open instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nfs4OpenTransaction {
    pub operation_id: u64,
    pub expected: Nfs4OpenExpectation,
    pub pin_id: [u8; 16],
    /// Installs `pin_id` atomically with OPEN. This is true for the first
    /// state instance and false for an upgrade that already owns its pin.
    /// [`Nfs4OpenExpectation::Missing`] requires this field to be true; a
    /// backend must reject an unpinned create transaction.
    pub acquire_pin: bool,
}

/// Complete, authoritative result of an atomic NFSv4 OPEN transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4OpenResult {
    pub value: CreatedObject,
    /// Parent-directory change information is mandatory even when OPEN found
    /// an existing object and `before == after`; `atomic` must be true.
    pub change_info: ChangeInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Nfs4OpenAccess {
    Read,
    Write,
    ReadWrite,
}

impl Nfs4OpenAccess {
    pub const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    pub const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4OpenCreate {
    /// Initial attributes, including any canonical ACL that must be
    /// inherited and synchronized with mode as part of the atomic open/create
    /// operation.
    pub attributes: SetAttributes,
    pub mode: CreateMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nfs4Quota {
    pub hard_bytes: Option<u64>,
    pub soft_bytes: Option<u64>,
    pub used_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationRequest {
    pub kind: DelegationKind,
    pub client_id: u64,
    pub requested_space: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationEligibility {
    Eligible,
    Delay,
    Ineligible,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationReservation {
    pub token: Bytes,
    pub reserved_bytes: u64,
}

/// Maximum opaque backend token accepted for one delegated-space reservation.
///
/// The server retains these tokens until cleanup is confirmed, so bounding
/// them is part of bounding delegation state.
pub const MAX_DELEGATION_RESERVATION_TOKEN_SIZE: usize = 1024;

impl DelegationReservation {
    /// Validates an application-provided reservation before the server adopts
    /// it into delegation state.
    pub fn validate(&self, requested_bytes: u64) -> Result<(), NfsError> {
        if self.token.is_empty()
            || self.token.len() > MAX_DELEGATION_RESERVATION_TOKEN_SIZE
            || self.reserved_bytes < requested_bytes
        {
            return Err(NfsError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PersistentObjectId(Bytes);

impl PersistentObjectId {
    pub fn new(value: impl Into<Bytes>) -> Result<Self, NfsError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 {
            return Err(NfsError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Nfs4LocationState {
    Present(Nfs4FsLocations),
    Absent(Nfs4FsLocations),
    Moved(Nfs4FsLocations),
}

/// Stable namespace used to isolate one logical NFSv4 server from another.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StableScope(Bytes);

impl StableScope {
    pub fn new(value: impl Into<Bytes>) -> Self {
        Self(value.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl From<&'static [u8]> for StableScope {
    fn from(value: &'static [u8]) -> Self {
        Self(Bytes::from_static(value))
    }
}

/// Opaque fencing token issued by stable storage for one open session.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StableFenceToken(Bytes);

impl StableFenceToken {
    pub fn new(value: impl Into<Bytes>) -> Self {
        Self(value.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Library-owned categories within the stable-state key space.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum StableRecordKind {
    Server,
    Client,
    OpenOwner,
    LockOwner,
    Migration,
}

/// A structurally typed key. Its byte component is opaque to storage.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StableKey {
    pub kind: StableRecordKind,
    pub key: Bytes,
}

/// One record recovered from stable storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableRecord {
    pub key: StableKey,
    /// Opaque library-owned encoding.
    pub payload: Bytes,
}

/// State from the last successfully fenced server incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableSnapshot {
    pub fence_token: StableFenceToken,
    pub generation: u64,
    pub records: Vec<StableRecord>,
}

/// One compare-and-swap mutation to stable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StableMutation {
    Put { key: StableKey, payload: Bytes },
    Delete { key: StableKey },
}

/// Mutations that storage must commit atomically.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StableBatch {
    pub mutations: Vec<StableMutation>,
}

impl StableBatch {
    pub fn new(mutations: Vec<StableMutation>) -> Self {
        Self { mutations }
    }

    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StableStateError {
    #[error("stable state is unavailable: {0}")]
    Unavailable(String),
    #[error("stable state is corrupt: {0}")]
    Corrupt(String),
    #[error("stable state session was fenced")]
    Fenced,
    #[error("stable state generation changed (expected {expected}, actual {actual})")]
    GenerationConflict { expected: u64, actual: u64 },
    #[error("stable state operation failed: {0}")]
    Other(String),
}

/// A fenced session for one server scope.
///
/// `commit` is a compare-and-swap operation. Implementations must make the
/// whole batch durable before returning its new generation. Applying a batch
/// must atomically advance the durable generation away from
/// `expected_generation`; records must never change without such an advance.
///
/// A returned error (including a transport cancellation) does not prove that
/// the batch was not applied. While the session remains fenced,
/// [`StableStateSession::recover`] must expose the latest durable generation
/// and records so callers can reconcile an ambiguous outcome exactly.
#[async_trait]
pub trait StableStateSession: Send + Sync + 'static {
    fn fence_token(&self) -> StableFenceToken;
    fn generation(&self) -> u64;

    async fn recover(&self) -> Result<StableSnapshot, StableStateError>;

    async fn commit(&self, expected_generation: u64, batch: StableBatch) -> Result<u64, StableStateError>;

    /// Persists a compaction/checkpoint while retaining CAS and fencing
    /// guarantees. Storage without a distinct checkpoint operation can commit
    /// an empty batch.
    async fn checkpoint(&self, expected_generation: u64) -> Result<u64, StableStateError> {
        self.commit(expected_generation, StableBatch::default()).await
    }
}

/// Durable, application-supplied NFSv4 stable storage.
#[async_trait]
pub trait StableStateStore: Send + Sync + 'static {
    async fn open_scope(&self, scope: StableScope) -> Result<Arc<dyn StableStateSession>, StableStateError>;
}

/// Identity-mapping failures are distinct from authorization failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityMappingError {
    #[error("identity is not mapped")]
    Unmapped,
    #[error("identity is malformed")]
    Invalid,
    #[error("identity mapper is unavailable: {0}")]
    Unavailable(String),
    #[error("identity mapping failed: {0}")]
    Other(String),
}

/// Maps local numeric identities to NFSv4 owner strings and canonicalizes
/// RPCSEC_GSS principals.
#[async_trait]
pub trait IdentityMapper: Send + Sync + 'static {
    async fn uid_to_owner(&self, uid: u32) -> Result<String, IdentityMappingError>;
    async fn owner_to_uid(&self, owner: &str) -> Result<u32, IdentityMappingError>;
    async fn gid_to_group(&self, gid: u32) -> Result<String, IdentityMappingError>;
    async fn group_to_gid(&self, group: &str) -> Result<u32, IdentityMappingError>;
    async fn canonicalize_gss(&self, principal: &str) -> Result<String, IdentityMappingError>;
}

/// A deterministic mapper for deployments where numeric IDs are the
/// authoritative identity source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumericIdentityMapper {
    domain: String,
}

impl NumericIdentityMapper {
    pub fn new(domain: impl Into<String>) -> Self {
        Self { domain: domain.into() }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    fn format_id(&self, id: u32) -> String {
        if self.domain.is_empty() {
            id.to_string()
        } else {
            format!("{id}@{}", self.domain)
        }
    }

    fn parse_id(&self, identity: &str) -> Result<u32, IdentityMappingError> {
        let numeric = if self.domain.is_empty() || !identity.contains('@') {
            identity
        } else {
            identity
                .strip_suffix(&format!("@{}", self.domain))
                .ok_or(IdentityMappingError::Unmapped)?
        };
        numeric.parse().map_err(|_| IdentityMappingError::Invalid)
    }
}

#[async_trait]
impl IdentityMapper for NumericIdentityMapper {
    async fn uid_to_owner(&self, uid: u32) -> Result<String, IdentityMappingError> {
        Ok(self.format_id(uid))
    }

    async fn owner_to_uid(&self, owner: &str) -> Result<u32, IdentityMappingError> {
        self.parse_id(owner)
    }

    async fn gid_to_group(&self, gid: u32) -> Result<String, IdentityMappingError> {
        Ok(self.format_id(gid))
    }

    async fn group_to_gid(&self, group: &str) -> Result<u32, IdentityMappingError> {
        self.parse_id(group)
    }

    async fn canonicalize_gss(&self, principal: &str) -> Result<String, IdentityMappingError> {
        let principal = principal.trim();
        if principal.is_empty() || principal.as_bytes().contains(&0) {
            return Err(IdentityMappingError::Invalid);
        }
        Ok(principal.to_owned())
    }
}

/// One `fs_locations` target, expressed independently of its wire encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4FsLocation {
    pub servers: Vec<String>,
    pub root_path: Vec<String>,
}

/// Current and alternate locations for one exported filesystem.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Nfs4FsLocations {
    pub fs_root: Vec<String>,
    pub locations: Vec<Nfs4FsLocation>,
}

/// Opaque fence returned while a migration is being prepared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationFence {
    pub export_id: ExportId,
    pub generation: u64,
    pub token: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MigrationError {
    #[error("filesystem migration is not supported")]
    NotSupported,
    #[error("migration operation was fenced")]
    Fenced,
    #[error("migration state conflicts with another operation")]
    Conflict,
    #[error("migration coordinator is unavailable: {0}")]
    Unavailable(String),
    #[error("migration failed: {0}")]
    Other(String),
}

/// Coordinates externally managed filesystem migration.
///
/// The coordinator owns placement decisions. The server owns the opaque state
/// bundle transferred through [`crate::server::NfsServerHandle`].
#[async_trait]
pub trait MigrationCoordinator: Send + Sync + 'static {
    fn locations(&self, export_id: ExportId) -> Nfs4FsLocations;

    async fn prepare(&self, export_id: ExportId, destination: Nfs4FsLocation)
        -> Result<MigrationFence, MigrationError>;

    async fn commit(&self, fence: &MigrationFence) -> Result<(), MigrationError>;

    async fn abort(&self, fence: &MigrationFence) -> Result<(), MigrationError>;
}

// Explicit aliases keep the NFSv4 prefix discoverable without forcing it into
// every application-owned trait name.
pub use IdentityMapper as Nfs4IdentityMapper;
pub use MigrationCoordinator as Nfs4MigrationCoordinator;
pub use StableStateStore as Nfs4StableStateStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn numeric_mapper_accepts_bare_and_canonical_owner_ids() {
        let mapper = NumericIdentityMapper::new("native.nfsembed");

        assert_eq!(mapper.uid_to_owner(65534).await.unwrap(), "65534@native.nfsembed");
        assert_eq!(mapper.owner_to_uid("65534").await.unwrap(), 65534);
        assert_eq!(mapper.owner_to_uid("65534@native.nfsembed").await.unwrap(), 65534);
        assert_eq!(mapper.group_to_gid("65534").await.unwrap(), 65534);
        assert_eq!(mapper.owner_to_uid("65534@other.example").await, Err(IdentityMappingError::Unmapped));
        assert_eq!(mapper.owner_to_uid("").await, Err(IdentityMappingError::Invalid));
        assert_eq!(mapper.group_to_gid("").await, Err(IdentityMappingError::Invalid));
    }
}
