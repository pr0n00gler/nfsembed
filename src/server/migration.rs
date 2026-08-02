//! Bounded NFSv4 migration bundles and two-phase migration control.
//!
//! A bundle contains protocol recovery records and authenticated filehandle
//! identity only. Application file data is intentionally outside this format
//! and must already be available at the destination under compatible object
//! identities.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::Duration;

use bytes::Bytes;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify};

use super::FileSystemId;
use crate::handles::{HandleCodec, HandleError, HandleTarget};
use crate::nfs4::delegation::{DelegationManager, PreparedDelegationRecovery};
use crate::nfs4::runtime::{Nfs4Runtime, PreparedRuntimeRecovery};
use crate::nfs4::stable::{
    recovery_from_migration_capsule, validate_migration_snapshot, CommittedMigration, MigrationCapsuleRecord,
    MigrationPhase, MigrationStableSnapshot, MigrationStageStatus, StableJournal, StableJournalLimits,
};
use crate::vfs::{
    ExportId, MigrationCoordinator, MigrationError, MigrationFence, Nfs4FsLocation, StableRecord, StableRecordKind,
};

const BUNDLE_MAGIC: [u8; 8] = *b"NFSMIG\0\0";
const BUNDLE_VERSION: u32 = 2;
const BUNDLE_FLAGS: u32 = 0;
const CHECKSUM_BYTES: usize = 32;
const FIXED_BODY_BYTES: usize = 185;

/// Resource bounds applied when a migration bundle is created or decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationBundleLimits {
    pub max_encoded_bytes: usize,
    pub max_records: usize,
    pub max_key_bytes: usize,
    pub max_record_payload_bytes: usize,
    pub max_coordinator_token_bytes: usize,
}

impl MigrationBundleLimits {
    pub const fn production_defaults() -> Self {
        Self {
            max_encoded_bytes: 16 * 1024 * 1024,
            // One additional mutation commits the durable migration marker.
            max_records: 4_095,
            max_key_bytes: 4 * 1024,
            max_record_payload_bytes: 16 * 1024 * 1024,
            max_coordinator_token_bytes: 4 * 1024,
        }
    }

    pub fn validate(self) -> Result<Self, MigrationBundleError> {
        if self.max_encoded_bytes < FIXED_BODY_BYTES + CHECKSUM_BYTES
            || self.max_records == 0
            || self.max_key_bytes < 16
            || self.max_record_payload_bytes < 16
            || self.max_coordinator_token_bytes == 0
            || self.max_encoded_bytes > u32::MAX as usize
            || self.max_records > u32::MAX as usize
            || self.max_key_bytes > u32::MAX as usize
            || self.max_record_payload_bytes > u32::MAX as usize
            || self.max_coordinator_token_bytes > u32::MAX as usize
        {
            return Err(MigrationBundleError::InvalidLimits);
        }
        Ok(self)
    }

    fn journal_limits(self) -> StableJournalLimits {
        StableJournalLimits {
            max_records: self.max_records,
            max_batch_mutations: self.max_records.saturating_add(1),
            max_key_bytes: self.max_key_bytes,
            max_payload_bytes: self.max_record_payload_bytes,
        }
    }
}

impl Default for MigrationBundleLimits {
    fn default() -> Self {
        Self::production_defaults()
    }
}

/// Opaque identifier shared by the source and destination halves of one
/// migration transaction.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MigrationId([u8; 16]);

impl MigrationId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    fn random() -> Result<Self, MigrationControlError> {
        loop {
            let mut value = [0; 16];
            OsRng
                .try_fill_bytes(&mut value)
                .map_err(|error| MigrationControlError::Entropy(error.to_string()))?;
            if value != [0; 16] {
                return Ok(Self(value));
            }
        }
    }
}

impl fmt::Debug for MigrationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MigrationId({self})")
    }
}

impl fmt::Display for MigrationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A validated, checksummed, versioned migration bundle.
///
/// The encoded bytes include filehandle key material. Applications must use a
/// confidential, authenticated transport and must apply their own
/// authorization before handing a received bundle to the server.
#[derive(Clone)]
pub struct MigrationBundle {
    encoded: Bytes,
    id: MigrationId,
    export_id: ExportId,
    fsid: FileSystemId,
    source_lease_seconds: u32,
    coordinator_generation: u64,
    coordinator_token_digest: [u8; 32],
    digest: [u8; 32],
    snapshot: MigrationStableSnapshot,
}

impl MigrationBundle {
    pub const fn version(&self) -> u32 {
        BUNDLE_VERSION
    }

    pub fn id(&self) -> MigrationId {
        self.id
    }

    pub fn export_id(&self) -> ExportId {
        self.export_id
    }

    pub fn fsid(&self) -> FileSystemId {
        self.fsid
    }

    pub fn source_generation(&self) -> u64 {
        self.snapshot.source_generation
    }

    /// Lease period advertised by the source when the migration was prepared.
    /// A destination performing reboot-style reclaim must keep grace open for
    /// at least this long.
    pub const fn source_lease_seconds(&self) -> u32 {
        self.source_lease_seconds
    }

    pub fn record_count(&self) -> usize {
        self.snapshot.records.len()
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub fn into_bytes(self) -> Bytes {
        self.encoded
    }

    pub fn decode(encoded: impl Into<Bytes>) -> Result<Self, MigrationBundleError> {
        Self::decode_with_limits(encoded, MigrationBundleLimits::default())
    }

    pub fn decode_with_limits(
        encoded: impl Into<Bytes>,
        limits: MigrationBundleLimits,
    ) -> Result<Self, MigrationBundleError> {
        let limits = limits.validate()?;
        let encoded = encoded.into();
        if encoded.len() > limits.max_encoded_bytes {
            return Err(MigrationBundleError::EncodedSize {
                actual: encoded.len(),
                maximum: limits.max_encoded_bytes,
            });
        }
        if encoded.len() < FIXED_BODY_BYTES + CHECKSUM_BYTES {
            return Err(MigrationBundleError::Truncated);
        }
        let body_length = encoded
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(MigrationBundleError::Truncated)?;
        let body = encoded.get(..body_length).ok_or(MigrationBundleError::Truncated)?;
        let expected_digest = encoded.get(body_length..).ok_or(MigrationBundleError::Truncated)?;
        let digest: [u8; 32] = Sha256::digest(body).into();
        if !constant_time_equal(&digest, expected_digest) {
            return Err(MigrationBundleError::Checksum);
        }

        let mut decoder = BundleDecoder::new(body);
        decoder.expect(&BUNDLE_MAGIC)?;
        let version = decoder.u32()?;
        if version != BUNDLE_VERSION {
            return Err(MigrationBundleError::UnsupportedVersion(version));
        }
        let flags = decoder.u32()?;
        if flags != BUNDLE_FLAGS {
            return Err(MigrationBundleError::UnsupportedFlags(flags));
        }
        let id = MigrationId(decoder.fixed()?);
        if id.0 == [0; 16] {
            return Err(MigrationBundleError::InvalidIdentity);
        }
        let export_id = ExportId(decoder.u32()?);
        let fsid = FileSystemId::new(decoder.u64()?, decoder.u64()?);
        let source_generation = decoder.u64()?;
        let source_lease_seconds = decoder.u32()?;
        if source_lease_seconds == 0 {
            return Err(MigrationBundleError::InvalidLeaseDuration);
        }
        let coordinator_generation = decoder.u64()?;
        let coordinator_token_digest = decoder.fixed()?;
        if coordinator_token_digest == [0; 32] {
            return Err(MigrationBundleError::InvalidIdentity);
        }
        let server_identity = crate::nfs4::stable::ServerIdentityRecord {
            identity: decoder.fixed()?,
        };
        let boot = crate::nfs4::stable::BootRecord {
            verifier: decoder.fixed()?,
            boot_tag: decoder.u32()?,
            started_at_unix_seconds: decoder.i64()?,
            clean_shutdown: decoder.boolean()?,
        };
        let handle_key = crate::nfs4::stable::HandleKeyRecord {
            instance_id: decoder.fixed()?,
            secret: decoder.fixed()?,
        };
        let count = usize::try_from(decoder.u32()?).map_err(|_| MigrationBundleError::LengthOverflow)?;
        if count > limits.max_records {
            return Err(MigrationBundleError::RecordCount {
                actual: count,
                maximum: limits.max_records,
            });
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = decode_record_kind(decoder.u8()?)?;
            let key = decoder.opaque(limits.max_key_bytes, "stable key")?;
            let payload = decoder.opaque(limits.max_record_payload_bytes, "stable payload")?;
            records.push(StableRecord {
                key: crate::vfs::StableKey { kind, key },
                payload,
            });
        }
        decoder.finish()?;
        let snapshot = MigrationStableSnapshot {
            source_generation,
            server_identity,
            boot,
            handle_key,
            records,
        };
        validate_migration_snapshot(&snapshot, export_id, limits.journal_limits())
            .map_err(|error| MigrationBundleError::InvalidStableState(error.to_string()))?;

        Ok(Self {
            encoded,
            id,
            export_id,
            fsid,
            source_lease_seconds,
            coordinator_generation,
            coordinator_token_digest,
            digest,
            snapshot,
        })
    }

    fn create(
        id: MigrationId,
        export_id: ExportId,
        fsid: FileSystemId,
        source_lease_seconds: u32,
        fence: &MigrationFence,
        snapshot: MigrationStableSnapshot,
        limits: MigrationBundleLimits,
    ) -> Result<Self, MigrationBundleError> {
        let limits = limits.validate()?;
        if fence.export_id != export_id {
            return Err(MigrationBundleError::FenceExportMismatch);
        }
        if source_lease_seconds == 0 {
            return Err(MigrationBundleError::InvalidLeaseDuration);
        }
        if fence.token.is_empty() {
            return Err(MigrationBundleError::InvalidIdentity);
        }
        if fence.token.len() > limits.max_coordinator_token_bytes {
            return Err(MigrationBundleError::CoordinatorTokenSize {
                actual: fence.token.len(),
                maximum: limits.max_coordinator_token_bytes,
            });
        }
        validate_migration_snapshot(&snapshot, export_id, limits.journal_limits())
            .map_err(|error| MigrationBundleError::InvalidStableState(error.to_string()))?;
        let coordinator_token_digest: [u8; 32] = Sha256::digest(fence.token.as_ref()).into();
        let mut encoder = BundleEncoder::with_capacity(
            FIXED_BODY_BYTES
                .saturating_add(snapshot.records.iter().map(encoded_record_len).sum::<usize>())
                .saturating_add(CHECKSUM_BYTES),
        );
        encoder.fixed(&BUNDLE_MAGIC);
        encoder.u32(BUNDLE_VERSION);
        encoder.u32(BUNDLE_FLAGS);
        encoder.fixed(&id.0);
        encoder.u32(export_id.0);
        encoder.u64(fsid.major);
        encoder.u64(fsid.minor);
        encoder.u64(snapshot.source_generation);
        encoder.u32(source_lease_seconds);
        encoder.u64(fence.generation);
        encoder.fixed(&coordinator_token_digest);
        encoder.fixed(&snapshot.server_identity.identity);
        encoder.fixed(&snapshot.boot.verifier);
        encoder.u32(snapshot.boot.boot_tag);
        encoder.i64(snapshot.boot.started_at_unix_seconds);
        encoder.boolean(snapshot.boot.clean_shutdown);
        encoder.fixed(&snapshot.handle_key.instance_id);
        encoder.fixed(&snapshot.handle_key.secret);
        encoder.u32(u32::try_from(snapshot.records.len()).map_err(|_| MigrationBundleError::RecordCount {
            actual: snapshot.records.len(),
            maximum: limits.max_records,
        })?);
        for record in &snapshot.records {
            encoder.u8(encode_record_kind(record.key.kind));
            encoder.opaque(&record.key.key)?;
            encoder.opaque(&record.payload)?;
        }
        let mut bytes = encoder.finish();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&digest);
        if bytes.len() > limits.max_encoded_bytes {
            return Err(MigrationBundleError::EncodedSize {
                actual: bytes.len(),
                maximum: limits.max_encoded_bytes,
            });
        }
        let encoded = Bytes::from(bytes);
        Ok(Self {
            encoded,
            id,
            export_id,
            fsid,
            source_lease_seconds,
            coordinator_generation: fence.generation,
            coordinator_token_digest,
            digest,
            snapshot,
        })
    }

    fn capsule(&self) -> MigrationCapsuleRecord {
        MigrationCapsuleRecord {
            transfer_id: self.id.0,
            export_id: self.export_id,
            fsid_major: self.fsid.major,
            fsid_minor: self.fsid.minor,
            source_generation: self.snapshot.source_generation,
            coordinator_generation: self.coordinator_generation,
            coordinator_token_digest: self.coordinator_token_digest,
            bundle_digest: self.digest,
            server_identity: self.snapshot.server_identity,
            boot: self.snapshot.boot,
            handle_key: self.snapshot.handle_key,
            phase: MigrationPhase::Staged,
            records: self.snapshot.records.clone(),
        }
    }
}

impl PartialEq for MigrationBundle {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for MigrationBundle {}

impl fmt::Debug for MigrationBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationBundle")
            .field("version", &BUNDLE_VERSION)
            .field("id", &self.id)
            .field("export_id", &self.export_id)
            .field("fsid", &self.fsid)
            .field("source_lease_seconds", &self.source_lease_seconds)
            .field("source_generation", &self.snapshot.source_generation)
            .field("record_count", &self.snapshot.records.len())
            .field("encoded_len", &self.encoded.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MigrationBundleError {
    #[error("migration bundle limits are invalid")]
    InvalidLimits,
    #[error("migration bundle is truncated")]
    Truncated,
    #[error("migration bundle contains trailing bytes")]
    TrailingBytes,
    #[error("migration bundle length overflow")]
    LengthOverflow,
    #[error("migration bundle checksum does not match")]
    Checksum,
    #[error("migration bundle version {0} is unsupported")]
    UnsupportedVersion(u32),
    #[error("migration bundle flags {0:#x} are unsupported")]
    UnsupportedFlags(u32),
    #[error("migration bundle identity is invalid")]
    InvalidIdentity,
    #[error("migration bundle source lease duration is invalid")]
    InvalidLeaseDuration,
    #[error("migration bundle encoded size {actual} exceeds limit {maximum}")]
    EncodedSize { actual: usize, maximum: usize },
    #[error("migration bundle record count {actual} exceeds limit {maximum}")]
    RecordCount { actual: usize, maximum: usize },
    #[error("migration bundle {field} size {actual} exceeds limit {maximum}")]
    FieldSize {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("migration coordinator token size {actual} exceeds limit {maximum}")]
    CoordinatorTokenSize { actual: usize, maximum: usize },
    #[error("migration fence belongs to a different export")]
    FenceExportMismatch,
    #[error("migration bundle stable state is invalid: {0}")]
    InvalidStableState(String),
    #[error("migration bundle stable record kind {0} is invalid")]
    InvalidRecordKind(u8),
    #[error("migration bundle boolean is not canonical")]
    InvalidBoolean,
    #[error("migration bundle magic is invalid")]
    InvalidMagic,
}

/// Errors from the server-handle two-phase migration API.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MigrationControlError {
    #[error("NFSv4 migration is not configured")]
    NotConfigured,
    #[error("export {0:?} is not registered")]
    UnknownExport(ExportId),
    #[error("export {0:?} does not use persistent filehandles")]
    PersistentHandlesRequired(ExportId),
    #[error("migration bundle fsid does not match export {export_id:?}")]
    FileSystemIdentityMismatch { export_id: ExportId },
    #[error("destination grace period is shorter than the source lease period for export {export_id:?}")]
    SourceLeaseExceedsGrace { export_id: ExportId },
    #[error("migration transaction {0} is not active on this server")]
    UnknownTransaction(MigrationId),
    #[error("another migration transaction is active for export {0:?}")]
    Conflict(ExportId),
    #[error("migration operation is fenced")]
    Fenced,
    #[error("source protocol state changed after the migration snapshot for export {export_id:?}")]
    SourceStateChanged { export_id: ExportId },
    #[error("migration transaction was already committed")]
    AlreadyCommitted,
    #[error("migration bundle is invalid: {0}")]
    Bundle(#[from] MigrationBundleError),
    #[error("migration coordinator failed: {0}")]
    Coordinator(#[from] MigrationError),
    #[error("durable migration state failed: {0}")]
    StableState(String),
    #[error("operating-system random source failed: {0}")]
    Entropy(String),
    #[error("migration worker failed: {0}")]
    Worker(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationGateStatus {
    Active,
    Quiescing,
    Moved,
}

#[derive(Default)]
pub(crate) struct MigrationGate {
    state: StdMutex<BTreeMap<ExportId, GateEntry>>,
    drained: Notify,
}

#[derive(Clone, Copy)]
struct GateEntry {
    status: MigrationGateStatus,
    in_flight_mutations: usize,
}

impl Default for GateEntry {
    fn default() -> Self {
        Self {
            status: MigrationGateStatus::Active,
            in_flight_mutations: 0,
        }
    }
}

impl MigrationGate {
    pub(crate) fn try_enter_mutation(
        self: &Arc<Self>,
        export_id: ExportId,
    ) -> Result<MigrationMutationGuard, MigrationGateStatus> {
        let mut state = lock_unpoisoned(&self.state);
        let entry = state.entry(export_id).or_default();
        if entry.status != MigrationGateStatus::Active {
            return Err(entry.status);
        }
        entry.in_flight_mutations = entry.in_flight_mutations.checked_add(1).ok_or(MigrationGateStatus::Quiescing)?;
        Ok(MigrationMutationGuard {
            gate: Arc::clone(self),
            export_id,
        })
    }

    pub(crate) fn status(&self, export_id: ExportId) -> MigrationGateStatus {
        lock_unpoisoned(&self.state).get(&export_id).copied().unwrap_or_default().status
    }

    async fn quiesce_and_drain(&self, export_id: ExportId) -> Result<(), MigrationControlError> {
        loop {
            let notified = self.drained.notified();
            {
                let mut state = lock_unpoisoned(&self.state);
                let entry = state.entry(export_id).or_default();
                match entry.status {
                    MigrationGateStatus::Moved => return Err(MigrationControlError::Fenced),
                    MigrationGateStatus::Active => entry.status = MigrationGateStatus::Quiescing,
                    MigrationGateStatus::Quiescing => {},
                }
                if entry.in_flight_mutations == 0 {
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    fn resume(&self, export_id: ExportId) {
        let mut state = lock_unpoisoned(&self.state);
        let entry = state.entry(export_id).or_default();
        if entry.status != MigrationGateStatus::Moved {
            entry.status = MigrationGateStatus::Active;
        }
        self.drained.notify_waiters();
    }

    fn mark_moved(&self, export_id: ExportId) {
        lock_unpoisoned(&self.state).entry(export_id).or_default().status = MigrationGateStatus::Moved;
        self.drained.notify_waiters();
    }
}

pub(crate) struct MigrationMutationGuard {
    gate: Arc<MigrationGate>,
    export_id: ExportId,
}

impl Drop for MigrationMutationGuard {
    fn drop(&mut self) {
        let mut state = lock_unpoisoned(&self.gate.state);
        if let Some(entry) = state.get_mut(&self.export_id) {
            entry.in_flight_mutations = entry.in_flight_mutations.saturating_sub(1);
            if entry.in_flight_mutations == 0 {
                self.gate.drained.notify_waiters();
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MigrationExportIdentity {
    pub export_id: ExportId,
    pub fsid: FileSystemId,
    pub persistent_handles: bool,
}

#[derive(Default)]
pub(crate) struct MigrationHandleRegistry {
    entries: StdMutex<BTreeMap<ExportId, Vec<ImportedCodec>>>,
}

struct ImportedCodec {
    transfer_id: [u8; 16],
    server_identity: [u8; 16],
    instance_id: [u8; 8],
    secret: [u8; 32],
    codec: HandleCodec,
}

impl MigrationHandleRegistry {
    fn validate_install(
        &self,
        export_id: ExportId,
        server_identity: [u8; 16],
        instance_id: [u8; 8],
        secret: [u8; 32],
    ) -> Result<(), MigrationControlError> {
        if lock_unpoisoned(&self.entries)
            .get(&export_id)
            .into_iter()
            .flatten()
            .any(|entry| {
                entry.instance_id == instance_id && (entry.server_identity != server_identity || entry.secret != secret)
            })
        {
            return Err(MigrationControlError::StableState("conflicting imported filehandle identity".to_owned()));
        }
        Ok(())
    }

    fn install(
        &self,
        export_id: ExportId,
        transfer_id: [u8; 16],
        server_identity: [u8; 16],
        instance_id: [u8; 8],
        secret: [u8; 32],
    ) -> Result<(), MigrationControlError> {
        self.validate_install(export_id, server_identity, instance_id, secret)?;
        let mut entries = lock_unpoisoned(&self.entries);
        let export_entries = entries.entry(export_id).or_default();
        if export_entries
            .iter()
            .any(|entry| entry.instance_id == instance_id && entry.secret == secret)
        {
            return Ok(());
        }
        export_entries.push(ImportedCodec {
            transfer_id,
            server_identity,
            instance_id,
            secret,
            codec: HandleCodec::from_key(instance_id, secret),
        });
        Ok(())
    }

    /// Decodes an untrusted PUTFH value without assuming an export first.
    /// Imported codecs remain scoped to the export they were migrated with;
    /// pseudo handles and ambiguously authenticated targets are rejected.
    pub(crate) fn decode_any(&self, handle: &[u8]) -> Option<Result<HandleTarget, HandleError>> {
        let entries = lock_unpoisoned(&self.entries);
        if entries.is_empty() {
            return None;
        }
        let mut decoded = None;
        let mut last_error = HandleError::StaleInstance;
        for (registered_export, codecs) in entries.iter() {
            for entry in codecs {
                match entry.codec.decode_target(handle) {
                    Ok(
                        target @ HandleTarget::Backend {
                            export_id: decoded_export,
                            ..
                        },
                    ) if decoded_export == *registered_export => {
                        if decoded.is_some_and(|existing| existing != target) {
                            return Some(Err(HandleError::InvalidTarget));
                        }
                        decoded = Some(target);
                    },
                    Ok(HandleTarget::Backend { .. }) => {
                        last_error = prefer_handle_error(Some(last_error), HandleError::WrongExport)
                    },
                    Ok(HandleTarget::Pseudo { .. }) => {
                        last_error = prefer_handle_error(Some(last_error), HandleError::InvalidTarget)
                    },
                    Err(error) => last_error = prefer_handle_error(Some(last_error), error),
                }
            }
        }
        Some(decoded.ok_or(last_error))
    }

    #[cfg(test)]
    fn len_for_export(&self, export_id: ExportId) -> usize {
        lock_unpoisoned(&self.entries).get(&export_id).map_or(0, Vec::len)
    }
}

impl fmt::Debug for MigrationHandleRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = lock_unpoisoned(&self.entries);
        let count = entries.values().map(Vec::len).sum::<usize>();
        let transfer_count = entries
            .values()
            .flatten()
            .map(|entry| entry.transfer_id)
            .collect::<std::collections::HashSet<_>>()
            .len();
        formatter
            .debug_struct("MigrationHandleRegistry")
            .field("export_count", &entries.len())
            .field("identity_count", &count)
            .field("transfer_count", &transfer_count)
            .finish()
    }
}

pub(crate) struct MigrationControl {
    coordinator: Arc<dyn MigrationCoordinator>,
    stable: Arc<Mutex<StableJournal>>,
    runtime: Nfs4Runtime,
    delegations: Arc<HashMap<ExportId, Arc<DelegationManager>>>,
    exports: BTreeMap<ExportId, MigrationExportIdentity>,
    limits: MigrationBundleLimits,
    gate: Arc<MigrationGate>,
    handles: Arc<MigrationHandleRegistry>,
    operations: Mutex<MigrationOperations>,
    operation_serial: Mutex<()>,
}

#[derive(Default)]
struct MigrationOperations {
    by_id: HashMap<MigrationId, PendingMigration>,
    by_export: BTreeMap<ExportId, MigrationId>,
}

#[derive(Clone)]
enum PendingMigration {
    Source {
        export_id: ExportId,
        destination: Nfs4FsLocation,
        fence: MigrationFence,
        bundle: MigrationBundle,
    },
    Import {
        export_id: ExportId,
        capsule: MigrationCapsuleRecord,
        prepared_runtime: Option<PreparedRuntimeRecovery>,
        prepared_delegation: Option<PreparedDelegationRecovery>,
    },
}

impl PendingMigration {
    fn export_id(&self) -> ExportId {
        match self {
            Self::Source { export_id, .. } | Self::Import { export_id, .. } => *export_id,
        }
    }
}

impl MigrationControl {
    pub(crate) async fn new(
        coordinator: Arc<dyn MigrationCoordinator>,
        stable: Arc<Mutex<StableJournal>>,
        runtime: Nfs4Runtime,
        delegations: Arc<HashMap<ExportId, Arc<DelegationManager>>>,
        exports: impl IntoIterator<Item = MigrationExportIdentity>,
        limits: MigrationBundleLimits,
    ) -> Result<Arc<Self>, MigrationControlError> {
        let limits = limits.validate()?;
        let mut export_map = BTreeMap::new();
        for export in exports {
            if export_map.insert(export.export_id, export).is_some() {
                return Err(MigrationControlError::Conflict(export.export_id));
            }
        }
        let handles = Arc::new(MigrationHandleRegistry::default());
        let (imported_handle_keys, source_moved_exports) = {
            let journal = stable.lock().await;
            (journal.imported_handle_keys(), journal.source_moved_exports())
        };
        for imported in imported_handle_keys {
            handles.install(
                imported.export_id,
                imported.transfer_id,
                imported.server_identity,
                imported.handle_key.instance_id,
                imported.handle_key.secret,
            )?;
        }
        let gate = Arc::new(MigrationGate::default());
        for export_id in source_moved_exports {
            gate.mark_moved(export_id);
        }
        Ok(Arc::new(Self {
            coordinator,
            stable,
            runtime,
            delegations,
            exports: export_map,
            limits,
            gate,
            handles,
            operations: Mutex::new(MigrationOperations::default()),
            operation_serial: Mutex::new(()),
        }))
    }

    pub(crate) fn gate(&self) -> Arc<MigrationGate> {
        Arc::clone(&self.gate)
    }

    pub(crate) fn imported_handles(&self) -> Arc<MigrationHandleRegistry> {
        Arc::clone(&self.handles)
    }

    /// Returns the coordinator's current locations for an export.
    ///
    /// An empty location list means the coordinator has no authoritative
    /// placement information, allowing the configured namespace locations to
    /// remain the fallback. The coordinator is consulted at request time so a
    /// completed cutover is reflected without rebuilding the server.
    pub(crate) fn locations(&self, export_id: ExportId) -> Option<crate::vfs::Nfs4FsLocations> {
        let locations = self.coordinator.locations(export_id);
        (!locations.locations.is_empty()).then_some(locations)
    }

    pub(crate) async fn prepare(
        self: &Arc<Self>,
        export_id: ExportId,
        destination: Nfs4FsLocation,
    ) -> Result<MigrationBundle, MigrationControlError> {
        let control = Arc::clone(self);
        shield(async move { control.prepare_inner(export_id, destination).await }).await
    }

    async fn prepare_inner(
        &self,
        export_id: ExportId,
        destination: Nfs4FsLocation,
    ) -> Result<MigrationBundle, MigrationControlError> {
        let _serial = self.operation_serial.lock().await;
        let identity = self.export_identity(export_id)?;
        if let Some(existing) = self.pending_for_export(export_id).await {
            return match existing {
                PendingMigration::Source {
                    destination: existing_destination,
                    bundle,
                    ..
                } if existing_destination == destination => Ok(bundle),
                _ => Err(MigrationControlError::Conflict(export_id)),
            };
        }

        let fence = self.coordinator.prepare(export_id, destination.clone()).await?;
        if fence.export_id != export_id {
            let _ = self.coordinator.abort(&fence).await;
            return Err(MigrationControlError::Fenced);
        }
        if let Err(error) = self.gate.quiesce_and_drain(export_id).await {
            let _ = self.coordinator.abort(&fence).await;
            self.gate.resume(export_id);
            return Err(error);
        }
        let snapshot = match self.stable.lock().await.snapshot_for_migration(export_id).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let _ = self.coordinator.abort(&fence).await;
                self.gate.resume(export_id);
                return Err(map_stable_error(error));
            },
        };
        let id = match MigrationId::random() {
            Ok(id) => id,
            Err(error) => {
                let _ = self.coordinator.abort(&fence).await;
                self.gate.resume(export_id);
                return Err(error);
            },
        };
        let source_lease_seconds = match u32::try_from(self.runtime.lease_duration().as_secs()) {
            Ok(seconds) if seconds != 0 => seconds,
            _ => {
                let _ = self.coordinator.abort(&fence).await;
                self.gate.resume(export_id);
                return Err(MigrationBundleError::InvalidLeaseDuration.into());
            },
        };
        let bundle = match MigrationBundle::create(
            id,
            export_id,
            identity.fsid,
            source_lease_seconds,
            &fence,
            snapshot,
            self.limits,
        ) {
            Ok(bundle) => bundle,
            Err(error) => {
                let _ = self.coordinator.abort(&fence).await;
                self.gate.resume(export_id);
                return Err(error.into());
            },
        };
        if let Err(error) = self
            .insert_pending(
                id,
                PendingMigration::Source {
                    export_id,
                    destination,
                    fence: fence.clone(),
                    bundle: bundle.clone(),
                },
            )
            .await
        {
            let _ = self.coordinator.abort(&fence).await;
            self.gate.resume(export_id);
            return Err(error);
        }
        Ok(bundle)
    }

    pub(crate) async fn import(
        self: &Arc<Self>,
        bundle: MigrationBundle,
    ) -> Result<MigrationId, MigrationControlError> {
        let control = Arc::clone(self);
        shield(async move { control.import_inner(bundle).await }).await
    }

    async fn import_inner(&self, bundle: MigrationBundle) -> Result<MigrationId, MigrationControlError> {
        let _serial = self.operation_serial.lock().await;
        let export_id = bundle.export_id;
        let identity = self.export_identity(export_id)?;
        if identity.fsid != bundle.fsid {
            return Err(MigrationControlError::FileSystemIdentityMismatch { export_id });
        }
        let source_lease = Duration::from_secs(u64::from(bundle.source_lease_seconds));
        if self.runtime.grace_duration() < source_lease {
            return Err(MigrationControlError::SourceLeaseExceedsGrace { export_id });
        }
        if let Some(existing) = self.pending_for_export(export_id).await {
            return match existing {
                PendingMigration::Import { capsule, .. } if capsule.transfer_id == bundle.id.0 => Ok(bundle.id),
                _ => Err(MigrationControlError::Conflict(export_id)),
            };
        }
        self.gate.quiesce_and_drain(export_id).await?;
        let capsule = bundle.capsule();
        if let Err(error) = self.handles.validate_install(
            export_id,
            capsule.server_identity.identity,
            capsule.handle_key.instance_id,
            capsule.handle_key.secret,
        ) {
            self.gate.resume(export_id);
            return Err(error);
        }
        let already_committed = {
            let stable = self.stable.lock().await;
            match stable.migration_import_already_committed(&capsule) {
                Ok(committed) => committed,
                Err(error) => {
                    self.gate.resume(export_id);
                    return Err(map_stable_error(error));
                },
            }
        };
        if already_committed {
            if let Err(error) = self.handles.install(
                export_id,
                capsule.transfer_id,
                capsule.server_identity.identity,
                capsule.handle_key.instance_id,
                capsule.handle_key.secret,
            ) {
                self.gate.resume(export_id);
                return Err(error);
            }
            if let Err(error) = self
                .insert_pending(
                    bundle.id,
                    PendingMigration::Import {
                        export_id,
                        capsule,
                        prepared_runtime: None,
                        prepared_delegation: None,
                    },
                )
                .await
            {
                self.gate.resume(export_id);
                return Err(error);
            }
            return Ok(bundle.id);
        }
        let recovered = {
            let stable = self.stable.lock().await;
            match recovery_from_migration_capsule(&capsule, stable.limits()) {
                Ok(recovered) => recovered,
                Err(error) => {
                    self.gate.resume(export_id);
                    return Err(map_stable_error(error));
                },
            }
        };
        let prepared_runtime = match self.runtime.prepare_recovery_import(&recovered, source_lease) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.gate.resume(export_id);
                return Err(MigrationControlError::StableState(format!(
                    "invalid migrated NFSv4 runtime state: {error}"
                )));
            },
        };
        let Some(delegation_manager) = self.delegations.get(&export_id) else {
            self.gate.resume(export_id);
            return Err(MigrationControlError::StableState("migration export has no delegation manager".to_owned()));
        };
        let prepared_delegation = match delegation_manager.prepare_recovery_import(&recovered).await {
            Ok(prepared) => prepared,
            Err(error) => {
                self.gate.resume(export_id);
                return Err(MigrationControlError::StableState(format!(
                    "invalid migrated NFSv4 delegation state: {error}"
                )));
            },
        };
        if let Err(error) = self.runtime.validate_recovery_import(&prepared_runtime).await {
            self.gate.resume(export_id);
            return Err(MigrationControlError::StableState(format!(
                "migrated NFSv4 runtime state conflicts with live state: {error}"
            )));
        }
        let stage = match self.stable.lock().await.stage_migration_import(capsule.clone()).await {
            Ok(stage) => stage,
            Err(error) => {
                self.gate.resume(export_id);
                return Err(map_stable_error(error));
            },
        };
        if stage == MigrationStageStatus::AlreadyCommitted {
            self.handles.install(
                export_id,
                capsule.transfer_id,
                capsule.server_identity.identity,
                capsule.handle_key.instance_id,
                capsule.handle_key.secret,
            )?;
        }
        let (prepared_runtime, prepared_delegation) = if stage == MigrationStageStatus::AlreadyCommitted {
            (None, None)
        } else {
            (Some(prepared_runtime), Some(prepared_delegation))
        };
        if let Err(error) = self
            .insert_pending(
                bundle.id,
                PendingMigration::Import {
                    export_id,
                    capsule,
                    prepared_runtime,
                    prepared_delegation,
                },
            )
            .await
        {
            if stage != MigrationStageStatus::AlreadyCommitted {
                let _ = self.stable.lock().await.abort_migration_import(bundle.id.0).await;
            }
            self.gate.resume(export_id);
            return Err(error);
        }
        Ok(bundle.id)
    }

    pub(crate) async fn commit(self: &Arc<Self>, id: MigrationId) -> Result<(), MigrationControlError> {
        let control = Arc::clone(self);
        shield(async move { control.commit_inner(id).await }).await
    }

    async fn commit_inner(&self, id: MigrationId) -> Result<(), MigrationControlError> {
        let _serial = self.operation_serial.lock().await;
        let pending = self
            .operations
            .lock()
            .await
            .by_id
            .get(&id)
            .cloned()
            .ok_or(MigrationControlError::UnknownTransaction(id))?;
        match &pending {
            PendingMigration::Source {
                export_id,
                fence,
                bundle,
                ..
            } => {
                // Keep the stable journal locked across the coordinator
                // cutover. Any protocol-state write after the snapshot either
                // makes this check fail or waits until the export has been
                // durably fenced as MOVED.
                let mut stable = self.stable.lock().await;
                stable.verify_live_fence().map_err(map_stable_error)?;
                let capsule = bundle.capsule();
                if !stable.source_cutover_armed(&capsule).map_err(map_stable_error)? {
                    if stable.generation() != bundle.source_generation() {
                        return Err(MigrationControlError::SourceStateChanged { export_id: *export_id });
                    }
                    stable.arm_source_cutover(capsule).await.map_err(map_stable_error)?;
                }
                // A process stop or ambiguous coordinator result after this
                // point must never cause the old source to serve again.
                self.gate.mark_moved(*export_id);
                self.coordinator.commit(fence).await?;
            },
            PendingMigration::Import {
                export_id,
                capsule,
                prepared_runtime,
                prepared_delegation,
            } => {
                self.handles.validate_install(
                    *export_id,
                    capsule.server_identity.identity,
                    capsule.handle_key.instance_id,
                    capsule.handle_key.secret,
                )?;
                let delegation_manager = self.delegations.get(export_id).ok_or_else(|| {
                    MigrationControlError::StableState("migration export has no delegation manager".to_owned())
                })?;
                // SETCLIENTID must observe either none or all of the imported
                // client/delegation identity. Keep its production path
                // serialized from the final conflict checks through durable
                // commit and activation of both registries.
                let _transition_guard = self.runtime.client_state_transition_guard().await;
                if let Some(prepared) = prepared_runtime {
                    self.runtime.validate_recovery_import(prepared).await.map_err(|error| {
                        MigrationControlError::StableState(format!(
                            "migrated NFSv4 runtime state conflicts with live state: {error}"
                        ))
                    })?;
                }
                if let Some(prepared) = prepared_delegation {
                    delegation_manager.validate_recovery_import(prepared).await.map_err(|error| {
                        MigrationControlError::StableState(format!(
                            "migrated NFSv4 delegation state conflicts with live state: {error}"
                        ))
                    })?;
                }
                let committed = self
                    .stable
                    .lock()
                    .await
                    .commit_migration_import(id.0)
                    .await
                    .map_err(map_stable_error)?;
                if let Some(prepared) = prepared_runtime.clone() {
                    self.runtime.activate_recovery_import(prepared).await.map_err(|error| {
                        MigrationControlError::StableState(format!(
                            "failed to activate migrated NFSv4 runtime state: {error}"
                        ))
                    })?;
                }
                if let Some(prepared) = prepared_delegation.clone() {
                    delegation_manager.activate_recovery_import(prepared).await.map_err(|error| {
                        MigrationControlError::StableState(format!(
                            "failed to activate migrated NFSv4 delegation state: {error}"
                        ))
                    })?;
                }
                self.install_committed_handle(&committed)?;
                self.gate.resume(*export_id);
            },
        }
        self.remove_pending(id, pending.export_id()).await;
        Ok(())
    }

    pub(crate) async fn abort(self: &Arc<Self>, id: MigrationId) -> Result<(), MigrationControlError> {
        let control = Arc::clone(self);
        shield(async move { control.abort_inner(id).await }).await
    }

    async fn abort_inner(&self, id: MigrationId) -> Result<(), MigrationControlError> {
        let _serial = self.operation_serial.lock().await;
        let pending = self
            .operations
            .lock()
            .await
            .by_id
            .get(&id)
            .cloned()
            .ok_or(MigrationControlError::UnknownTransaction(id))?;
        match &pending {
            PendingMigration::Source {
                export_id,
                fence,
                bundle,
                ..
            } => {
                if self
                    .stable
                    .lock()
                    .await
                    .source_cutover_armed(&bundle.capsule())
                    .map_err(map_stable_error)?
                {
                    self.gate.mark_moved(*export_id);
                    return Err(MigrationControlError::AlreadyCommitted);
                }
                self.coordinator.abort(fence).await?;
                self.gate.resume(*export_id);
            },
            PendingMigration::Import { export_id, .. } => {
                let aborted = self.stable.lock().await.abort_migration_import(id.0).await;
                if let Err(error) = aborted {
                    if error == crate::nfs4::stable::StableJournalError::MigrationCommitted {
                        self.gate.resume(*export_id);
                    }
                    return Err(map_stable_error(error));
                }
                self.gate.resume(*export_id);
            },
        }
        self.remove_pending(id, pending.export_id()).await;
        Ok(())
    }

    fn export_identity(&self, export_id: ExportId) -> Result<MigrationExportIdentity, MigrationControlError> {
        let identity = self
            .exports
            .get(&export_id)
            .copied()
            .ok_or(MigrationControlError::UnknownExport(export_id))?;
        if !identity.persistent_handles {
            return Err(MigrationControlError::PersistentHandlesRequired(export_id));
        }
        Ok(identity)
    }

    async fn pending_for_export(&self, export_id: ExportId) -> Option<PendingMigration> {
        let operations = self.operations.lock().await;
        operations
            .by_export
            .get(&export_id)
            .and_then(|id| operations.by_id.get(id))
            .cloned()
    }

    async fn insert_pending(&self, id: MigrationId, pending: PendingMigration) -> Result<(), MigrationControlError> {
        let export_id = pending.export_id();
        let mut operations = self.operations.lock().await;
        if operations.by_id.contains_key(&id) || operations.by_export.contains_key(&export_id) {
            return Err(MigrationControlError::Conflict(export_id));
        }
        operations.by_export.insert(export_id, id);
        operations.by_id.insert(id, pending);
        Ok(())
    }

    async fn remove_pending(&self, id: MigrationId, export_id: ExportId) {
        let mut operations = self.operations.lock().await;
        operations.by_id.remove(&id);
        if operations.by_export.get(&export_id) == Some(&id) {
            operations.by_export.remove(&export_id);
        }
    }

    fn install_committed_handle(&self, committed: &CommittedMigration) -> Result<(), MigrationControlError> {
        self.handles.install(
            committed.export_id,
            committed.transfer_id,
            committed.server_identity,
            committed.handle_key.instance_id,
            committed.handle_key.secret,
        )
    }
}

impl fmt::Debug for MigrationControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationControl")
            .field("exports", &self.exports.keys().collect::<Vec<_>>())
            .field("limits", &self.limits)
            .field("gate", &"<migration gate>")
            .field("handles", &self.handles)
            .finish_non_exhaustive()
    }
}

async fn shield<T, F>(future: F) -> Result<T, MigrationControlError>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, MigrationControlError>> + Send + 'static,
{
    tokio::spawn(future)
        .await
        .map_err(|error| MigrationControlError::Worker(error.to_string()))?
}

fn map_stable_error(error: crate::nfs4::stable::StableJournalError) -> MigrationControlError {
    match error {
        crate::nfs4::stable::StableJournalError::Fenced => MigrationControlError::Fenced,
        crate::nfs4::stable::StableJournalError::MigrationConflict => {
            MigrationControlError::StableState("migration state conflicts with durable state".to_owned())
        },
        crate::nfs4::stable::StableJournalError::MigrationCommitted => MigrationControlError::AlreadyCommitted,
        error => MigrationControlError::StableState(error.to_string()),
    }
}

fn encoded_record_len(record: &StableRecord) -> usize {
    1usize
        .saturating_add(4)
        .saturating_add(record.key.key.len())
        .saturating_add(4)
        .saturating_add(record.payload.len())
}

fn encode_record_kind(kind: StableRecordKind) -> u8 {
    match kind {
        StableRecordKind::Server => 0,
        StableRecordKind::Client => 1,
        StableRecordKind::OpenOwner => 2,
        StableRecordKind::LockOwner => 3,
        StableRecordKind::Migration => 4,
    }
}

fn decode_record_kind(code: u8) -> Result<StableRecordKind, MigrationBundleError> {
    match code {
        0 => Ok(StableRecordKind::Server),
        1 => Ok(StableRecordKind::Client),
        2 => Ok(StableRecordKind::OpenOwner),
        3 => Ok(StableRecordKind::LockOwner),
        4 => Ok(StableRecordKind::Migration),
        _ => Err(MigrationBundleError::InvalidRecordKind(code)),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> StdMutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn prefer_handle_error(current: Option<HandleError>, candidate: HandleError) -> HandleError {
    match current {
        Some(current) if handle_error_rank(current) >= handle_error_rank(candidate) => current,
        _ => candidate,
    }
}

fn handle_error_rank(error: HandleError) -> u8 {
    match error {
        HandleError::InvalidTarget => 6,
        HandleError::WrongExport => 5,
        HandleError::InvalidTag => 4,
        HandleError::InvalidFormat => 3,
        HandleError::InvalidLength => 2,
        HandleError::StaleInstance => 1,
    }
}

struct BundleEncoder {
    bytes: Vec<u8>,
}

impl BundleEncoder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.fixed(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn opaque(&mut self, value: &[u8]) -> Result<(), MigrationBundleError> {
        self.u32(u32::try_from(value.len()).map_err(|_| MigrationBundleError::LengthOverflow)?);
        self.fixed(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct BundleDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BundleDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MigrationBundleError> {
        let end = self.position.checked_add(length).ok_or(MigrationBundleError::LengthOverflow)?;
        let value = self.bytes.get(self.position..end).ok_or(MigrationBundleError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn expect<const N: usize>(&mut self, expected: &[u8; N]) -> Result<(), MigrationBundleError> {
        if self.take(N)? == expected {
            Ok(())
        } else {
            Err(MigrationBundleError::InvalidMagic)
        }
    }

    fn u8(&mut self) -> Result<u8, MigrationBundleError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, MigrationBundleError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MigrationBundleError::InvalidBoolean),
        }
    }

    fn u32(&mut self) -> Result<u32, MigrationBundleError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, MigrationBundleError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn i64(&mut self) -> Result<i64, MigrationBundleError> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], MigrationBundleError> {
        self.take(N)?.try_into().map_err(|_| MigrationBundleError::Truncated)
    }

    fn opaque(&mut self, maximum: usize, field: &'static str) -> Result<Bytes, MigrationBundleError> {
        let length = usize::try_from(self.u32()?).map_err(|_| MigrationBundleError::LengthOverflow)?;
        if length > maximum {
            return Err(MigrationBundleError::FieldSize {
                field,
                actual: length,
                maximum,
            });
        }
        Ok(Bytes::copy_from_slice(self.take(length)?))
    }

    fn finish(self) -> Result<(), MigrationBundleError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MigrationBundleError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as TestMutex;
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::nfs4::callback::SystemCallbackClock;
    use crate::nfs4::delegation::DelegationManager;
    use crate::nfs4::runtime::{Nfs4Runtime, RuntimeConfig};
    use crate::nfs4::stable::{
        BootRecord, ClientRecord, DelegationRecord, HandleKeyRecord, JournalKey, JournalRecord, PersistBatch,
        ServerIdentityRecord, StableObject,
    };
    use crate::nfs4::types::{
        CallbackClient, ClientAddress, NfsClientId, NfsStatus, SetClientIdArgs, SetClientIdResult,
    };
    use crate::server::{DelegationPolicy, Nfs4Limits};
    use crate::vfs::{
        ChangeId, CreatedObject, FileAttributes, FileType, Nfs4FsLocations, NfsError, NfsName, NfsTime, ObjectKey,
        Principal, RequestContext, StableBatch, StableFenceToken, StableKey, StableMutation, StableRecord,
        StableRecordKind, StableScope, StableSnapshot, StableStateError, StableStateSession, StableStateStore,
        VfsCapabilities, VirtualFileSystem,
    };

    #[derive(Default)]
    struct TestStableStore {
        state: Arc<TestMutex<TestStableState>>,
    }

    #[derive(Default)]
    struct TestStableState {
        generation: u64,
        fence: u64,
        records: StdHashMap<StableKey, Bytes>,
    }

    struct TestStableSession {
        state: Arc<TestMutex<TestStableState>>,
        fence: StableFenceToken,
    }

    #[async_trait]
    impl StableStateStore for TestStableStore {
        async fn open_scope(&self, _scope: StableScope) -> Result<Arc<dyn StableStateSession>, StableStateError> {
            let fence = {
                let mut state = self.state.lock().unwrap();
                state.fence += 1;
                state.fence
            };
            Ok(Arc::new(TestStableSession {
                state: Arc::clone(&self.state),
                fence: StableFenceToken::new(Bytes::copy_from_slice(&fence.to_be_bytes())),
            }))
        }
    }

    #[async_trait]
    impl StableStateSession for TestStableSession {
        fn fence_token(&self) -> StableFenceToken {
            self.fence.clone()
        }

        fn generation(&self) -> u64 {
            self.state.lock().unwrap().generation
        }

        async fn recover(&self) -> Result<StableSnapshot, StableStateError> {
            let state = self.state.lock().unwrap();
            if self.fence.as_bytes() != state.fence.to_be_bytes() {
                return Err(StableStateError::Fenced);
            }
            Ok(StableSnapshot {
                fence_token: self.fence.clone(),
                generation: state.generation,
                records: state
                    .records
                    .iter()
                    .map(|(key, payload)| StableRecord {
                        key: key.clone(),
                        payload: payload.clone(),
                    })
                    .collect(),
            })
        }

        async fn commit(&self, expected_generation: u64, batch: StableBatch) -> Result<u64, StableStateError> {
            let mut state = self.state.lock().unwrap();
            if self.fence.as_bytes() != state.fence.to_be_bytes() {
                return Err(StableStateError::Fenced);
            }
            if state.generation != expected_generation {
                return Err(StableStateError::GenerationConflict {
                    expected: expected_generation,
                    actual: state.generation,
                });
            }
            for mutation in batch.mutations {
                match mutation {
                    StableMutation::Put { key, payload } => {
                        state.records.insert(key, payload);
                    },
                    StableMutation::Delete { key } => {
                        state.records.remove(&key);
                    },
                }
            }
            state.generation += 1;
            Ok(state.generation)
        }
    }

    #[derive(Default)]
    struct TestCoordinator {
        calls: TestMutex<Vec<&'static str>>,
        locations: Nfs4FsLocations,
        fail_commit: bool,
    }

    impl TestCoordinator {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }

        fn with_locations(locations: Nfs4FsLocations) -> Self {
            Self {
                calls: TestMutex::new(Vec::new()),
                locations,
                fail_commit: false,
            }
        }

        fn failing_commit() -> Self {
            Self {
                fail_commit: true,
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl MigrationCoordinator for TestCoordinator {
        fn locations(&self, _export_id: ExportId) -> Nfs4FsLocations {
            self.locations.clone()
        }

        async fn prepare(
            &self,
            export_id: ExportId,
            _destination: Nfs4FsLocation,
        ) -> Result<MigrationFence, MigrationError> {
            self.calls.lock().unwrap().push("prepare");
            Ok(MigrationFence {
                export_id,
                generation: 4,
                token: Bytes::from_static(b"test-migration-fence"),
            })
        }

        async fn commit(&self, _fence: &MigrationFence) -> Result<(), MigrationError> {
            self.calls.lock().unwrap().push("commit");
            if self.fail_commit {
                Err(MigrationError::Unavailable("injected coordinator failure".to_owned()))
            } else {
                Ok(())
            }
        }

        async fn abort(&self, _fence: &MigrationFence) -> Result<(), MigrationError> {
            self.calls.lock().unwrap().push("abort");
            Ok(())
        }
    }

    async fn test_journal(store: Arc<TestStableStore>, scope: &'static [u8]) -> Arc<Mutex<StableJournal>> {
        Arc::new(Mutex::new(
            StableJournal::initialize(store, StableScope::from(scope), 1_700_000_000, StableJournalLimits::default())
                .await
                .unwrap(),
        ))
    }

    struct MigrationTestVfs;

    #[async_trait]
    impl VirtualFileSystem for MigrationTestVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_ONLY
        }

        fn root(&self) -> ObjectKey {
            ObjectKey {
                file_id: 1,
                generation: 1,
            }
        }

        async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            Ok(FileAttributes {
                file_type: FileType::Directory,
                mode: 0o755,
                links: 1,
                uid: 0,
                gid: 0,
                size: 0,
                used: 0,
                device: None,
                fs_id: 1,
                file_id: object.file_id,
                change_id: ChangeId(1),
                access_time: NfsTime::default(),
                modify_time: NfsTime::default(),
                change_time: NfsTime::default(),
            })
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            Err(NfsError::NotFound)
        }
    }

    async fn test_protocol_state(
        journal: Arc<Mutex<StableJournal>>,
    ) -> (Nfs4Runtime, Arc<HashMap<ExportId, Arc<DelegationManager>>>) {
        let (boot, recovered) = {
            let journal = journal.lock().await;
            (journal.boot(), journal.recovery().clone())
        };
        let runtime = Nfs4Runtime::new(RuntimeConfig {
            lease_duration: Duration::from_secs(90),
            grace_duration: Duration::from_secs(90),
            limits: Nfs4Limits::default(),
            boot_tag: boot.boot_tag,
            write_verifier: boot.verifier,
            stable_journal: Some(journal.clone()),
            recovered: Some(recovered.clone()),
        })
        .unwrap();
        let manager = DelegationManager::with_boot_tag_and_stable_state(
            Arc::new(MigrationTestVfs),
            DelegationPolicy::Conservative {
                max_read_delegations: 64,
                max_write_delegations: 64,
                persistent: true,
            },
            Duration::from_secs(90),
            Arc::new(SystemCallbackClock::default()),
            boot.boot_tag,
            Some(journal),
            Some(&recovered),
            Some(ExportId(7)),
        )
        .unwrap();
        (runtime, Arc::new(HashMap::from([(ExportId(7), Arc::new(manager))])))
    }

    async fn test_control(
        coordinator: Arc<TestCoordinator>,
        journal: Arc<Mutex<StableJournal>>,
    ) -> Arc<MigrationControl> {
        let (runtime, delegations) = test_protocol_state(journal.clone()).await;
        MigrationControl::new(
            coordinator,
            journal,
            runtime,
            delegations,
            [export_identity()],
            MigrationBundleLimits::default(),
        )
        .await
        .unwrap()
    }

    async fn confirm_migrating_client(control: &MigrationControl) -> u64 {
        let arguments = SetClientIdArgs {
            client: NfsClientId {
                verifier: [1; 8],
                id: b"owner".to_vec(),
            },
            callback: CallbackClient {
                program: 0x4000_0000,
                location: ClientAddress {
                    netid: b"tcp".to_vec(),
                    address: b"127.0.0.1.8.1".to_vec(),
                },
            },
            callback_identifier: 7,
        };
        let SetClientIdResult::Ok(result) =
            control.runtime.set_client_id(&arguments, &Principal::Anonymous).await.result
        else {
            panic!("SETCLIENTID failed");
        };
        assert_eq!(
            control
                .runtime
                .confirm_client(result.client_id, result.confirmation, &Principal::Anonymous)
                .await
                .result,
            NfsStatus::Ok
        );
        result.client_id
    }

    fn export_identity() -> MigrationExportIdentity {
        MigrationExportIdentity {
            export_id: ExportId(7),
            fsid: FileSystemId::new(3, 5),
            persistent_handles: true,
        }
    }

    fn destination() -> Nfs4FsLocation {
        Nfs4FsLocation {
            servers: vec!["destination.example.test".to_owned()],
            root_path: vec!["exports".to_owned(), "data".to_owned()],
        }
    }

    fn snapshot(export_id: ExportId) -> MigrationStableSnapshot {
        let limits = MigrationBundleLimits::default().journal_limits();
        let previous_client_id = (8u64 << 32) | 9;
        let client = JournalRecord::Client(ClientRecord {
            client_id: previous_client_id,
            owner: Bytes::from_static(b"owner"),
            verifier: [1; 8],
            canonical_principal: Bytes::from_static(b"\0"),
            confirmed: true,
        });
        let client_key = JournalKey::Client {
            client_id: previous_client_id,
        };
        let mut delegation_token = [6; 16];
        delegation_token[..4].copy_from_slice(&1u32.to_be_bytes());
        delegation_token[4..8].copy_from_slice(&(!8u32).to_be_bytes());
        let delegation = JournalRecord::Delegation(DelegationRecord {
            state_token: delegation_token,
            client_id: previous_client_id,
            object: StableObject {
                export_id,
                file_id: 41,
                generation: 3,
            },
            write: false,
            requested_space: 0,
            persistent_object_id: Bytes::from_static(b"object-41"),
        });
        let delegation_key = JournalKey::Delegation {
            state_token: delegation_token,
        };
        MigrationStableSnapshot {
            source_generation: 17,
            server_identity: ServerIdentityRecord { identity: [2; 16] },
            boot: BootRecord {
                verifier: [3; 8],
                boot_tag: 8,
                started_at_unix_seconds: -4,
                clean_shutdown: false,
            },
            handle_key: HandleKeyRecord {
                instance_id: [4; 8],
                secret: [5; 32],
            },
            records: vec![
                crate::nfs4::stable::migration_stable_record_for_test(&client_key, &client, limits),
                crate::nfs4::stable::migration_stable_record_for_test(&delegation_key, &delegation, limits),
            ],
        }
    }

    fn fence(export_id: ExportId) -> MigrationFence {
        MigrationFence {
            export_id,
            generation: 11,
            token: Bytes::from_static(b"coordinator-fence"),
        }
    }

    fn test_bundle(transfer_id: [u8; 16]) -> MigrationBundle {
        let export_id = ExportId(7);
        MigrationBundle::create(
            MigrationId(transfer_id),
            export_id,
            export_identity().fsid,
            90,
            &fence(export_id),
            snapshot(export_id),
            MigrationBundleLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn bundle_round_trip_is_canonical_and_redacts_secret_debug_output() {
        let export_id = ExportId(7);
        let bundle = MigrationBundle::create(
            MigrationId([1; 16]),
            export_id,
            FileSystemId::new(3, 5),
            120,
            &fence(export_id),
            snapshot(export_id),
            MigrationBundleLimits::default(),
        )
        .unwrap();

        let decoded = MigrationBundle::decode(Bytes::copy_from_slice(bundle.as_bytes())).unwrap();

        assert_eq!(decoded, bundle);
        assert_eq!(decoded.id(), MigrationId([1; 16]));
        assert_eq!(decoded.export_id(), export_id);
        assert_eq!(decoded.fsid(), FileSystemId::new(3, 5));
        assert_eq!(decoded.source_lease_seconds(), 120);
        assert_eq!(decoded.record_count(), 2);
        assert!(!format!("{decoded:?}").contains("05050505"));
    }

    #[test]
    fn bundle_rejects_tampering_unknown_versions_and_oversized_input() {
        let export_id = ExportId(7);
        let bundle = MigrationBundle::create(
            MigrationId([1; 16]),
            export_id,
            FileSystemId::new(3, 5),
            90,
            &fence(export_id),
            snapshot(export_id),
            MigrationBundleLimits::default(),
        )
        .unwrap();
        let mut tampered = bundle.as_bytes().to_vec();
        tampered[40] ^= 1;
        assert_eq!(MigrationBundle::decode(Bytes::from(tampered)).unwrap_err(), MigrationBundleError::Checksum);

        let mut wrong_version = bundle.as_bytes().to_vec();
        let unsupported_version = BUNDLE_VERSION + 1;
        wrong_version[8..12].copy_from_slice(&unsupported_version.to_be_bytes());
        let body_length = wrong_version.len() - CHECKSUM_BYTES;
        let checksum: [u8; 32] = Sha256::digest(&wrong_version[..body_length]).into();
        wrong_version[body_length..].copy_from_slice(&checksum);
        assert_eq!(
            MigrationBundle::decode(Bytes::from(wrong_version)).unwrap_err(),
            MigrationBundleError::UnsupportedVersion(unsupported_version)
        );

        let limits = MigrationBundleLimits {
            max_encoded_bytes: bundle.encoded_len() - 1,
            ..MigrationBundleLimits::default()
        };
        assert!(matches!(
            MigrationBundle::decode_with_limits(Bytes::copy_from_slice(bundle.as_bytes()), limits),
            Err(MigrationBundleError::EncodedSize { .. })
        ));
    }

    #[tokio::test]
    async fn migration_gate_waits_for_mutations_and_marks_source_moved() {
        let gate = Arc::new(MigrationGate::default());
        let guard = gate.try_enter_mutation(ExportId(7)).unwrap();
        let waiting = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                gate.quiesce_and_drain(ExportId(7)).await.unwrap();
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(gate.status(ExportId(7)), MigrationGateStatus::Quiescing);
        assert!(gate.try_enter_mutation(ExportId(7)).is_err());
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), waiting).await.unwrap().unwrap();
        gate.mark_moved(ExportId(7));
        assert_eq!(gate.status(ExportId(7)), MigrationGateStatus::Moved);
        gate.resume(ExportId(7));
        assert_eq!(gate.status(ExportId(7)), MigrationGateStatus::Moved);
    }

    #[tokio::test]
    async fn source_prepare_is_idempotent_and_abort_resumes_mutations() {
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store, b"source-control").await;
        let coordinator = Arc::new(TestCoordinator::default());
        let control = test_control(coordinator.clone(), journal).await;

        let bundle = control.prepare(ExportId(7), destination()).await.unwrap();
        let retry = control.prepare(ExportId(7), destination()).await.unwrap();

        assert_eq!(retry, bundle);
        assert_eq!(coordinator.calls(), vec!["prepare"]);
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Quiescing);

        control.abort(bundle.id()).await.unwrap();
        assert_eq!(coordinator.calls(), vec!["prepare", "abort"]);
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Active);
        assert!(control.gate().try_enter_mutation(ExportId(7)).is_ok());
    }

    #[tokio::test]
    async fn coordinator_locations_are_live_and_empty_values_fall_back() {
        let advertised = Nfs4FsLocations {
            fs_root: vec!["exports".to_owned(), "seven".to_owned()],
            locations: vec![Nfs4FsLocation {
                servers: vec!["destination.example.test".to_owned()],
                root_path: vec!["exports".to_owned(), "seven".to_owned()],
            }],
        };
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store, b"coordinator-locations").await;
        let control = test_control(Arc::new(TestCoordinator::with_locations(advertised.clone())), journal).await;

        assert_eq!(control.locations(ExportId(7)), Some(advertised));

        let empty_store = Arc::new(TestStableStore::default());
        let empty_journal = test_journal(empty_store, b"coordinator-locations-empty").await;
        let empty = test_control(Arc::new(TestCoordinator::default()), empty_journal).await;
        assert_eq!(empty.locations(ExportId(7)), None);
    }

    #[tokio::test]
    async fn source_commit_fences_the_export_as_moved() {
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store, b"source-commit").await;
        let coordinator = Arc::new(TestCoordinator::default());
        let control = test_control(coordinator.clone(), journal).await;
        let bundle = control.prepare(ExportId(7), destination()).await.unwrap();

        control.commit(bundle.id()).await.unwrap();

        assert_eq!(coordinator.calls(), vec!["prepare", "commit"]);
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Moved);
        assert!(matches!(control.gate().try_enter_mutation(ExportId(7)), Err(MigrationGateStatus::Moved)));
    }

    #[tokio::test]
    async fn ambiguous_source_commit_is_durably_fenced_across_restart() {
        let scope = b"source-ambiguous-commit";
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store.clone(), scope).await;
        let coordinator = Arc::new(TestCoordinator::failing_commit());
        let control = test_control(coordinator.clone(), journal).await;
        let bundle = control.prepare(ExportId(7), destination()).await.unwrap();

        assert!(matches!(
            control.commit(bundle.id()).await,
            Err(MigrationControlError::Coordinator(MigrationError::Unavailable(_)))
        ));
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Moved);
        // Retrying the external commit remains possible and does not mistake
        // the marker's own journal generation for a protocol-state change.
        assert!(matches!(
            control.commit(bundle.id()).await,
            Err(MigrationControlError::Coordinator(MigrationError::Unavailable(_)))
        ));
        assert_eq!(coordinator.calls(), vec!["prepare", "commit", "commit"]);
        assert_eq!(control.abort(bundle.id()).await.unwrap_err(), MigrationControlError::AlreadyCommitted);
        drop(control);

        let restarted_journal = test_journal(store, scope).await;
        let restarted = test_control(Arc::new(TestCoordinator::default()), restarted_journal).await;
        assert_eq!(restarted.gate().status(ExportId(7)), MigrationGateStatus::Moved);
        assert!(matches!(restarted.gate().try_enter_mutation(ExportId(7)), Err(MigrationGateStatus::Moved)));
    }

    #[tokio::test]
    async fn source_commit_rejects_protocol_state_changed_after_snapshot() {
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store, b"source-generation-change").await;
        let coordinator = Arc::new(TestCoordinator::default());
        let control = test_control(coordinator.clone(), journal).await;
        let bundle = control.prepare(ExportId(7), destination()).await.unwrap();

        control
            .stable
            .lock()
            .await
            .persist_before_ack(PersistBatch::default().put(
                JournalKey::Client { client_id: 91 },
                JournalRecord::Client(ClientRecord {
                    client_id: 91,
                    owner: Bytes::from_static(b"changed-after-snapshot"),
                    verifier: [9; 8],
                    canonical_principal: Bytes::from_static(b"\0"),
                    confirmed: true,
                }),
            ))
            .await
            .unwrap();

        assert_eq!(
            control.commit(bundle.id()).await.unwrap_err(),
            MigrationControlError::SourceStateChanged { export_id: ExportId(7) }
        );
        assert_eq!(coordinator.calls(), vec!["prepare"]);
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Quiescing);
        control.abort(bundle.id()).await.unwrap();
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Active);
    }

    #[tokio::test]
    async fn destination_commit_activates_runtime_delegations_and_persistent_handles() {
        let export_id = ExportId(7);
        let source_snapshot = snapshot(export_id);
        let source_codec =
            HandleCodec::from_key(source_snapshot.handle_key.instance_id, source_snapshot.handle_key.secret);
        let bundle = test_bundle([9; 16]);

        let destination_store = Arc::new(TestStableStore::default());
        let destination_journal = test_journal(destination_store, b"destination-import").await;
        let destination_control = test_control(Arc::new(TestCoordinator::default()), destination_journal).await;
        let current_client_id = confirm_migrating_client(&destination_control).await;
        let id = destination_control.import(bundle.clone()).await.unwrap();
        assert_eq!(destination_control.gate().status(ExportId(7)), MigrationGateStatus::Quiescing);
        assert!(destination_control
            .runtime
            .previous_client_ids(current_client_id, &Principal::Anonymous)
            .await
            .unwrap()
            .is_empty());
        assert!(destination_control
            .delegations
            .get(&export_id)
            .unwrap()
            .recovered_delegations()
            .await
            .is_empty());
        destination_control.commit(id).await.unwrap();
        assert_eq!(destination_control.gate().status(ExportId(7)), MigrationGateStatus::Active);
        assert_eq!(
            destination_control
                .runtime
                .previous_client_ids(current_client_id, &Principal::Anonymous)
                .await
                .unwrap(),
            vec![(8u64 << 32) | 9]
        );
        let recovered_delegations = destination_control
            .delegations
            .get(&export_id)
            .unwrap()
            .recovered_delegations()
            .await;
        assert_eq!(recovered_delegations.len(), 1);
        assert_eq!(recovered_delegations[0].client_id, (8u64 << 32) | 9);

        let retry_id = destination_control.import(bundle).await.unwrap();
        assert_eq!(retry_id, id);
        assert_eq!(destination_control.gate().status(export_id), MigrationGateStatus::Quiescing);
        destination_control.commit(retry_id).await.unwrap();
        assert_eq!(destination_control.gate().status(export_id), MigrationGateStatus::Active);
        assert_eq!(
            destination_control
                .runtime
                .previous_client_ids(current_client_id, &Principal::Anonymous)
                .await
                .unwrap(),
            vec![(8u64 << 32) | 9]
        );
        assert_eq!(
            destination_control
                .delegations
                .get(&export_id)
                .unwrap()
                .recovered_delegations()
                .await
                .len(),
            1
        );
        assert_eq!(destination_control.imported_handles().len_for_export(export_id), 1);

        let object = ObjectKey {
            file_id: 41,
            generation: 3,
        };
        let handle = source_codec.encode_target(HandleTarget::Backend {
            export_id: ExportId(7),
            object,
            namespace_node: None,
        });
        assert_eq!(
            destination_control.imported_handles().decode_any(&handle),
            Some(Ok(HandleTarget::Backend {
                export_id: ExportId(7),
                object,
                namespace_node: None,
            }))
        );
    }

    #[tokio::test]
    async fn destination_import_rejects_collision_before_staging_or_live_activation() {
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store.clone(), b"destination-collision").await;
        let previous_client_id = (8u64 << 32) | 9;
        journal
            .lock()
            .await
            .persist_before_ack(PersistBatch::default().put(
                JournalKey::Client {
                    client_id: previous_client_id,
                },
                JournalRecord::Client(ClientRecord {
                    client_id: previous_client_id,
                    owner: Bytes::from_static(b"conflicting-owner"),
                    verifier: [1; 8],
                    canonical_principal: Bytes::from_static(b"\0"),
                    confirmed: true,
                }),
            ))
            .await
            .unwrap();
        let control = test_control(Arc::new(TestCoordinator::default()), journal).await;

        let error = control.import(test_bundle([10; 16])).await.unwrap_err();

        assert!(matches!(error, MigrationControlError::StableState(_)));
        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Active);
        assert_eq!(control.imported_handles().len_for_export(ExportId(7)), 0);
        assert!(control
            .delegations
            .get(&ExportId(7))
            .unwrap()
            .recovered_delegations()
            .await
            .is_empty());
        assert!(!store
            .state
            .lock()
            .unwrap()
            .records
            .keys()
            .any(|key| key.kind == StableRecordKind::Migration));
    }

    #[tokio::test]
    async fn destination_abort_discards_staged_state_without_touching_live_recovery() {
        let store = Arc::new(TestStableStore::default());
        let journal = test_journal(store.clone(), b"destination-abort").await;
        let control = test_control(Arc::new(TestCoordinator::default()), journal).await;
        let current_client_id = confirm_migrating_client(&control).await;
        let bundle = test_bundle([11; 16]);
        let id = control.import(bundle).await.unwrap();

        assert!(store
            .state
            .lock()
            .unwrap()
            .records
            .keys()
            .any(|key| key.kind == StableRecordKind::Migration));
        assert!(control
            .runtime
            .previous_client_ids(current_client_id, &Principal::Anonymous)
            .await
            .unwrap()
            .is_empty());
        assert!(control
            .delegations
            .get(&ExportId(7))
            .unwrap()
            .recovered_delegations()
            .await
            .is_empty());
        assert_eq!(control.imported_handles().len_for_export(ExportId(7)), 0);

        control.abort(id).await.unwrap();

        assert_eq!(control.gate().status(ExportId(7)), MigrationGateStatus::Active);
        assert!(control
            .runtime
            .previous_client_ids(current_client_id, &Principal::Anonymous)
            .await
            .unwrap()
            .is_empty());
        assert!(control
            .delegations
            .get(&ExportId(7))
            .unwrap()
            .recovered_delegations()
            .await
            .is_empty());
        assert_eq!(control.imported_handles().len_for_export(ExportId(7)), 0);
        assert!(!store
            .state
            .lock()
            .unwrap()
            .records
            .keys()
            .any(|key| key.kind == StableRecordKind::Migration));
        assert_eq!(control.commit(id).await.unwrap_err(), MigrationControlError::UnknownTransaction(id));
    }

    #[test]
    fn imported_handle_registry_keeps_multiple_historical_keys_per_export() {
        let registry = MigrationHandleRegistry::default();
        registry.install(ExportId(7), [1; 16], [2; 16], [3; 8], [4; 32]).unwrap();
        registry.install(ExportId(7), [5; 16], [6; 16], [7; 8], [8; 32]).unwrap();
        assert_eq!(registry.len_for_export(ExportId(7)), 2);

        let source = HandleCodec::from_key([3; 8], [4; 32]);
        let object = ObjectKey {
            file_id: 41,
            generation: 3,
        };
        let migrated = source.encode_target(HandleTarget::Backend {
            export_id: ExportId(7),
            object,
            namespace_node: Some(2),
        });
        assert_eq!(
            registry.decode_any(&migrated),
            Some(Ok(HandleTarget::Backend {
                export_id: ExportId(7),
                object,
                namespace_node: Some(2),
            }))
        );

        let wrong_export = source.encode_target(HandleTarget::Backend {
            export_id: ExportId(8),
            object,
            namespace_node: None,
        });
        assert_eq!(registry.decode_any(&wrong_export), Some(Err(HandleError::WrongExport)));

        let imported_pseudo = source.encode_target(HandleTarget::Pseudo { namespace_node: 9 });
        assert_eq!(registry.decode_any(&imported_pseudo), Some(Err(HandleError::InvalidTarget)));
    }
}
