#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use bytes::Bytes;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::handles::HandleCodec;
use crate::vfs::{
    ExportId, StableBatch, StableFenceToken, StableKey, StableMutation, StableRecord, StableRecordKind, StableScope,
    StableSnapshot, StableStateError, StableStateSession, StableStateStore,
};

const SCHEMA_VERSION: u32 = 4;
const KEY_MAGIC: [u8; 4] = *b"N4K\0";
const RECORD_MAGIC: [u8; 4] = *b"N4R\0";

const TAG_SCHEMA: u8 = 0;
const TAG_SERVER_IDENTITY: u8 = 1;
const TAG_BOOT: u8 = 2;
const TAG_HANDLE_KEY: u8 = 3;
const TAG_CLIENT: u8 = 10;
const TAG_OPEN: u8 = 11;
const TAG_LOCK: u8 = 12;
const TAG_DELEGATION: u8 = 13;
const TAG_REVOCATION: u8 = 14;
const TAG_REPLAY: u8 = 15;
const TAG_MIGRATION: u8 = 16;
const MAX_DELEGATION_OBJECT_ID_BYTES: usize = 1024;
const MAX_OPEN_CONTRIBUTION_VARIANTS: usize = 12;
const ENCODED_OPEN_CONTRIBUTION_BYTES: usize = 12;
const ENCODED_LOCK_RANGE_BYTES: usize = 17;
const MIN_ENCODED_STABLE_RECORD_BYTES: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StableJournalLimits {
    pub max_records: usize,
    pub max_batch_mutations: usize,
    pub max_key_bytes: usize,
    pub max_payload_bytes: usize,
}

impl StableJournalLimits {
    pub const fn production_defaults() -> Self {
        Self {
            max_records: 262_144,
            max_batch_mutations: 4_096,
            max_key_bytes: 4 * 1024,
            max_payload_bytes: 16 * 1024 * 1024,
        }
    }

    fn validate(self) -> Result<Self, StableJournalError> {
        if self.max_records == 0
            || self.max_batch_mutations == 0
            || self.max_key_bytes < 16
            || self.max_payload_bytes < 16
            || self.max_key_bytes > u32::MAX as usize
            || self.max_payload_bytes > u32::MAX as usize
        {
            return Err(StableJournalError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for StableJournalLimits {
    fn default() -> Self {
        Self::production_defaults()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StableObject {
    pub export_id: ExportId,
    pub file_id: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum JournalKey {
    Schema,
    ServerIdentity,
    Boot,
    HandleKey,
    Client {
        client_id: u64,
    },
    Open {
        state_token: [u8; 16],
    },
    Lock {
        state_token: [u8; 16],
    },
    Delegation {
        state_token: [u8; 16],
    },
    Revocation {
        state_token: [u8; 16],
    },
    Replay {
        client_id: u64,
        owner_kind: ReplayOwnerKind,
        owner: Bytes,
    },
    Migration {
        export_id: ExportId,
        transfer_id: [u8; 16],
    },
}

impl JournalKey {
    fn tag(&self) -> u8 {
        match self {
            Self::Schema => TAG_SCHEMA,
            Self::ServerIdentity => TAG_SERVER_IDENTITY,
            Self::Boot => TAG_BOOT,
            Self::HandleKey => TAG_HANDLE_KEY,
            Self::Client { .. } => TAG_CLIENT,
            Self::Open { .. } => TAG_OPEN,
            Self::Lock { .. } => TAG_LOCK,
            Self::Delegation { .. } => TAG_DELEGATION,
            Self::Revocation { .. } => TAG_REVOCATION,
            Self::Replay { .. } => TAG_REPLAY,
            Self::Migration { .. } => TAG_MIGRATION,
        }
    }

    fn storage_kind(&self) -> StableRecordKind {
        match self {
            Self::Schema | Self::ServerIdentity | Self::Boot | Self::HandleKey | Self::Revocation { .. } => {
                StableRecordKind::Server
            },
            Self::Client { .. } | Self::Delegation { .. } => StableRecordKind::Client,
            Self::Open { .. } => StableRecordKind::OpenOwner,
            Self::Lock { .. } => StableRecordKind::LockOwner,
            Self::Replay {
                owner_kind: ReplayOwnerKind::Open,
                ..
            } => StableRecordKind::OpenOwner,
            Self::Replay {
                owner_kind: ReplayOwnerKind::Lock,
                ..
            } => StableRecordKind::LockOwner,
            Self::Migration { .. } => StableRecordKind::Migration,
        }
    }

    fn is_reserved(&self) -> bool {
        matches!(self, Self::Schema | Self::ServerIdentity | Self::Boot | Self::HandleKey | Self::Migration { .. })
    }

    fn encode(&self, limits: StableJournalLimits) -> Result<StableKey, StableJournalError> {
        let mut encoder = BinaryEncoder::new();
        encoder.fixed(&KEY_MAGIC);
        encoder.u32(SCHEMA_VERSION);
        encoder.u8(self.tag());
        match self {
            Self::Schema | Self::ServerIdentity | Self::Boot | Self::HandleKey => {},
            Self::Client { client_id } => encoder.u64(*client_id),
            Self::Open { state_token }
            | Self::Lock { state_token }
            | Self::Delegation { state_token }
            | Self::Revocation { state_token } => encoder.fixed(state_token),
            Self::Replay {
                client_id,
                owner_kind,
                owner,
            } => {
                encoder.u64(*client_id);
                encoder.u8(owner_kind.code());
                encoder.opaque(owner, limits.max_key_bytes)?;
            },
            Self::Migration { export_id, transfer_id } => {
                encoder.u32(export_id.0);
                encoder.fixed(transfer_id);
            },
        }
        let key = encoder.finish();
        if key.len() > limits.max_key_bytes {
            return Err(StableJournalError::LimitExceeded("stable record key"));
        }
        Ok(StableKey {
            kind: self.storage_kind(),
            key,
        })
    }

    fn decode(key: &StableKey, limits: StableJournalLimits) -> Result<Self, StableJournalError> {
        if key.key.len() > limits.max_key_bytes {
            return Err(StableJournalError::LimitExceeded("stable record key"));
        }
        let mut decoder = BinaryDecoder::new(&key.key);
        decoder.expect_fixed(&KEY_MAGIC)?;
        let version = decoder.u32()?;
        if version != SCHEMA_VERSION {
            return Err(StableJournalError::UnsupportedSchema(version));
        }
        let decoded = match decoder.u8()? {
            TAG_SCHEMA => Self::Schema,
            TAG_SERVER_IDENTITY => Self::ServerIdentity,
            TAG_BOOT => Self::Boot,
            TAG_HANDLE_KEY => Self::HandleKey,
            TAG_CLIENT => Self::Client {
                client_id: decoder.u64()?,
            },
            TAG_OPEN => Self::Open {
                state_token: decoder.fixed()?,
            },
            TAG_LOCK => Self::Lock {
                state_token: decoder.fixed()?,
            },
            TAG_DELEGATION => Self::Delegation {
                state_token: decoder.fixed()?,
            },
            TAG_REVOCATION => Self::Revocation {
                state_token: decoder.fixed()?,
            },
            TAG_REPLAY => Self::Replay {
                client_id: decoder.u64()?,
                owner_kind: ReplayOwnerKind::from_code(decoder.u8()?)?,
                owner: decoder.opaque(limits.max_key_bytes)?,
            },
            TAG_MIGRATION => Self::Migration {
                export_id: ExportId(decoder.u32()?),
                transfer_id: decoder.fixed()?,
            },
            tag => return Err(StableJournalError::UnknownRecordTag(tag)),
        };
        decoder.finish()?;
        if key.kind != decoded.storage_kind() {
            return Err(StableJournalError::Corrupt("stable record kind does not match its typed key"));
        }
        Ok(decoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ReplayOwnerKind {
    Open,
    Lock,
}

impl ReplayOwnerKind {
    fn code(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Lock => 1,
        }
    }

    fn from_code(code: u8) -> Result<Self, StableJournalError> {
        match code {
            0 => Ok(Self::Open),
            1 => Ok(Self::Lock),
            _ => Err(StableJournalError::Corrupt("invalid replay-owner kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchemaRecord {
    pub version: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServerIdentityRecord {
    pub identity: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootRecord {
    pub verifier: [u8; 8],
    pub boot_tag: u32,
    pub started_at_unix_seconds: i64,
    pub clean_shutdown: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct HandleKeyRecord {
    pub instance_id: [u8; 8],
    pub secret: [u8; 32],
}

impl std::fmt::Debug for HandleKeyRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandleKeyRecord")
            .field("instance_id", &self.instance_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClientRecord {
    pub client_id: u64,
    pub owner: Bytes,
    pub verifier: [u8; 8],
    pub canonical_principal: Bytes,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpenRecord {
    pub state_token: [u8; 16],
    pub client_id: u64,
    pub owner: Bytes,
    pub object: StableObject,
    pub share_access: u32,
    pub share_deny: u32,
    /// Exact multiplicity of the still-effective OPEN requests whose union is
    /// represented by `share_access` and `share_deny`.
    pub contributions: Vec<OpenContributionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenContributionRecord {
    pub share_access: u32,
    pub share_deny: u32,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockRecord {
    pub state_token: [u8; 16],
    pub open_state_token: [u8; 16],
    pub client_id: u64,
    pub owner: Bytes,
    pub object: StableObject,
    /// Complete normalized range set for this lock owner and file.
    pub ranges: Vec<LockRangeRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LockRangeRecord {
    pub offset: u64,
    /// Zero represents a range extending to end-of-file.
    pub length: u64,
    pub write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DelegationRecord {
    pub state_token: [u8; 16],
    pub client_id: u64,
    pub object: StableObject,
    pub write: bool,
    pub requested_space: u64,
    pub persistent_object_id: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevocationReason {
    LeaseExpired,
    Administration,
    Conflict,
    Migration,
}

impl RevocationReason {
    fn code(self) -> u8 {
        match self {
            Self::LeaseExpired => 0,
            Self::Administration => 1,
            Self::Conflict => 2,
            Self::Migration => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, StableJournalError> {
        match code {
            0 => Ok(Self::LeaseExpired),
            1 => Ok(Self::Administration),
            2 => Ok(Self::Conflict),
            3 => Ok(Self::Migration),
            _ => Err(StableJournalError::Corrupt("invalid revocation reason")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevocationRecord {
    pub state_token: [u8; 16],
    pub client_id: u64,
    pub reason: RevocationReason,
    pub revoked_at_unix_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayRecord {
    pub client_id: u64,
    pub owner_kind: ReplayOwnerKind,
    pub owner: Bytes,
    pub sequence_id: u32,
    pub request_digest: [u8; 32],
    pub reply: Bytes,
    pub current_object: Option<StableObject>,
    /// The authenticated source that must be used when an exact replay is
    /// recovered after a restart or migration.  The explicit tag keeps the
    /// bounded wire codec forward-auditable instead of treating `0` as a
    /// magic client id.
    pub renewal_source: ReplayRenewalSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayRenewalSource {
    None,
    StateId { client_id: u64 },
}

impl ReplayRenewalSource {
    fn encode(self, encoder: &mut BinaryEncoder) {
        match self {
            Self::None => encoder.u8(0),
            Self::StateId { client_id } => {
                encoder.u8(1);
                encoder.u64(client_id);
            },
        }
    }

    fn decode(decoder: &mut BinaryDecoder<'_>) -> Result<Self, StableJournalError> {
        match decoder.u8()? {
            0 => Ok(Self::None),
            1 => Ok(Self::StateId {
                client_id: decoder.u64()?,
            }),
            _ => Err(StableJournalError::Corrupt("invalid replay renewal source")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationPhase {
    Staged,
    Committed,
    /// The source durably armed cutover and must remain fenced after restart.
    SourceMoved,
}

impl MigrationPhase {
    fn code(self) -> u8 {
        match self {
            Self::Staged => 0,
            Self::Committed => 1,
            Self::SourceMoved => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, StableJournalError> {
        match code {
            0 => Ok(Self::Staged),
            1 => Ok(Self::Committed),
            2 => Ok(Self::SourceMoved),
            _ => Err(StableJournalError::Corrupt("invalid migration phase")),
        }
    }
}

/// Canonical stable state carried by a migration bundle. The record payloads
/// contain protocol metadata only; file data remains application-owned.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MigrationStableSnapshot {
    pub source_generation: u64,
    pub server_identity: ServerIdentityRecord,
    pub boot: BootRecord,
    pub handle_key: HandleKeyRecord,
    pub records: Vec<StableRecord>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MigrationCapsuleRecord {
    pub transfer_id: [u8; 16],
    pub export_id: ExportId,
    pub fsid_major: u64,
    pub fsid_minor: u64,
    pub source_generation: u64,
    pub coordinator_generation: u64,
    pub coordinator_token_digest: [u8; 32],
    pub bundle_digest: [u8; 32],
    pub server_identity: ServerIdentityRecord,
    pub boot: BootRecord,
    pub handle_key: HandleKeyRecord,
    pub phase: MigrationPhase,
    pub records: Vec<StableRecord>,
}

#[derive(Clone)]
pub(crate) struct ImportedHandleKey {
    pub export_id: ExportId,
    pub transfer_id: [u8; 16],
    pub server_identity: [u8; 16],
    pub handle_key: HandleKeyRecord,
}

#[derive(Clone)]
pub(crate) struct CommittedMigration {
    pub export_id: ExportId,
    pub transfer_id: [u8; 16],
    pub server_identity: [u8; 16],
    pub boot: BootRecord,
    pub handle_key: HandleKeyRecord,
    pub records: Vec<(JournalKey, JournalRecord)>,
}

impl std::fmt::Debug for MigrationStableSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MigrationStableSnapshot")
            .field("source_generation", &self.source_generation)
            .field("server_identity", &self.server_identity)
            .field("boot", &self.boot)
            .field("handle_instance_id", &self.handle_key.instance_id)
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MigrationCapsuleRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MigrationCapsuleRecord")
            .field("transfer_id", &self.transfer_id)
            .field("export_id", &self.export_id)
            .field("fsid_major", &self.fsid_major)
            .field("fsid_minor", &self.fsid_minor)
            .field("source_generation", &self.source_generation)
            .field("coordinator_generation", &self.coordinator_generation)
            .field("server_identity", &self.server_identity)
            .field("boot", &self.boot)
            .field("handle_instance_id", &self.handle_key.instance_id)
            .field("phase", &self.phase)
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ImportedHandleKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedHandleKey")
            .field("export_id", &self.export_id)
            .field("transfer_id", &self.transfer_id)
            .field("server_identity", &self.server_identity)
            .field("handle_instance_id", &self.handle_key.instance_id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CommittedMigration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommittedMigration")
            .field("export_id", &self.export_id)
            .field("transfer_id", &self.transfer_id)
            .field("server_identity", &self.server_identity)
            .field("boot", &self.boot)
            .field("handle_instance_id", &self.handle_key.instance_id)
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationStageStatus {
    Staged,
    AlreadyStaged,
    AlreadyCommitted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalRecord {
    Schema(SchemaRecord),
    ServerIdentity(ServerIdentityRecord),
    Boot(BootRecord),
    HandleKey(HandleKeyRecord),
    Client(ClientRecord),
    Open(OpenRecord),
    Lock(LockRecord),
    Delegation(DelegationRecord),
    Revocation(RevocationRecord),
    Replay(ReplayRecord),
    Migration(MigrationCapsuleRecord),
}

impl JournalRecord {
    fn tag(&self) -> u8 {
        match self {
            Self::Schema(_) => TAG_SCHEMA,
            Self::ServerIdentity(_) => TAG_SERVER_IDENTITY,
            Self::Boot(_) => TAG_BOOT,
            Self::HandleKey(_) => TAG_HANDLE_KEY,
            Self::Client(_) => TAG_CLIENT,
            Self::Open(_) => TAG_OPEN,
            Self::Lock(_) => TAG_LOCK,
            Self::Delegation(_) => TAG_DELEGATION,
            Self::Revocation(_) => TAG_REVOCATION,
            Self::Replay(_) => TAG_REPLAY,
            Self::Migration(_) => TAG_MIGRATION,
        }
    }

    fn encode(&self, limits: StableJournalLimits) -> Result<Bytes, StableJournalError> {
        let mut encoder = BinaryEncoder::new();
        encoder.fixed(&RECORD_MAGIC);
        encoder.u32(SCHEMA_VERSION);
        encoder.u8(self.tag());
        match self {
            Self::Schema(record) => encoder.u32(record.version),
            Self::ServerIdentity(record) => encoder.fixed(&record.identity),
            Self::Boot(record) => {
                encoder.fixed(&record.verifier);
                encoder.u32(record.boot_tag);
                encoder.i64(record.started_at_unix_seconds);
                encoder.boolean(record.clean_shutdown);
            },
            Self::HandleKey(record) => {
                encoder.fixed(&record.instance_id);
                encoder.fixed(&record.secret);
            },
            Self::Client(record) => {
                encoder.u64(record.client_id);
                encoder.opaque(&record.owner, limits.max_payload_bytes)?;
                encoder.fixed(&record.verifier);
                encoder.opaque(&record.canonical_principal, limits.max_payload_bytes)?;
                encoder.boolean(record.confirmed);
            },
            Self::Open(record) => {
                validate_open_record(record)?;
                encoder.fixed(&record.state_token);
                encoder.u64(record.client_id);
                encoder.opaque(&record.owner, limits.max_payload_bytes)?;
                encoder.object(record.object);
                encoder.u32(record.share_access);
                encoder.u32(record.share_deny);
                encoder.u32(
                    u32::try_from(record.contributions.len())
                        .map_err(|_| StableJournalError::LimitExceeded("stable OPEN contribution variants"))?,
                );
                for contribution in &record.contributions {
                    encoder.u32(contribution.share_access);
                    encoder.u32(contribution.share_deny);
                    encoder.u32(contribution.count);
                }
            },
            Self::Lock(record) => {
                encoder.fixed(&record.state_token);
                encoder.fixed(&record.open_state_token);
                encoder.u64(record.client_id);
                encoder.opaque(&record.owner, limits.max_payload_bytes)?;
                encoder.object(record.object);
                if record.ranges.len() > stable_lock_range_limit(limits) {
                    return Err(StableJournalError::LimitExceeded("stable lock range count"));
                }
                encoder.u32(
                    u32::try_from(record.ranges.len())
                        .map_err(|_| StableJournalError::LimitExceeded("stable lock range count"))?,
                );
                for range in &record.ranges {
                    encoder.u64(range.offset);
                    encoder.u64(range.length);
                    encoder.boolean(range.write);
                }
            },
            Self::Delegation(record) => {
                encoder.fixed(&record.state_token);
                encoder.u64(record.client_id);
                encoder.object(record.object);
                encoder.boolean(record.write);
                encoder.u64(record.requested_space);
                encoder.opaque(&record.persistent_object_id, MAX_DELEGATION_OBJECT_ID_BYTES)?;
            },
            Self::Revocation(record) => {
                encoder.fixed(&record.state_token);
                encoder.u64(record.client_id);
                encoder.u8(record.reason.code());
                encoder.i64(record.revoked_at_unix_seconds);
            },
            Self::Replay(record) => {
                encoder.u64(record.client_id);
                encoder.u8(record.owner_kind.code());
                encoder.opaque(&record.owner, limits.max_payload_bytes)?;
                encoder.u32(record.sequence_id);
                encoder.fixed(&record.request_digest);
                encoder.opaque(&record.reply, limits.max_payload_bytes)?;
                encoder.option_object(record.current_object);
                record.renewal_source.encode(&mut encoder);
            },
            Self::Migration(record) => {
                encoder.fixed(&record.transfer_id);
                encoder.u32(record.export_id.0);
                encoder.u64(record.fsid_major);
                encoder.u64(record.fsid_minor);
                encoder.u64(record.source_generation);
                encoder.u64(record.coordinator_generation);
                encoder.fixed(&record.coordinator_token_digest);
                encoder.fixed(&record.bundle_digest);
                encoder.fixed(&record.server_identity.identity);
                encode_boot(&mut encoder, record.boot);
                encoder.fixed(&record.handle_key.instance_id);
                encoder.fixed(&record.handle_key.secret);
                encoder.u8(record.phase.code());
                encoder.u32(
                    u32::try_from(record.records.len())
                        .map_err(|_| StableJournalError::LimitExceeded("migration record count"))?,
                );
                for stable_record in &record.records {
                    encode_stable_record(&mut encoder, stable_record, limits)?;
                }
            },
        }
        let payload = encoder.finish();
        if payload.len() > limits.max_payload_bytes {
            return Err(StableJournalError::LimitExceeded("stable record payload"));
        }
        Ok(payload)
    }

    fn decode(payload: &Bytes, limits: StableJournalLimits) -> Result<Self, StableJournalError> {
        if payload.len() > limits.max_payload_bytes {
            return Err(StableJournalError::LimitExceeded("stable record payload"));
        }
        let mut decoder = BinaryDecoder::new(payload);
        decoder.expect_fixed(&RECORD_MAGIC)?;
        let version = decoder.u32()?;
        if version != SCHEMA_VERSION {
            return Err(StableJournalError::UnsupportedSchema(version));
        }
        let record = match decoder.u8()? {
            TAG_SCHEMA => Self::Schema(SchemaRecord {
                version: decoder.u32()?,
            }),
            TAG_SERVER_IDENTITY => Self::ServerIdentity(ServerIdentityRecord {
                identity: decoder.fixed()?,
            }),
            TAG_BOOT => Self::Boot(BootRecord {
                verifier: decoder.fixed()?,
                boot_tag: decoder.u32()?,
                started_at_unix_seconds: decoder.i64()?,
                clean_shutdown: decoder.boolean()?,
            }),
            TAG_HANDLE_KEY => Self::HandleKey(HandleKeyRecord {
                instance_id: decoder.fixed()?,
                secret: decoder.fixed()?,
            }),
            TAG_CLIENT => Self::Client(ClientRecord {
                client_id: decoder.u64()?,
                owner: decoder.opaque(limits.max_payload_bytes)?,
                verifier: decoder.fixed()?,
                canonical_principal: decoder.opaque(limits.max_payload_bytes)?,
                confirmed: decoder.boolean()?,
            }),
            TAG_OPEN => {
                let state_token = decoder.fixed()?;
                let client_id = decoder.u64()?;
                let owner = decoder.opaque(limits.max_payload_bytes)?;
                let object = decoder.object()?;
                let share_access = decoder.u32()?;
                let share_deny = decoder.u32()?;
                let count = usize::try_from(decoder.u32()?)
                    .map_err(|_| StableJournalError::Corrupt("stable OPEN contribution count overflow"))?;
                if count == 0 || count > MAX_OPEN_CONTRIBUTION_VARIANTS {
                    return Err(StableJournalError::LimitExceeded("stable OPEN contribution variants"));
                }
                if count > decoder.remaining() / ENCODED_OPEN_CONTRIBUTION_BYTES {
                    return Err(StableJournalError::Corrupt("truncated stable OPEN contributions"));
                }
                let mut contributions = Vec::with_capacity(count);
                for _ in 0..count {
                    contributions.push(OpenContributionRecord {
                        share_access: decoder.u32()?,
                        share_deny: decoder.u32()?,
                        count: decoder.u32()?,
                    });
                }
                let record = OpenRecord {
                    state_token,
                    client_id,
                    owner,
                    object,
                    share_access,
                    share_deny,
                    contributions,
                };
                validate_open_record(&record)?;
                Self::Open(record)
            },
            TAG_LOCK => Self::Lock(LockRecord {
                state_token: decoder.fixed()?,
                open_state_token: decoder.fixed()?,
                client_id: decoder.u64()?,
                owner: decoder.opaque(limits.max_payload_bytes)?,
                object: decoder.object()?,
                ranges: {
                    let count = usize::try_from(decoder.u32()?)
                        .map_err(|_| StableJournalError::Corrupt("stable lock range count overflow"))?;
                    if count > stable_lock_range_limit(limits) {
                        return Err(StableJournalError::LimitExceeded("stable lock range count"));
                    }
                    if count > decoder.remaining() / ENCODED_LOCK_RANGE_BYTES {
                        return Err(StableJournalError::Corrupt("truncated stable lock range set"));
                    }
                    let mut ranges = Vec::with_capacity(count);
                    for _ in 0..count {
                        ranges.push(LockRangeRecord {
                            offset: decoder.u64()?,
                            length: decoder.u64()?,
                            write: decoder.boolean()?,
                        });
                    }
                    ranges
                },
            }),
            TAG_DELEGATION => Self::Delegation(DelegationRecord {
                state_token: decoder.fixed()?,
                client_id: decoder.u64()?,
                object: decoder.object()?,
                write: decoder.boolean()?,
                requested_space: decoder.u64()?,
                persistent_object_id: decoder.opaque(MAX_DELEGATION_OBJECT_ID_BYTES)?,
            }),
            TAG_REVOCATION => Self::Revocation(RevocationRecord {
                state_token: decoder.fixed()?,
                client_id: decoder.u64()?,
                reason: RevocationReason::from_code(decoder.u8()?)?,
                revoked_at_unix_seconds: decoder.i64()?,
            }),
            TAG_REPLAY => Self::Replay(ReplayRecord {
                client_id: decoder.u64()?,
                owner_kind: ReplayOwnerKind::from_code(decoder.u8()?)?,
                owner: decoder.opaque(limits.max_payload_bytes)?,
                sequence_id: decoder.u32()?,
                request_digest: decoder.fixed()?,
                reply: decoder.opaque(limits.max_payload_bytes)?,
                current_object: decoder.option_object()?,
                renewal_source: ReplayRenewalSource::decode(&mut decoder)?,
            }),
            TAG_MIGRATION => {
                let transfer_id = decoder.fixed()?;
                let export_id = ExportId(decoder.u32()?);
                let fsid_major = decoder.u64()?;
                let fsid_minor = decoder.u64()?;
                let source_generation = decoder.u64()?;
                let coordinator_generation = decoder.u64()?;
                let coordinator_token_digest = decoder.fixed()?;
                let bundle_digest = decoder.fixed()?;
                let server_identity = ServerIdentityRecord {
                    identity: decoder.fixed()?,
                };
                let boot = decode_boot(&mut decoder)?;
                let handle_key = HandleKeyRecord {
                    instance_id: decoder.fixed()?,
                    secret: decoder.fixed()?,
                };
                let phase = MigrationPhase::from_code(decoder.u8()?)?;
                let count = usize::try_from(decoder.u32()?)
                    .map_err(|_| StableJournalError::Corrupt("migration record count overflow"))?;
                // Legacy schema-v3 capsules can contain revocation records
                // which no longer count toward an import. Bound the raw count
                // by the enclosing payload before decoding it; the sanitized
                // active-record count is enforced by migration validation.
                if count > decoder.remaining() / MIN_ENCODED_STABLE_RECORD_BYTES {
                    return Err(StableJournalError::Corrupt("truncated migration record set"));
                }
                let mut records = Vec::with_capacity(count.min(limits.max_records));
                for _ in 0..count {
                    records.push(decode_stable_record(&mut decoder, limits)?);
                }
                Self::Migration(sanitize_migration_capsule(
                    MigrationCapsuleRecord {
                        transfer_id,
                        export_id,
                        fsid_major,
                        fsid_minor,
                        source_generation,
                        coordinator_generation,
                        coordinator_token_digest,
                        bundle_digest,
                        server_identity,
                        boot,
                        handle_key,
                        phase,
                        records,
                    },
                    limits,
                )?)
            },
            tag => return Err(StableJournalError::UnknownRecordTag(tag)),
        };
        decoder.finish()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), StableJournalError> {
        match self {
            Self::Schema(record) if record.version != SCHEMA_VERSION => {
                Err(StableJournalError::UnsupportedSchema(record.version))
            },
            Self::Boot(record) if record.boot_tag == 0 || record.boot_tag == u32::MAX => {
                Err(StableJournalError::Corrupt("invalid stable boot tag"))
            },
            Self::Client(record) if record.owner.is_empty() || record.canonical_principal.is_empty() => {
                Err(StableJournalError::Corrupt("empty stable client identity"))
            },
            Self::Open(record) => validate_open_record(record),
            Self::Lock(record) if record.owner.is_empty() || !valid_stable_lock_ranges(&record.ranges) => {
                Err(StableJournalError::Corrupt("invalid stable lock record"))
            },
            Self::Delegation(record)
                if record.state_token[..4] == [0; 4]
                    || record.state_token[4..] == [0; 12]
                    || record.persistent_object_id.is_empty()
                    || record.persistent_object_id.len() > MAX_DELEGATION_OBJECT_ID_BYTES =>
            {
                Err(StableJournalError::Corrupt("invalid stable delegation record"))
            },
            Self::Replay(record)
                if record.owner.is_empty()
                    || matches!(record.renewal_source, ReplayRenewalSource::StateId { client_id } if client_id != record.client_id) =>
            {
                Err(StableJournalError::Corrupt("invalid stable replay record"))
            },
            Self::Migration(record)
                if record.transfer_id == [0; 16]
                    || record.server_identity.identity == [0; 16]
                    || record.handle_key.instance_id == [0; 8]
                    || record.handle_key.secret == [0; 32] =>
            {
                Err(StableJournalError::Corrupt("invalid migration identity"))
            },
            _ => Ok(()),
        }
    }
}

fn validate_open_record(record: &OpenRecord) -> Result<(), StableJournalError> {
    if record.owner.is_empty()
        || !(1..=3).contains(&record.share_access)
        || record.share_deny > 3
        || record.contributions.is_empty()
        || record.contributions.len() > MAX_OPEN_CONTRIBUTION_VARIANTS
    {
        return Err(StableJournalError::Corrupt("invalid stable open record"));
    }
    let mut seen = [[false; 4]; 3];
    let mut union_access = 0u32;
    let mut union_deny = 0u32;
    for contribution in &record.contributions {
        if !(1..=3).contains(&contribution.share_access) || contribution.share_deny > 3 || contribution.count == 0 {
            return Err(StableJournalError::Corrupt("invalid stable OPEN contribution"));
        }
        let access_index = usize::try_from(contribution.share_access - 1)
            .map_err(|_| StableJournalError::Corrupt("stable OPEN access overflow"))?;
        let deny_index = usize::try_from(contribution.share_deny)
            .map_err(|_| StableJournalError::Corrupt("stable OPEN deny overflow"))?;
        if std::mem::replace(&mut seen[access_index][deny_index], true) {
            return Err(StableJournalError::Corrupt("duplicate stable OPEN contribution"));
        }
        union_access |= contribution.share_access;
        union_deny |= contribution.share_deny;
    }
    if union_access != record.share_access || union_deny != record.share_deny {
        return Err(StableJournalError::Corrupt(
            "stable OPEN contributions do not match the aggregate share reservation",
        ));
    }
    Ok(())
}

fn stable_lock_range_limit(limits: StableJournalLimits) -> usize {
    limits.max_payload_bytes / ENCODED_LOCK_RANGE_BYTES
}

fn valid_stable_lock_ranges(ranges: &[LockRangeRecord]) -> bool {
    if ranges.is_empty() {
        return false;
    }
    let mut previous: Option<(Option<u64>, bool)> = None;
    for range in ranges {
        let end = if range.length == 0 {
            None
        } else {
            let Some(end) = range.offset.checked_add(range.length) else {
                return false;
            };
            Some(end)
        };
        if let Some((previous_end, previous_write)) = previous {
            let Some(previous_end) = previous_end else {
                return false;
            };
            if previous_end > range.offset || (previous_end == range.offset && previous_write == range.write) {
                return false;
            }
        }
        previous = Some((end, range.write));
    }
    true
}

fn validate_key_record(key: &JournalKey, record: &JournalRecord) -> Result<(), StableJournalError> {
    let matches = match (key, record) {
        (JournalKey::Schema, JournalRecord::Schema(_))
        | (JournalKey::ServerIdentity, JournalRecord::ServerIdentity(_))
        | (JournalKey::Boot, JournalRecord::Boot(_))
        | (JournalKey::HandleKey, JournalRecord::HandleKey(_)) => true,
        (JournalKey::Client { client_id }, JournalRecord::Client(record)) => *client_id == record.client_id,
        (JournalKey::Open { state_token }, JournalRecord::Open(record)) => *state_token == record.state_token,
        (JournalKey::Lock { state_token }, JournalRecord::Lock(record)) => *state_token == record.state_token,
        (JournalKey::Delegation { state_token }, JournalRecord::Delegation(record)) => {
            *state_token == record.state_token
        },
        (JournalKey::Revocation { state_token }, JournalRecord::Revocation(record)) => {
            *state_token == record.state_token
        },
        (
            JournalKey::Replay {
                client_id,
                owner_kind,
                owner,
            },
            JournalRecord::Replay(record),
        ) => *client_id == record.client_id && *owner_kind == record.owner_kind && *owner == record.owner,
        (JournalKey::Migration { export_id, transfer_id }, JournalRecord::Migration(record)) => {
            *export_id == record.export_id && *transfer_id == record.transfer_id
        },
        _ => false,
    };
    if !matches || key.tag() != record.tag() {
        return Err(StableJournalError::Corrupt("stable record payload does not match its typed key"));
    }
    record.validate()
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum JournalMutation {
    Put { key: JournalKey, record: JournalRecord },
    Delete { key: JournalKey },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PersistBatch {
    mutations: Vec<JournalMutation>,
}

impl PersistBatch {
    pub fn new(mutations: Vec<JournalMutation>) -> Self {
        Self { mutations }
    }

    pub fn put(mut self, key: JournalKey, record: JournalRecord) -> Self {
        self.mutations.push(JournalMutation::Put { key, record });
        self
    }

    pub fn delete(mut self, key: JournalKey) -> Self {
        self.mutations.push(JournalMutation::Delete { key });
        self
    }

    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Persisted {
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreviousShutdown {
    FirstBoot,
    Clean,
    Unclean,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveredStableState {
    pub previous_shutdown: PreviousShutdown,
    pub previous_boot: Option<BootRecord>,
    pub records: Vec<(JournalKey, JournalRecord)>,
}

fn legacy_revocation_tokens<'a>(records: impl Iterator<Item = &'a JournalRecord>) -> HashSet<[u8; 16]> {
    records
        .filter_map(|record| match record {
            JournalRecord::Revocation(revocation) => Some(revocation.state_token),
            _ => None,
        })
        .collect()
}

fn confirmed_client_ids<'a>(records: impl Iterator<Item = &'a JournalRecord>) -> HashSet<u64> {
    records
        .filter_map(|record| match record {
            JournalRecord::Client(client) if client.confirmed => Some(client.client_id),
            _ => None,
        })
        .collect()
}

fn legacy_record_is_suppressed(
    record: &JournalRecord,
    revoked_tokens: &HashSet<[u8; 16]>,
    confirmed_clients: &HashSet<u64>,
) -> bool {
    match record {
        JournalRecord::Revocation(_) => true,
        JournalRecord::Delegation(delegation) => {
            revoked_tokens.contains(&delegation.state_token) || !confirmed_clients.contains(&delegation.client_id)
        },
        _ => false,
    }
}

fn sanitize_typed_records(
    records: Vec<(JournalKey, JournalRecord)>,
) -> (Vec<(JournalKey, JournalRecord)>, Vec<JournalKey>) {
    let revoked_tokens = legacy_revocation_tokens(records.iter().map(|(_, record)| record));
    let confirmed_clients = confirmed_client_ids(records.iter().map(|(_, record)| record));
    let mut retained = Vec::with_capacity(records.len());
    let mut removed = Vec::new();
    for (key, record) in records {
        if legacy_record_is_suppressed(&record, &revoked_tokens, &confirmed_clients) {
            removed.push(key);
        } else {
            retained.push((key, record));
        }
    }
    (retained, removed)
}

struct SanitizedTransferRecords {
    stable: Vec<StableRecord>,
    typed: Vec<(JournalKey, JournalRecord)>,
}

fn sanitize_transfer_records(
    records: &[StableRecord],
    limits: StableJournalLimits,
) -> Result<SanitizedTransferRecords, StableJournalError> {
    let mut seen = HashSet::with_capacity(records.len());
    let mut typed = Vec::with_capacity(records.len().min(limits.max_records));
    for record in records {
        if !seen.insert(record.key.clone()) {
            return Err(StableJournalError::Corrupt("duplicate migrated stable key"));
        }
        typed.push(validate_transfer_record(record, limits)?);
    }

    let revoked_tokens = legacy_revocation_tokens(typed.iter().map(|(_, record)| record));
    let confirmed_clients = confirmed_client_ids(typed.iter().map(|(_, record)| record));
    let mut stable = Vec::with_capacity(typed.len());
    let mut retained_typed = Vec::with_capacity(typed.len());
    for (stable_record, typed_record) in records.iter().zip(typed) {
        if !legacy_record_is_suppressed(&typed_record.1, &revoked_tokens, &confirmed_clients) {
            stable.push(stable_record.clone());
            retained_typed.push(typed_record);
        }
    }
    if stable.len() > limits.max_records {
        return Err(StableJournalError::LimitExceeded("migration record count"));
    }
    Ok(SanitizedTransferRecords {
        stable,
        typed: retained_typed,
    })
}

/// Builds the recovery image represented by a validated, staged migration
/// capsule without making any of its records durable or visible.
///
/// Migration is a live handoff rather than a clean server restart, so the
/// source boot is deliberately treated as an unclean previous boot. This
/// admits the transferred clients to a bounded destination grace period once
/// migration control activates the prepared image.
pub(crate) fn recovery_from_migration_capsule(
    capsule: &MigrationCapsuleRecord,
    limits: StableJournalLimits,
) -> Result<RecoveredStableState, StableJournalError> {
    validate_migration_capsule(capsule, limits)?;
    Ok(RecoveredStableState {
        previous_shutdown: PreviousShutdown::Unclean,
        previous_boot: Some(capsule.boot),
        records: decode_transfer_records(&capsule.records, limits)?,
    })
}

type LiveRecordUpdates = HashMap<StableKey, Option<Bytes>>;

fn plan_live_record_updates(
    live_records: &HashMap<StableKey, Bytes>,
    mutations: &[StableMutation],
    max_records: usize,
) -> Result<LiveRecordUpdates, StableJournalError> {
    let mut projected_count = live_records.len();
    let mut updates = HashMap::with_capacity(mutations.len());
    for mutation in mutations {
        let (key, next_payload) = match mutation {
            StableMutation::Put { key, payload } => (key, Some(payload.clone())),
            StableMutation::Delete { key } => (key, None),
        };
        let next_present = next_payload.is_some();
        let current_present = updates
            .get(key)
            .map(Option::is_some)
            .unwrap_or_else(|| live_records.contains_key(key));
        if current_present != next_present {
            projected_count = if next_present {
                projected_count
                    .checked_add(1)
                    .ok_or(StableJournalError::LimitExceeded("stable record count"))?
            } else {
                projected_count.saturating_sub(1)
            };
        }
        updates.insert(key.clone(), next_payload);
    }
    if projected_count > max_records {
        return Err(StableJournalError::LimitExceeded("stable record count"));
    }
    Ok(updates)
}

fn apply_live_record_updates(live_records: &mut HashMap<StableKey, Bytes>, updates: &LiveRecordUpdates) {
    for (key, payload) in updates {
        if let Some(payload) = payload {
            live_records.insert(key.clone(), payload.clone());
        } else {
            live_records.remove(key);
        }
    }
}

async fn resolve_commit_result(
    session: &Arc<dyn StableStateSession>,
    fence_token: &StableFenceToken,
    expected_generation: u64,
    live_records: &HashMap<StableKey, Bytes>,
    updates: &LiveRecordUpdates,
    limits: StableJournalLimits,
    result: Result<u64, StableStateError>,
) -> Result<u64, StableJournalError> {
    match result {
        Ok(generation) => {
            if generation == expected_generation {
                return Err(StableJournalError::Corrupt("stable commit did not advance its generation"));
            }
            Ok(generation)
        },
        Err(commit_error) => {
            if session.fence_token() != *fence_token {
                return Err(StableJournalError::Fenced);
            }
            let snapshot = session.recover().await.map_err(StableJournalError::from)?;
            if snapshot.fence_token != *fence_token {
                return Err(StableJournalError::Fenced);
            }
            if snapshot.records.len() > limits.max_records {
                return Err(StableJournalError::LimitExceeded("stable record count"));
            }
            for record in &snapshot.records {
                if record.key.key.len() > limits.max_key_bytes {
                    return Err(StableJournalError::LimitExceeded("stable record key"));
                }
                if record.payload.len() > limits.max_payload_bytes {
                    return Err(StableJournalError::LimitExceeded("stable record payload"));
                }
            }
            let recovered_records = stable_record_map(&snapshot)?;

            if snapshot.generation == expected_generation {
                // The session contract makes generation equality definitive:
                // no commit changed the durable image.
                if recovered_records != *live_records {
                    return Err(StableJournalError::Corrupt(
                        "stable records changed without advancing their generation",
                    ));
                }
                return Err(StableJournalError::from(commit_error));
            }

            let mut expected_records = live_records.clone();
            apply_live_record_updates(&mut expected_records, updates);
            // Fencing rules out a second writer. Still compare the complete
            // image so an unrelated or partial mutation is never mistaken for
            // this batch merely because its touched keys have the right value.
            if recovered_records == expected_records {
                Ok(snapshot.generation)
            } else {
                Err(StableJournalError::CasConflict {
                    expected: expected_generation,
                    actual: snapshot.generation,
                })
            }
        },
    }
}

pub(crate) struct StableJournal {
    session: Arc<dyn StableStateSession>,
    fence_token: StableFenceToken,
    generation: u64,
    limits: StableJournalLimits,
    live_records: HashMap<StableKey, Bytes>,
    server_identity: ServerIdentityRecord,
    boot: BootRecord,
    handle_key: HandleKeyRecord,
    recovery: RecoveredStableState,
    migrations: BTreeMap<[u8; 16], MigrationCapsuleRecord>,
}

impl StableJournal {
    pub async fn initialize(
        store: Arc<dyn StableStateStore>,
        scope: StableScope,
        started_at_unix_seconds: i64,
        limits: StableJournalLimits,
    ) -> Result<Self, StableJournalError> {
        let limits = limits.validate()?;
        let session = store.open_scope(scope).await.map_err(StableJournalError::from)?;
        let snapshot = session.recover().await.map_err(StableJournalError::from)?;
        let fence_token = session.fence_token();
        if snapshot.fence_token != fence_token {
            return Err(StableJournalError::Fenced);
        }
        if snapshot.records.len() > limits.max_records {
            return Err(StableJournalError::LimitExceeded("stable record count"));
        }

        let decoded = decode_snapshot(&snapshot, limits)?;
        let DecodedSnapshot {
            schema,
            server_identity: decoded_server_identity,
            boot: decoded_boot,
            handle_key: decoded_handle_key,
            records: decoded_records,
            migrations,
            legacy_cleanup_keys,
        } = decoded;
        let is_new = snapshot.records.is_empty();
        let (server_identity, handle_key, previous_boot, records) = if is_new {
            (
                ServerIdentityRecord {
                    identity: random_array()?,
                },
                HandleKeyRecord {
                    instance_id: random_array()?,
                    secret: random_array()?,
                },
                None,
                Vec::new(),
            )
        } else {
            let schema =
                schema.ok_or(StableJournalError::Corrupt("initialized stable state is missing its schema record"))?;
            if schema.version != SCHEMA_VERSION {
                return Err(StableJournalError::UnsupportedSchema(schema.version));
            }
            (
                decoded_server_identity
                    .ok_or(StableJournalError::Corrupt("initialized stable state is missing server identity"))?,
                decoded_handle_key
                    .ok_or(StableJournalError::Corrupt("initialized stable state is missing handle-key material"))?,
                Some(
                    decoded_boot
                        .ok_or(StableJournalError::Corrupt("initialized stable state is missing its boot record"))?,
                ),
                decoded_records,
            )
        };

        let boot = BootRecord {
            verifier: random_array_excluding(previous_boot.map(|record| record.verifier))?,
            boot_tag: random_boot_tag(previous_boot.map(|record| record.boot_tag))?,
            started_at_unix_seconds,
            clean_shutdown: false,
        };
        let mut startup_mutations = Vec::with_capacity(if is_new { 4 } else { 1 });
        if is_new {
            startup_mutations.push(put_mutation(
                &JournalKey::Schema,
                &JournalRecord::Schema(SchemaRecord {
                    version: SCHEMA_VERSION,
                }),
                limits,
            )?);
            startup_mutations.push(put_mutation(
                &JournalKey::ServerIdentity,
                &JournalRecord::ServerIdentity(server_identity),
                limits,
            )?);
            startup_mutations.push(put_mutation(
                &JournalKey::HandleKey,
                &JournalRecord::HandleKey(handle_key),
                limits,
            )?);
        }
        startup_mutations.push(put_mutation(&JournalKey::Boot, &JournalRecord::Boot(boot), limits)?);

        let mut live_records = stable_record_map(&snapshot)?;
        let startup_updates = plan_live_record_updates(&live_records, &startup_mutations, limits.max_records)?;
        let commit_result = session.commit(snapshot.generation, StableBatch::new(startup_mutations)).await;
        let mut generation = resolve_commit_result(
            &session,
            &fence_token,
            snapshot.generation,
            &live_records,
            &startup_updates,
            limits,
            commit_result,
        )
        .await?;
        apply_live_record_updates(&mut live_records, &startup_updates);

        let mut legacy_cleanup_keys = legacy_cleanup_keys
            .into_iter()
            .map(|key| key.encode(limits))
            .collect::<Result<Vec<_>, _>>()?;
        legacy_cleanup_keys.sort_by(|left, right| {
            stable_kind_code(left.kind)
                .cmp(&stable_kind_code(right.kind))
                .then_with(|| left.key.as_ref().cmp(right.key.as_ref()))
        });
        legacy_cleanup_keys.dedup();
        for keys in legacy_cleanup_keys.chunks(limits.max_batch_mutations) {
            let mutations = keys
                .iter()
                .cloned()
                .map(|key| StableMutation::Delete { key })
                .collect::<Vec<_>>();
            let updates = plan_live_record_updates(&live_records, &mutations, limits.max_records)?;
            let expected_generation = generation;
            let result = session.commit(expected_generation, StableBatch::new(mutations)).await;
            generation = resolve_commit_result(
                &session,
                &fence_token,
                expected_generation,
                &live_records,
                &updates,
                limits,
                result,
            )
            .await?;
            apply_live_record_updates(&mut live_records, &updates);
        }
        let previous_shutdown = match previous_boot {
            None => PreviousShutdown::FirstBoot,
            Some(previous) if previous.clean_shutdown => PreviousShutdown::Clean,
            Some(_) => PreviousShutdown::Unclean,
        };

        Ok(Self {
            session,
            fence_token,
            generation,
            limits,
            live_records,
            server_identity,
            boot,
            handle_key,
            recovery: RecoveredStableState {
                previous_shutdown,
                previous_boot,
                records,
            },
            migrations,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn fence_token(&self) -> &StableFenceToken {
        &self.fence_token
    }

    pub fn server_identity(&self) -> ServerIdentityRecord {
        self.server_identity
    }

    pub fn boot(&self) -> BootRecord {
        self.boot
    }

    pub fn handle_key(&self) -> HandleKeyRecord {
        self.handle_key
    }

    pub fn handle_codec(&self) -> HandleCodec {
        HandleCodec::from_key(self.handle_key.instance_id, self.handle_key.secret)
    }

    pub fn recovery(&self) -> &RecoveredStableState {
        &self.recovery
    }

    pub(crate) fn limits(&self) -> StableJournalLimits {
        self.limits
    }

    pub(crate) fn verify_live_fence(&self) -> Result<(), StableJournalError> {
        self.ensure_fence()
    }

    pub(crate) fn imported_handle_keys(&self) -> Vec<ImportedHandleKey> {
        self.migrations
            .values()
            .filter(|migration| migration.phase == MigrationPhase::Committed)
            .map(|migration| ImportedHandleKey {
                export_id: migration.export_id,
                transfer_id: migration.transfer_id,
                server_identity: migration.server_identity.identity,
                handle_key: migration.handle_key,
            })
            .collect()
    }

    /// Takes a fenced, checkpointed snapshot of protocol records belonging to
    /// one export. File contents are never represented in the stable journal.
    pub(crate) async fn snapshot_for_migration(
        &mut self,
        export_id: ExportId,
    ) -> Result<MigrationStableSnapshot, StableJournalError> {
        self.checkpoint().await?;
        let snapshot = self.session.recover().await.map_err(StableJournalError::from)?;
        self.validate_current_snapshot(&snapshot)?;
        let decoded = decode_snapshot(&snapshot, self.limits)?;
        let records = select_export_records(decoded.records, export_id, self.limits)?;
        let migration = MigrationStableSnapshot {
            source_generation: snapshot.generation,
            server_identity: self.server_identity,
            boot: self.boot,
            handle_key: self.handle_key,
            records,
        };
        validate_migration_snapshot(&migration, export_id, self.limits)?;
        Ok(migration)
    }

    /// Stages an imported migration as one fenced record. Staged protocol
    /// state is deliberately invisible to recovery until `commit` atomically
    /// materializes it into canonical journal records.
    pub(crate) async fn stage_migration_import(
        &mut self,
        mut capsule: MigrationCapsuleRecord,
    ) -> Result<MigrationStageStatus, StableJournalError> {
        self.ensure_fence()?;
        if capsule.phase != MigrationPhase::Staged {
            return Err(StableJournalError::InvalidMigration("only staged capsules may be imported"));
        }
        capsule = sanitize_migration_capsule(capsule, self.limits)?;

        if let Some(existing) = self.migrations.get(&capsule.transfer_id) {
            if existing != &capsule
                && !(existing.phase == MigrationPhase::Committed && migration_identity_matches(existing, &capsule))
            {
                return Err(StableJournalError::MigrationConflict);
            }
            return Ok(match existing.phase {
                MigrationPhase::Staged => MigrationStageStatus::AlreadyStaged,
                MigrationPhase::Committed => MigrationStageStatus::AlreadyCommitted,
                MigrationPhase::SourceMoved => return Err(StableJournalError::MigrationConflict),
            });
        }
        if self
            .migrations
            .values()
            .any(|migration| migration.export_id == capsule.export_id && migration.phase == MigrationPhase::Staged)
        {
            return Err(StableJournalError::MigrationConflict);
        }

        let snapshot = self.session.recover().await.map_err(StableJournalError::from)?;
        self.validate_current_snapshot(&snapshot)?;
        let (_, added) = validate_import_projection(&snapshot, &capsule.records, self.limits)?;
        if snapshot
            .records
            .len()
            .checked_add(added)
            .and_then(|count| count.checked_add(1))
            .is_none_or(|count| count > self.limits.max_records)
        {
            return Err(StableJournalError::LimitExceeded("stable record count after migration import"));
        }
        let key = JournalKey::Migration {
            export_id: capsule.export_id,
            transfer_id: capsule.transfer_id,
        };
        let mutation = put_mutation(&key, &JournalRecord::Migration(capsule.clone()), self.limits)?;
        self.commit(vec![mutation]).await?;
        self.migrations.insert(capsule.transfer_id, capsule);
        Ok(MigrationStageStatus::Staged)
    }

    /// Checks whether this exact migration was committed previously without
    /// staging or materializing any records. This lets a restarted
    /// destination answer an application-level import retry idempotently
    /// while its runtime has already recovered the committed records.
    pub(crate) fn migration_import_already_committed(
        &self,
        capsule: &MigrationCapsuleRecord,
    ) -> Result<bool, StableJournalError> {
        self.ensure_fence()?;
        validate_migration_capsule(capsule, self.limits)?;
        let Some(existing) = self.migrations.get(&capsule.transfer_id) else {
            return Ok(false);
        };
        if !migration_identity_matches(existing, capsule) {
            return Err(StableJournalError::MigrationConflict);
        }
        Ok(existing.phase == MigrationPhase::Committed)
    }

    /// Returns exports whose source cutover was durably armed. Presence of
    /// this marker fences the source conservatively even if the process
    /// stopped while the external coordinator commit was in flight.
    pub(crate) fn source_moved_exports(&self) -> Vec<ExportId> {
        let mut exports = self
            .migrations
            .values()
            .filter(|migration| migration.phase == MigrationPhase::SourceMoved)
            .map(|migration| migration.export_id)
            .collect::<Vec<_>>();
        exports.sort_by_key(|export_id| export_id.0);
        exports.dedup();
        exports
    }

    /// Reports whether this exact source cutover was already armed.
    pub(crate) fn source_cutover_armed(&self, capsule: &MigrationCapsuleRecord) -> Result<bool, StableJournalError> {
        self.ensure_fence()?;
        validate_migration_capsule(capsule, self.limits)?;
        let Some(existing) = self.migrations.get(&capsule.transfer_id) else {
            return Ok(false);
        };
        if !migration_identity_matches(existing, capsule) {
            return Err(StableJournalError::MigrationConflict);
        }
        Ok(existing.phase == MigrationPhase::SourceMoved)
    }

    /// Durably arms a source cutover before the application coordinator is
    /// committed. The marker is intentionally not reversible: after an
    /// ambiguous crash the old source must fail closed instead of serving a
    /// filesystem that may already be active elsewhere.
    pub(crate) async fn arm_source_cutover(
        &mut self,
        mut capsule: MigrationCapsuleRecord,
    ) -> Result<(), StableJournalError> {
        self.ensure_fence()?;
        if capsule.phase != MigrationPhase::Staged {
            return Err(StableJournalError::InvalidMigration("source cutover requires a staged capsule"));
        }
        validate_migration_capsule(&capsule, self.limits)?;
        if let Some(existing) = self.migrations.get(&capsule.transfer_id) {
            if existing.phase == MigrationPhase::SourceMoved && migration_identity_matches(existing, &capsule) {
                return Ok(());
            }
            return Err(StableJournalError::MigrationConflict);
        }
        if self
            .migrations
            .values()
            .any(|migration| migration.export_id == capsule.export_id && migration.phase == MigrationPhase::SourceMoved)
        {
            return Err(StableJournalError::MigrationConflict);
        }

        capsule.phase = MigrationPhase::SourceMoved;
        // Canonical protocol state is already present in this source store.
        // Keeping a second embedded copy would consume the bounded payload
        // budget without improving restart fencing.
        capsule.records.clear();
        let key = JournalKey::Migration {
            export_id: capsule.export_id,
            transfer_id: capsule.transfer_id,
        };
        let mutation = put_mutation(&key, &JournalRecord::Migration(capsule.clone()), self.limits)?;
        self.commit(vec![mutation]).await?;
        self.migrations.insert(capsule.transfer_id, capsule);
        Ok(())
    }

    /// Atomically activates a staged import. Either every protocol record and
    /// the committed handle identity become durable, or none do.
    pub(crate) async fn commit_migration_import(
        &mut self,
        transfer_id: [u8; 16],
    ) -> Result<CommittedMigration, StableJournalError> {
        self.ensure_fence()?;
        let staged = self
            .migrations
            .get(&transfer_id)
            .cloned()
            .ok_or(StableJournalError::MigrationNotFound)?;
        let staged = sanitize_migration_capsule(staged, self.limits)?;
        if staged.phase == MigrationPhase::SourceMoved {
            return Err(StableJournalError::MigrationCommitted);
        }
        let typed_records = decode_transfer_records(&staged.records, self.limits)?;
        if staged.phase == MigrationPhase::Committed {
            return Ok(CommittedMigration {
                export_id: staged.export_id,
                transfer_id,
                server_identity: staged.server_identity.identity,
                boot: staged.boot,
                handle_key: staged.handle_key,
                records: typed_records,
            });
        }

        let snapshot = self.session.recover().await.map_err(StableJournalError::from)?;
        self.validate_current_snapshot(&snapshot)?;
        let (existing, added) = validate_import_projection(&snapshot, &staged.records, self.limits)?;
        if snapshot
            .records
            .len()
            .checked_add(added)
            .is_none_or(|count| count > self.limits.max_records)
        {
            return Err(StableJournalError::LimitExceeded("stable record count after migration commit"));
        }
        let mut mutations = Vec::with_capacity(staged.records.len().saturating_add(1));
        for record in &staged.records {
            match existing.get(&record.key) {
                Some(payload) if payload == &record.payload => {},
                Some(_) => return Err(StableJournalError::MigrationConflict),
                None => mutations.push(StableMutation::Put {
                    key: record.key.clone(),
                    payload: record.payload.clone(),
                }),
            }
        }

        let mut committed = staged.clone();
        committed.phase = MigrationPhase::Committed;
        committed.records.clear();
        mutations.push(put_mutation(
            &JournalKey::Migration {
                export_id: committed.export_id,
                transfer_id,
            },
            &JournalRecord::Migration(committed.clone()),
            self.limits,
        )?);
        if mutations.len() > self.limits.max_batch_mutations {
            return Err(StableJournalError::LimitExceeded("migration commit batch"));
        }
        self.commit(mutations).await?;
        self.migrations.insert(transfer_id, committed);

        Ok(CommittedMigration {
            export_id: staged.export_id,
            transfer_id,
            server_identity: staged.server_identity.identity,
            boot: staged.boot,
            handle_key: staged.handle_key,
            records: typed_records,
        })
    }

    pub(crate) async fn abort_migration_import(&mut self, transfer_id: [u8; 16]) -> Result<(), StableJournalError> {
        self.ensure_fence()?;
        let staged = self.migrations.get(&transfer_id).ok_or(StableJournalError::MigrationNotFound)?;
        if matches!(staged.phase, MigrationPhase::Committed | MigrationPhase::SourceMoved) {
            return Err(StableJournalError::MigrationCommitted);
        }
        let key = JournalKey::Migration {
            export_id: staged.export_id,
            transfer_id,
        };
        self.commit(vec![StableMutation::Delete {
            key: key.encode(self.limits)?,
        }])
        .await?;
        self.migrations.remove(&transfer_id);
        Ok(())
    }

    fn validate_current_snapshot(&self, snapshot: &StableSnapshot) -> Result<(), StableJournalError> {
        self.ensure_fence()?;
        if snapshot.fence_token != self.fence_token {
            return Err(StableJournalError::Fenced);
        }
        if snapshot.generation != self.generation {
            return Err(StableJournalError::CasConflict {
                expected: self.generation,
                actual: snapshot.generation,
            });
        }
        if snapshot.records.len() > self.limits.max_records {
            return Err(StableJournalError::LimitExceeded("stable record count"));
        }
        Ok(())
    }

    /// Commits state that must become durable before the corresponding NFS
    /// success reply is acknowledged to the client.
    pub async fn persist_before_ack(&mut self, batch: PersistBatch) -> Result<Persisted, StableJournalError> {
        if batch.mutations.is_empty() {
            return Err(StableJournalError::EmptyBatch);
        }
        if batch.mutations.len() > self.limits.max_batch_mutations {
            return Err(StableJournalError::LimitExceeded("stable mutation batch"));
        }
        self.ensure_fence()?;

        let mut encoded = Vec::with_capacity(batch.mutations.len());
        for mutation in batch.mutations {
            match mutation {
                JournalMutation::Put { key, record } => {
                    if key.is_reserved() {
                        return Err(StableJournalError::ReservedRecord);
                    }
                    validate_key_record(&key, &record)?;
                    encoded.push(put_mutation(&key, &record, self.limits)?);
                },
                JournalMutation::Delete { key } => {
                    if key.is_reserved() {
                        return Err(StableJournalError::ReservedRecord);
                    }
                    encoded.push(StableMutation::Delete {
                        key: key.encode(self.limits)?,
                    });
                },
            }
        }
        self.commit(encoded).await
    }

    pub async fn checkpoint(&mut self) -> Result<Persisted, StableJournalError> {
        self.ensure_fence()?;
        let expected_generation = self.generation;
        let result = self.session.checkpoint(expected_generation).await;
        let generation = resolve_commit_result(
            &self.session,
            &self.fence_token,
            expected_generation,
            &self.live_records,
            &LiveRecordUpdates::new(),
            self.limits,
            result,
        )
        .await?;
        self.generation = generation;
        Ok(Persisted { generation })
    }

    pub async fn mark_clean_shutdown(&mut self) -> Result<Persisted, StableJournalError> {
        if self.boot.clean_shutdown {
            return self.checkpoint().await;
        }
        let mut clean = self.boot;
        clean.clean_shutdown = true;
        let persisted = self
            .commit(vec![put_mutation(
                &JournalKey::Boot,
                &JournalRecord::Boot(clean),
                self.limits,
            )?])
            .await?;
        self.boot = clean;
        Ok(persisted)
    }

    async fn commit(&mut self, mutations: Vec<StableMutation>) -> Result<Persisted, StableJournalError> {
        self.ensure_fence()?;
        let updates = plan_live_record_updates(&self.live_records, &mutations, self.limits.max_records)?;
        let expected_generation = self.generation;
        let result = self.session.commit(expected_generation, StableBatch::new(mutations)).await;
        let generation = resolve_commit_result(
            &self.session,
            &self.fence_token,
            expected_generation,
            &self.live_records,
            &updates,
            self.limits,
            result,
        )
        .await?;
        apply_live_record_updates(&mut self.live_records, &updates);
        self.generation = generation;
        Ok(Persisted { generation })
    }

    fn ensure_fence(&self) -> Result<(), StableJournalError> {
        if self.session.fence_token() != self.fence_token {
            return Err(StableJournalError::Fenced);
        }
        Ok(())
    }
}

impl std::fmt::Debug for StableJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StableJournal")
            .field("fence_token", &self.fence_token)
            .field("generation", &self.generation)
            .field("live_record_count", &self.live_records.len())
            .field("server_identity", &self.server_identity)
            .field("boot", &self.boot)
            .field("handle_instance_id", &self.handle_key.instance_id)
            .field("recovery", &self.recovery)
            .field("migration_count", &self.migrations.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct DecodedSnapshot {
    schema: Option<SchemaRecord>,
    server_identity: Option<ServerIdentityRecord>,
    boot: Option<BootRecord>,
    handle_key: Option<HandleKeyRecord>,
    records: Vec<(JournalKey, JournalRecord)>,
    migrations: BTreeMap<[u8; 16], MigrationCapsuleRecord>,
    legacy_cleanup_keys: Vec<JournalKey>,
}

fn decode_snapshot(
    snapshot: &StableSnapshot,
    limits: StableJournalLimits,
) -> Result<DecodedSnapshot, StableJournalError> {
    let mut decoded = DecodedSnapshot::default();
    let mut seen_storage_keys = std::collections::HashSet::with_capacity(snapshot.records.len());
    for stable_record in &snapshot.records {
        if !seen_storage_keys.insert(stable_record.key.clone()) {
            return Err(StableJournalError::Corrupt("duplicate stable storage key"));
        }
        let key = JournalKey::decode(&stable_record.key, limits)?;
        let record = JournalRecord::decode(&stable_record.payload, limits)?;
        validate_key_record(&key, &record)?;
        match record {
            JournalRecord::Schema(record) => set_once(&mut decoded.schema, record, "duplicate schema record")?,
            JournalRecord::ServerIdentity(record) => {
                set_once(&mut decoded.server_identity, record, "duplicate server-identity record")?
            },
            JournalRecord::Boot(record) => set_once(&mut decoded.boot, record, "duplicate boot record")?,
            JournalRecord::HandleKey(record) => {
                set_once(&mut decoded.handle_key, record, "duplicate handle-key record")?
            },
            JournalRecord::Migration(record) => {
                let record = sanitize_migration_capsule(record, limits)?;
                if decoded.migrations.insert(record.transfer_id, record).is_some() {
                    return Err(StableJournalError::Corrupt("duplicate migration transfer id"));
                }
            },
            record => decoded.records.push((key, record)),
        }
    }
    let (records, legacy_cleanup_keys) = sanitize_typed_records(decoded.records);
    decoded.records = records;
    decoded.legacy_cleanup_keys = legacy_cleanup_keys;
    validate_active_state_identities(&decoded.records)?;
    validate_durable_delegation_graph(&decoded.records)?;
    Ok(decoded)
}

fn set_once<T>(slot: &mut Option<T>, value: T, message: &'static str) -> Result<(), StableJournalError> {
    if slot.replace(value).is_some() {
        return Err(StableJournalError::Corrupt(message));
    }
    Ok(())
}

fn put_mutation(
    key: &JournalKey,
    record: &JournalRecord,
    limits: StableJournalLimits,
) -> Result<StableMutation, StableJournalError> {
    validate_key_record(key, record)?;
    Ok(StableMutation::Put {
        key: key.encode(limits)?,
        payload: record.encode(limits)?,
    })
}

fn encode_boot(encoder: &mut BinaryEncoder, boot: BootRecord) {
    encoder.fixed(&boot.verifier);
    encoder.u32(boot.boot_tag);
    encoder.i64(boot.started_at_unix_seconds);
    encoder.boolean(boot.clean_shutdown);
}

fn decode_boot(decoder: &mut BinaryDecoder<'_>) -> Result<BootRecord, StableJournalError> {
    Ok(BootRecord {
        verifier: decoder.fixed()?,
        boot_tag: decoder.u32()?,
        started_at_unix_seconds: decoder.i64()?,
        clean_shutdown: decoder.boolean()?,
    })
}

fn stable_kind_code(kind: StableRecordKind) -> u8 {
    match kind {
        StableRecordKind::Server => 0,
        StableRecordKind::Client => 1,
        StableRecordKind::OpenOwner => 2,
        StableRecordKind::LockOwner => 3,
        StableRecordKind::Migration => 4,
    }
}

fn stable_kind_from_code(code: u8) -> Result<StableRecordKind, StableJournalError> {
    match code {
        0 => Ok(StableRecordKind::Server),
        1 => Ok(StableRecordKind::Client),
        2 => Ok(StableRecordKind::OpenOwner),
        3 => Ok(StableRecordKind::LockOwner),
        4 => Ok(StableRecordKind::Migration),
        _ => Err(StableJournalError::Corrupt("invalid stable record kind")),
    }
}

fn encode_stable_record(
    encoder: &mut BinaryEncoder,
    stable_record: &StableRecord,
    limits: StableJournalLimits,
) -> Result<(), StableJournalError> {
    validate_transfer_record(stable_record, limits)?;
    encoder.u8(stable_kind_code(stable_record.key.kind));
    encoder.opaque(&stable_record.key.key, limits.max_key_bytes)?;
    encoder.opaque(&stable_record.payload, limits.max_payload_bytes)?;
    Ok(())
}

fn decode_stable_record(
    decoder: &mut BinaryDecoder<'_>,
    limits: StableJournalLimits,
) -> Result<StableRecord, StableJournalError> {
    let stable_record = StableRecord {
        key: StableKey {
            kind: stable_kind_from_code(decoder.u8()?)?,
            key: decoder.opaque(limits.max_key_bytes)?,
        },
        payload: decoder.opaque(limits.max_payload_bytes)?,
    };
    validate_transfer_record(&stable_record, limits)?;
    Ok(stable_record)
}

fn validate_transfer_record(
    stable_record: &StableRecord,
    limits: StableJournalLimits,
) -> Result<(JournalKey, JournalRecord), StableJournalError> {
    if stable_record.key.kind == StableRecordKind::Migration {
        return Err(StableJournalError::Corrupt("nested migration record"));
    }
    let key = JournalKey::decode(&stable_record.key, limits)?;
    if matches!(
        key,
        JournalKey::Schema
            | JournalKey::ServerIdentity
            | JournalKey::Boot
            | JournalKey::HandleKey
            | JournalKey::Migration { .. }
    ) {
        return Err(StableJournalError::Corrupt("reserved record in migration state"));
    }
    let record = JournalRecord::decode(&stable_record.payload, limits)?;
    validate_key_record(&key, &record)?;
    Ok((key, record))
}

fn stable_record_from_typed(
    key: &JournalKey,
    record: &JournalRecord,
    limits: StableJournalLimits,
) -> Result<StableRecord, StableJournalError> {
    let mutation = put_mutation(key, record, limits)?;
    match mutation {
        StableMutation::Put { key, payload } => Ok(StableRecord { key, payload }),
        StableMutation::Delete { .. } => unreachable!("put_mutation always returns a put"),
    }
}

#[cfg(test)]
pub(crate) fn migration_stable_record_for_test(
    key: &JournalKey,
    record: &JournalRecord,
    limits: StableJournalLimits,
) -> StableRecord {
    stable_record_from_typed(key, record, limits).expect("test migration record must be canonical")
}

pub(crate) fn validate_migration_snapshot(
    snapshot: &MigrationStableSnapshot,
    export_id: ExportId,
    limits: StableJournalLimits,
) -> Result<(), StableJournalError> {
    if snapshot.server_identity.identity == [0; 16]
        || snapshot.handle_key.instance_id == [0; 8]
        || snapshot.handle_key.secret == [0; 32]
    {
        return Err(StableJournalError::Corrupt("invalid migration identity"));
    }
    if snapshot.source_generation == 0 {
        return Err(StableJournalError::Corrupt("zero migration source generation"));
    }
    JournalRecord::Boot(snapshot.boot).validate()?;
    let sanitized = sanitize_transfer_records(&snapshot.records, limits)?;
    if sanitized.stable.windows(2).any(|records| {
        let left = &records[0];
        let right = &records[1];
        stable_kind_code(left.key.kind)
            .cmp(&stable_kind_code(right.key.kind))
            .then_with(|| left.key.key.as_ref().cmp(right.key.key.as_ref()))
            != std::cmp::Ordering::Less
    }) {
        return Err(StableJournalError::Corrupt("migration records are not in canonical order"));
    }

    if sanitized.stable.len().saturating_add(1) > limits.max_batch_mutations {
        return Err(StableJournalError::LimitExceeded("migration record count"));
    }
    let typed = sanitized.typed;
    let mut client_ids = HashSet::new();
    let mut recorded_clients = HashSet::new();
    for (_, record) in &typed {
        match record {
            JournalRecord::Client(record) => {
                recorded_clients.insert(record.client_id);
            },
            JournalRecord::Open(record) => {
                if record.object.export_id != export_id {
                    return Err(StableJournalError::MigrationExportMismatch);
                }
                client_ids.insert(record.client_id);
            },
            JournalRecord::Lock(record) => {
                if record.object.export_id != export_id {
                    return Err(StableJournalError::MigrationExportMismatch);
                }
                client_ids.insert(record.client_id);
            },
            JournalRecord::Delegation(record) => {
                if record.object.export_id != export_id {
                    return Err(StableJournalError::MigrationExportMismatch);
                }
                client_ids.insert(record.client_id);
            },
            JournalRecord::Revocation(_) => {},
            JournalRecord::Replay(record) => {
                if record.current_object.is_some_and(|object| object.export_id != export_id) {
                    return Err(StableJournalError::MigrationExportMismatch);
                }
                client_ids.insert(record.client_id);
            },
            JournalRecord::Schema(_)
            | JournalRecord::ServerIdentity(_)
            | JournalRecord::Boot(_)
            | JournalRecord::HandleKey(_)
            | JournalRecord::Migration(_) => {
                return Err(StableJournalError::Corrupt("reserved record in migration state"));
            },
        }
    }
    validate_active_state_identities(&typed)?;
    validate_durable_delegation_graph(&typed)?;
    if !client_ids.is_subset(&recorded_clients) {
        return Err(StableJournalError::Corrupt("migrated state is missing a client record"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ActiveStableState<'a> {
    Open(&'a OpenRecord),
    Lock,
    Delegation,
}

fn stable_state_identity(state_token: [u8; 16]) -> [u8; 12] {
    state_token[4..]
        .try_into()
        .expect("a stable state token always contains a 12-byte object identity")
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct CanonicalStableClientIdentity {
    owner: Bytes,
    verifier: [u8; 8],
    canonical_principal: Bytes,
}

#[derive(Default)]
struct DurableDelegationOwners {
    identities: HashSet<CanonicalStableClientIdentity>,
    has_write: bool,
}

/// Validates the complete persistent-delegation ownership graph in linear
/// time. Client IDs are aliases rather than canonical identities: two IDs
/// carrying the same confirmed identity cannot create duplicate durable
/// claims. Distinct identities may share read delegations, while a write
/// delegation must be the sole durable claim for its exported object.
fn validate_durable_delegation_graph(records: &[(JournalKey, JournalRecord)]) -> Result<(), StableJournalError> {
    let clients = records
        .iter()
        .filter_map(|(_, record)| match record {
            JournalRecord::Client(client) if client.confirmed => Some((
                client.client_id,
                CanonicalStableClientIdentity {
                    owner: client.owner.clone(),
                    verifier: client.verifier,
                    canonical_principal: client.canonical_principal.clone(),
                },
            )),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let mut owners = HashMap::<(ExportId, Bytes), DurableDelegationOwners>::new();
    for (_, record) in records {
        let JournalRecord::Delegation(delegation) = record else {
            continue;
        };
        let identity = clients
            .get(&delegation.client_id)
            .ok_or(StableJournalError::Corrupt("stable delegation is missing a confirmed client"))?;
        let owners = owners
            .entry((delegation.object.export_id, delegation.persistent_object_id.clone()))
            .or_default();
        if owners.identities.contains(identity)
            || (!owners.identities.is_empty() && (owners.has_write || delegation.write))
        {
            return Err(StableJournalError::Corrupt("conflicting stable delegation ownership graph"));
        }
        owners.identities.insert(identity.clone());
        owners.has_write |= delegation.write;
    }
    Ok(())
}

/// Validates the complete active-state image in linear time.
///
/// The leading four bytes of an NFSv4 stateid are a mutable sequence number.
/// The trailing 12-byte `other` field identifies the state object and must be
/// unique across every active state kind. A LOCK's saved OPEN token can carry
/// an earlier sequence number, so ancestry is resolved through that stable
/// object identity instead of comparing the complete token.
fn validate_active_state_identities(records: &[(JournalKey, JournalRecord)]) -> Result<(), StableJournalError> {
    let mut states = HashMap::with_capacity(records.len());
    for (_, record) in records {
        let (state_token, state) = match record {
            JournalRecord::Open(open) => (open.state_token, ActiveStableState::Open(open)),
            JournalRecord::Lock(lock) => (lock.state_token, ActiveStableState::Lock),
            JournalRecord::Delegation(delegation) => (delegation.state_token, ActiveStableState::Delegation),
            JournalRecord::Schema(_)
            | JournalRecord::ServerIdentity(_)
            | JournalRecord::Boot(_)
            | JournalRecord::HandleKey(_)
            | JournalRecord::Client(_)
            | JournalRecord::Revocation(_)
            | JournalRecord::Replay(_)
            | JournalRecord::Migration(_) => continue,
        };
        if states.insert(stable_state_identity(state_token), state).is_some() {
            return Err(StableJournalError::Corrupt("duplicate stable state object identity"));
        }
    }

    for (_, record) in records {
        let JournalRecord::Lock(lock) = record else {
            continue;
        };
        let Some(ActiveStableState::Open(open)) = states.get(&stable_state_identity(lock.open_state_token)) else {
            return Err(StableJournalError::Corrupt("stable lock is missing its open state"));
        };
        if open.client_id != lock.client_id || open.object != lock.object {
            return Err(StableJournalError::Corrupt("stable lock does not match its open state"));
        }
    }
    Ok(())
}

fn validate_migration_capsule(
    capsule: &MigrationCapsuleRecord,
    limits: StableJournalLimits,
) -> Result<(), StableJournalError> {
    if capsule.transfer_id == [0; 16] || capsule.coordinator_token_digest == [0; 32] || capsule.bundle_digest == [0; 32]
    {
        return Err(StableJournalError::Corrupt("invalid migration transaction identity"));
    }
    let snapshot = MigrationStableSnapshot {
        source_generation: capsule.source_generation,
        server_identity: capsule.server_identity,
        boot: capsule.boot,
        handle_key: capsule.handle_key,
        records: capsule.records.clone(),
    };
    validate_migration_snapshot(&snapshot, capsule.export_id, limits)
}

fn sanitize_migration_capsule(
    mut capsule: MigrationCapsuleRecord,
    limits: StableJournalLimits,
) -> Result<MigrationCapsuleRecord, StableJournalError> {
    capsule.records = sanitize_transfer_records(&capsule.records, limits)?.stable;
    validate_migration_capsule(&capsule, limits)?;
    Ok(capsule)
}

fn migration_identity_matches(left: &MigrationCapsuleRecord, right: &MigrationCapsuleRecord) -> bool {
    left.transfer_id == right.transfer_id
        && left.export_id == right.export_id
        && left.fsid_major == right.fsid_major
        && left.fsid_minor == right.fsid_minor
        && left.source_generation == right.source_generation
        && left.coordinator_generation == right.coordinator_generation
        && left.coordinator_token_digest == right.coordinator_token_digest
        && left.bundle_digest == right.bundle_digest
        && left.server_identity == right.server_identity
        && left.boot == right.boot
        && left.handle_key == right.handle_key
}

fn decode_transfer_records(
    records: &[StableRecord],
    limits: StableJournalLimits,
) -> Result<Vec<(JournalKey, JournalRecord)>, StableJournalError> {
    Ok(sanitize_transfer_records(records, limits)?.typed)
}

fn select_export_records(
    records: Vec<(JournalKey, JournalRecord)>,
    export_id: ExportId,
    limits: StableJournalLimits,
) -> Result<Vec<StableRecord>, StableJournalError> {
    let (records, _) = sanitize_typed_records(records);
    let mut selected_owners = HashSet::new();
    let mut selected_clients = HashSet::new();
    let mut selected = Vec::new();

    for (key, record) in &records {
        match record {
            JournalRecord::Open(open) if open.object.export_id == export_id => {
                selected_clients.insert(open.client_id);
                selected_owners.insert((open.client_id, ReplayOwnerKind::Open, open.owner.clone()));
                selected.push((key.clone(), record.clone()));
            },
            JournalRecord::Lock(lock) if lock.object.export_id == export_id => {
                selected_clients.insert(lock.client_id);
                selected_owners.insert((lock.client_id, ReplayOwnerKind::Lock, lock.owner.clone()));
                selected.push((key.clone(), record.clone()));
            },
            JournalRecord::Delegation(delegation) if delegation.object.export_id == export_id => {
                selected_clients.insert(delegation.client_id);
                selected.push((key.clone(), record.clone()));
            },
            _ => {},
        }
    }

    for (key, record) in &records {
        if let JournalRecord::Replay(replay) = record {
            let owner_selected = selected_owners.contains(&(replay.client_id, replay.owner_kind, replay.owner.clone()));
            let object_selected = replay.current_object.is_some_and(|object| object.export_id == export_id);
            if owner_selected || object_selected {
                selected_clients.insert(replay.client_id);
                selected.push((key.clone(), record.clone()));
            }
        }
    }
    for (key, record) in &records {
        if matches!(record, JournalRecord::Client(client) if selected_clients.contains(&client.client_id)) {
            selected.push((key.clone(), record.clone()));
        }
    }

    let mut encoded = selected
        .into_iter()
        .map(|(key, record)| stable_record_from_typed(&key, &record, limits))
        .collect::<Result<Vec<_>, _>>()?;
    encoded.sort_by(|left, right| {
        stable_kind_code(left.key.kind)
            .cmp(&stable_kind_code(right.key.kind))
            .then_with(|| left.key.key.as_ref().cmp(right.key.key.as_ref()))
    });
    let snapshot = MigrationStableSnapshot {
        source_generation: 1,
        server_identity: ServerIdentityRecord { identity: [1; 16] },
        boot: BootRecord {
            verifier: [1; 8],
            boot_tag: 1,
            started_at_unix_seconds: 0,
            clean_shutdown: false,
        },
        handle_key: HandleKeyRecord {
            instance_id: [1; 8],
            secret: [1; 32],
        },
        records: encoded,
    };
    validate_migration_snapshot(&snapshot, export_id, limits)?;
    Ok(snapshot.records)
}

fn stable_record_map(snapshot: &StableSnapshot) -> Result<HashMap<StableKey, Bytes>, StableJournalError> {
    let mut records = HashMap::with_capacity(snapshot.records.len());
    for record in &snapshot.records {
        if records.insert(record.key.clone(), record.payload.clone()).is_some() {
            return Err(StableJournalError::Corrupt("duplicate stable storage key"));
        }
    }
    Ok(records)
}

fn validate_import_projection(
    current: &StableSnapshot,
    imported: &[StableRecord],
    limits: StableJournalLimits,
) -> Result<(HashMap<StableKey, Bytes>, usize), StableJournalError> {
    let mut projected = decode_snapshot(current, limits)?.records;
    let current = stable_record_map(current)?;
    let SanitizedTransferRecords {
        stable: imported,
        typed: imported_typed,
    } = sanitize_transfer_records(imported, limits)?;
    let mut added = 0usize;
    for (stable_record, (key, record)) in imported.iter().zip(imported_typed) {
        match current.get(&stable_record.key) {
            Some(payload) if payload != &stable_record.payload => {
                return Err(StableJournalError::MigrationConflict);
            },
            Some(_) => {},
            None => {
                added = added.saturating_add(1);
                projected.push((key, record));
            },
        }
    }
    validate_active_state_identities(&projected).map_err(|_| StableJournalError::MigrationConflict)?;
    validate_durable_delegation_graph(&projected).map_err(|_| StableJournalError::MigrationConflict)?;
    Ok((current, added))
}

fn random_array<const N: usize>() -> Result<[u8; N], StableJournalError> {
    let mut value = [0; N];
    OsRng
        .try_fill_bytes(&mut value)
        .map_err(|error| StableJournalError::Entropy(error.to_string()))?;
    Ok(value)
}

fn random_array_excluding<const N: usize>(excluded: Option<[u8; N]>) -> Result<[u8; N], StableJournalError> {
    loop {
        let value = random_array()?;
        if excluded != Some(value) {
            return Ok(value);
        }
    }
}

fn random_boot_tag(excluded: Option<u32>) -> Result<u32, StableJournalError> {
    loop {
        let tag = u32::from_be_bytes(random_array()?);
        if tag != 0 && tag != u32::MAX && excluded != Some(tag) {
            return Ok(tag);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StableJournalError {
    #[error("stable journal limits are invalid")]
    InvalidLimits,
    #[error("stable journal mutation batch is empty")]
    EmptyBatch,
    #[error("server identity records cannot be mutated through the application batch API")]
    ReservedRecord,
    #[error("stable journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("stable journal is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("stable journal schema version {0} is unsupported")]
    UnsupportedSchema(u32),
    #[error("unknown stable journal record tag {0}")]
    UnknownRecordTag(u8),
    #[error("stable state session was fenced")]
    Fenced,
    #[error("stable state generation changed (expected {expected}, actual {actual})")]
    CasConflict { expected: u64, actual: u64 },
    #[error("migration state conflicts with existing durable state")]
    MigrationConflict,
    #[error("migration export identity does not match its protocol records")]
    MigrationExportMismatch,
    #[error("migration transaction was not found")]
    MigrationNotFound,
    #[error("committed migration state cannot be aborted")]
    MigrationCommitted,
    #[error("invalid migration state: {0}")]
    InvalidMigration(&'static str),
    #[error("operating-system random source failed: {0}")]
    Entropy(String),
    #[error(transparent)]
    Storage(StableStateError),
}

impl From<StableStateError> for StableJournalError {
    fn from(error: StableStateError) -> Self {
        match error {
            StableStateError::Fenced => Self::Fenced,
            StableStateError::GenerationConflict { expected, actual } => Self::CasConflict { expected, actual },
            error => Self::Storage(error),
        }
    }
}

struct BinaryEncoder {
    bytes: Vec<u8>,
}

impl BinaryEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
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

    fn opaque(&mut self, value: &[u8], limit: usize) -> Result<(), StableJournalError> {
        if value.len() > limit {
            return Err(StableJournalError::LimitExceeded("stable opaque field"));
        }
        let length =
            u32::try_from(value.len()).map_err(|_| StableJournalError::LimitExceeded("stable opaque field"))?;
        self.u32(length);
        self.fixed(value);
        Ok(())
    }

    fn object(&mut self, object: StableObject) {
        self.u32(object.export_id.0);
        self.u64(object.file_id);
        self.u64(object.generation);
    }

    fn option_object(&mut self, object: Option<StableObject>) {
        self.boolean(object.is_some());
        if let Some(object) = object {
            self.object(object);
        }
    }

    fn finish(self) -> Bytes {
        Bytes::from(self.bytes)
    }
}

struct BinaryDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BinaryDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StableJournalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(StableJournalError::Corrupt("stable record length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(StableJournalError::Corrupt("truncated stable record"))?;
        self.position = end;
        Ok(value)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn u8(&mut self) -> Result<u8, StableJournalError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, StableJournalError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StableJournalError::Corrupt("non-canonical stable boolean")),
        }
    }

    fn u32(&mut self) -> Result<u32, StableJournalError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, StableJournalError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn i64(&mut self) -> Result<i64, StableJournalError> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], StableJournalError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StableJournalError::Corrupt("truncated stable fixed field"))
    }

    fn expect_fixed<const N: usize>(&mut self, expected: &[u8; N]) -> Result<(), StableJournalError> {
        if &self.fixed::<N>()? != expected {
            return Err(StableJournalError::Corrupt("invalid stable record magic"));
        }
        Ok(())
    }

    fn opaque(&mut self, limit: usize) -> Result<Bytes, StableJournalError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| StableJournalError::Corrupt("stable opaque length overflow"))?;
        if length > limit {
            return Err(StableJournalError::LimitExceeded("stable opaque field"));
        }
        Ok(Bytes::copy_from_slice(self.take(length)?))
    }

    fn object(&mut self) -> Result<StableObject, StableJournalError> {
        Ok(StableObject {
            export_id: ExportId(self.u32()?),
            file_id: self.u64()?,
            generation: self.u64()?,
        })
    }

    fn option_object(&mut self) -> Result<Option<StableObject>, StableJournalError> {
        if self.boolean()? {
            Ok(Some(self.object()?))
        } else {
            Ok(None)
        }
    }

    fn finish(self) -> Result<(), StableJournalError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(StableJournalError::Corrupt("trailing bytes in stable record"))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, MutexGuard};

    use async_trait::async_trait;

    use super::*;
    use crate::vfs::{ObjectKey, StableRecord};

    #[derive(Clone, Default)]
    pub(crate) struct DurableFakeStore {
        inner: Arc<Mutex<DurableFakeState>>,
    }

    #[derive(Default)]
    struct DurableFakeState {
        scopes: HashMap<Vec<u8>, DurableFakeScope>,
    }

    #[derive(Default)]
    struct DurableFakeScope {
        generation: u64,
        records: HashMap<StableKey, Bytes>,
        next_fence: u64,
        active_fence: Option<StableFenceToken>,
        checkpoints: usize,
        fail_next_commit: bool,
        fail_next_commit_after_apply: bool,
        fail_next_delete_commit_after_apply: bool,
        unexpected_record_after_apply: Option<StableRecord>,
        committed_batches: Vec<Vec<StableKey>>,
    }

    struct DurableFakeSession {
        inner: Arc<Mutex<DurableFakeState>>,
        scope: Vec<u8>,
        fence_token: StableFenceToken,
    }

    impl DurableFakeStore {
        fn lock(&self) -> MutexGuard<'_, DurableFakeState> {
            self.inner.lock().expect("durable fake-store lock poisoned")
        }

        pub(crate) fn advance_generation(&self, scope: &StableScope) -> u64 {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(scope.as_bytes())
                .expect("stable scope must have been opened");
            scope.generation = scope.generation.checked_add(1).expect("test generation overflow");
            scope.generation
        }

        pub(crate) fn fail_next_commit(&self, scope: &StableScope) {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(scope.as_bytes())
                .expect("stable scope must have been opened");
            scope.fail_next_commit = true;
        }

        fn fail_next_commit_after_apply(&self, scope: &StableScope) {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(scope.as_bytes())
                .expect("stable scope must have been opened");
            scope.fail_next_commit_after_apply = true;
        }

        fn fail_next_delete_commit_after_apply(&self, scope: &StableScope) {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(scope.as_bytes())
                .expect("stable scope must have been opened");
            scope.fail_next_delete_commit_after_apply = true;
        }

        fn fail_next_commit_after_apply_with_unexpected_record(
            &self,
            scope: &StableScope,
            unexpected_record: StableRecord,
        ) {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(scope.as_bytes())
                .expect("stable scope must have been opened");
            scope.unexpected_record_after_apply = Some(unexpected_record);
        }

        fn checkpoint_count(&self, scope: &StableScope) -> usize {
            self.lock()
                .scopes
                .get(scope.as_bytes())
                .expect("stable scope must have been opened")
                .checkpoints
        }

        fn committed_batches(&self, scope: &StableScope) -> Vec<Vec<StableKey>> {
            self.lock()
                .scopes
                .get(scope.as_bytes())
                .expect("stable scope must have been opened")
                .committed_batches
                .clone()
        }
    }

    impl DurableFakeSession {
        fn lock(&self) -> MutexGuard<'_, DurableFakeState> {
            self.inner.lock().expect("durable fake-session lock poisoned")
        }

        fn ensure_active(scope: &DurableFakeScope, fence_token: &StableFenceToken) -> Result<(), StableStateError> {
            if scope.active_fence.as_ref() == Some(fence_token) {
                Ok(())
            } else {
                Err(StableStateError::Fenced)
            }
        }
    }

    #[async_trait]
    impl StableStateStore for DurableFakeStore {
        async fn open_scope(&self, scope: StableScope) -> Result<Arc<dyn StableStateSession>, StableStateError> {
            let scope_key = scope.as_bytes().to_vec();
            let fence_token = {
                let mut state = self.lock();
                let scope = state.scopes.entry(scope_key.clone()).or_default();
                scope.next_fence = scope
                    .next_fence
                    .checked_add(1)
                    .ok_or_else(|| StableStateError::Other("test fence-token overflow".into()))?;
                let fence_token = StableFenceToken::new(Bytes::copy_from_slice(&scope.next_fence.to_be_bytes()));
                scope.active_fence = Some(fence_token.clone());
                fence_token
            };
            Ok(Arc::new(DurableFakeSession {
                inner: Arc::clone(&self.inner),
                scope: scope_key,
                fence_token,
            }))
        }
    }

    #[async_trait]
    impl StableStateSession for DurableFakeSession {
        fn fence_token(&self) -> StableFenceToken {
            self.fence_token.clone()
        }

        fn generation(&self) -> u64 {
            self.lock()
                .scopes
                .get(&self.scope)
                .expect("stable scope must exist for its session")
                .generation
        }

        async fn recover(&self) -> Result<StableSnapshot, StableStateError> {
            let state = self.lock();
            let scope = state
                .scopes
                .get(&self.scope)
                .ok_or_else(|| StableStateError::Other("stable scope disappeared".into()))?;
            Self::ensure_active(scope, &self.fence_token)?;
            let mut records = scope
                .records
                .iter()
                .map(|(key, payload)| StableRecord {
                    key: key.clone(),
                    payload: payload.clone(),
                })
                .collect::<Vec<_>>();
            records.sort_by(|left, right| left.key.key.as_ref().cmp(right.key.key.as_ref()));
            Ok(StableSnapshot {
                fence_token: self.fence_token.clone(),
                generation: scope.generation,
                records,
            })
        }

        async fn commit(&self, expected_generation: u64, batch: StableBatch) -> Result<u64, StableStateError> {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(&self.scope)
                .ok_or_else(|| StableStateError::Other("stable scope disappeared".into()))?;
            Self::ensure_active(scope, &self.fence_token)?;
            if std::mem::take(&mut scope.fail_next_commit) {
                return Err(StableStateError::Other("injected commit failure".into()));
            }
            if scope.generation != expected_generation {
                return Err(StableStateError::GenerationConflict {
                    expected: expected_generation,
                    actual: scope.generation,
                });
            }
            let next_generation = scope
                .generation
                .checked_add(1)
                .ok_or_else(|| StableStateError::Other("test generation overflow".into()))?;
            let fail_delete_after_apply = scope.fail_next_delete_commit_after_apply
                && batch
                    .mutations
                    .iter()
                    .all(|mutation| matches!(mutation, StableMutation::Delete { .. }));
            if fail_delete_after_apply {
                scope.fail_next_delete_commit_after_apply = false;
            }
            let fail_after_apply = std::mem::take(&mut scope.fail_next_commit_after_apply) || fail_delete_after_apply;
            let unexpected_record = scope.unexpected_record_after_apply.take();
            let has_unexpected_record = unexpected_record.is_some();
            scope.committed_batches.push(
                batch
                    .mutations
                    .iter()
                    .map(|mutation| match mutation {
                        StableMutation::Put { key, .. } | StableMutation::Delete { key } => key.clone(),
                    })
                    .collect(),
            );
            for mutation in batch.mutations {
                match mutation {
                    StableMutation::Put { key, payload } => {
                        scope.records.insert(key, payload);
                    },
                    StableMutation::Delete { key } => {
                        scope.records.remove(&key);
                    },
                }
            }
            if let Some(record) = unexpected_record {
                scope.records.insert(record.key, record.payload);
            }
            scope.generation = next_generation;
            if fail_after_apply || has_unexpected_record {
                Err(StableStateError::Other("injected ambiguous commit failure".into()))
            } else {
                Ok(next_generation)
            }
        }

        async fn checkpoint(&self, expected_generation: u64) -> Result<u64, StableStateError> {
            let mut state = self.lock();
            let scope = state
                .scopes
                .get_mut(&self.scope)
                .ok_or_else(|| StableStateError::Other("stable scope disappeared".into()))?;
            Self::ensure_active(scope, &self.fence_token)?;
            if scope.generation != expected_generation {
                return Err(StableStateError::GenerationConflict {
                    expected: expected_generation,
                    actual: scope.generation,
                });
            }
            scope.generation = scope
                .generation
                .checked_add(1)
                .ok_or_else(|| StableStateError::Other("test generation overflow".into()))?;
            scope.checkpoints += 1;
            Ok(scope.generation)
        }
    }

    pub(crate) fn test_scope() -> StableScope {
        StableScope::new(Bytes::from_static(b"nfs4-stable-journal-test"))
    }

    fn test_object() -> StableObject {
        StableObject {
            export_id: ExportId(7),
            file_id: 41,
            generation: 3,
        }
    }

    fn client_entry(client_id: u64) -> (JournalKey, JournalRecord) {
        client_entry_with_identity(
            client_id,
            Bytes::from_static(b"client-owner"),
            [4; 8],
            Bytes::from_static(b"nfs/client@example.test"),
            true,
        )
    }

    fn client_entry_with_identity(
        client_id: u64,
        owner: Bytes,
        verifier: [u8; 8],
        canonical_principal: Bytes,
        confirmed: bool,
    ) -> (JournalKey, JournalRecord) {
        (
            JournalKey::Client { client_id },
            JournalRecord::Client(ClientRecord {
                client_id,
                owner,
                verifier,
                canonical_principal,
                confirmed,
            }),
        )
    }

    fn client_batch(client_id: u64) -> PersistBatch {
        let (key, record) = client_entry(client_id);
        PersistBatch::new(vec![JournalMutation::Put { key, record }])
    }

    fn test_state_token(sequence_id: u32, namespace: u32, object_id: u64) -> [u8; 16] {
        let mut token = [0; 16];
        token[..4].copy_from_slice(&sequence_id.to_be_bytes());
        token[4..8].copy_from_slice(&namespace.to_be_bytes());
        token[8..].copy_from_slice(&object_id.to_be_bytes());
        token
    }

    fn test_open_record(state_token: [u8; 16], client_id: u64, object: StableObject) -> JournalRecord {
        JournalRecord::Open(OpenRecord {
            state_token,
            client_id,
            owner: Bytes::from_static(b"open-owner"),
            object,
            share_access: 1,
            share_deny: 0,
            contributions: vec![OpenContributionRecord {
                share_access: 1,
                share_deny: 0,
                count: 1,
            }],
        })
    }

    fn test_lock_record(
        state_token: [u8; 16],
        open_state_token: [u8; 16],
        client_id: u64,
        object: StableObject,
    ) -> JournalRecord {
        JournalRecord::Lock(LockRecord {
            state_token,
            open_state_token,
            client_id,
            owner: Bytes::from_static(b"lock-owner"),
            object,
            ranges: vec![LockRangeRecord {
                offset: 0,
                length: 1,
                write: false,
            }],
        })
    }

    fn delegation_entry(
        state_token: [u8; 16],
        client_id: u64,
        object: StableObject,
        write: bool,
        persistent_object_id: Bytes,
    ) -> (JournalKey, JournalRecord) {
        (
            JournalKey::Delegation { state_token },
            JournalRecord::Delegation(DelegationRecord {
                state_token,
                client_id,
                object,
                write,
                requested_space: if write { 4096 } else { 0 },
                persistent_object_id,
            }),
        )
    }

    fn revocation_entry(state_token: [u8; 16], client_id: u64) -> (JournalKey, JournalRecord) {
        (
            JournalKey::Revocation { state_token },
            JournalRecord::Revocation(RevocationRecord {
                state_token,
                client_id,
                reason: RevocationReason::Conflict,
                revoked_at_unix_seconds: 18,
            }),
        )
    }

    fn migration_snapshot(
        records: Vec<(JournalKey, JournalRecord)>,
        limits: StableJournalLimits,
    ) -> MigrationStableSnapshot {
        let mut records = records
            .iter()
            .map(|(key, record)| stable_record_from_typed(key, record, limits).unwrap())
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            stable_kind_code(left.key.kind)
                .cmp(&stable_kind_code(right.key.kind))
                .then_with(|| left.key.key.as_ref().cmp(right.key.key.as_ref()))
        });
        MigrationStableSnapshot {
            source_generation: 1,
            server_identity: ServerIdentityRecord { identity: [1; 16] },
            boot: BootRecord {
                verifier: [2; 8],
                boot_tag: 3,
                started_at_unix_seconds: 4,
                clean_shutdown: false,
            },
            handle_key: HandleKeyRecord {
                instance_id: [5; 8],
                secret: [6; 32],
            },
            records,
        }
    }

    fn test_migration_capsule(
        transfer_id: [u8; 16],
        records: Vec<(JournalKey, JournalRecord)>,
        limits: StableJournalLimits,
    ) -> MigrationCapsuleRecord {
        let snapshot = migration_snapshot(records, limits);
        MigrationCapsuleRecord {
            transfer_id,
            export_id: test_object().export_id,
            fsid_major: 3,
            fsid_minor: 5,
            source_generation: snapshot.source_generation,
            coordinator_generation: 11,
            coordinator_token_digest: [6; 32],
            bundle_digest: [7; 32],
            server_identity: snapshot.server_identity,
            boot: snapshot.boot,
            handle_key: snapshot.handle_key,
            phase: MigrationPhase::Staged,
            records: snapshot.records,
        }
    }

    #[test]
    fn duplicate_active_state_identity_is_rejected_across_kinds_and_sequences() {
        let object = test_object();
        let open_token = test_state_token(1, 0x1020_3040, 51);
        let duplicate_open_token = test_state_token(9, 0x1020_3040, 51);
        let records = vec![(
            JournalKey::Open {
                state_token: open_token,
            },
            test_open_record(open_token, 37, object),
        )];
        let duplicates = [
            (
                JournalKey::Open {
                    state_token: duplicate_open_token,
                },
                test_open_record(duplicate_open_token, 37, object),
            ),
            (
                JournalKey::Lock {
                    state_token: duplicate_open_token,
                },
                test_lock_record(duplicate_open_token, open_token, 37, object),
            ),
            (
                JournalKey::Delegation {
                    state_token: duplicate_open_token,
                },
                JournalRecord::Delegation(DelegationRecord {
                    state_token: duplicate_open_token,
                    client_id: 37,
                    object,
                    write: false,
                    requested_space: 0,
                    persistent_object_id: Bytes::from_static(b"object-51"),
                }),
            ),
        ];

        for duplicate in duplicates {
            let mut candidate = records.clone();
            candidate.push(duplicate);
            assert_eq!(
                validate_active_state_identities(&candidate).unwrap_err(),
                StableJournalError::Corrupt("duplicate stable state object identity")
            );
        }
    }

    #[test]
    fn lock_ancestry_uses_the_open_identity_and_checks_its_owner_and_object() {
        let object = test_object();
        let open_token = test_state_token(7, 0x1020_3040, 61);
        let earlier_open_token = test_state_token(1, 0x1020_3040, 61);
        let lock_token = test_state_token(3, 0x5060_7080, 62);
        let open = (
            JournalKey::Open {
                state_token: open_token,
            },
            test_open_record(open_token, 37, object),
        );
        let lock_key = JournalKey::Lock {
            state_token: lock_token,
        };
        let valid_lock = test_lock_record(lock_token, earlier_open_token, 37, object);

        validate_active_state_identities(&[open.clone(), (lock_key.clone(), valid_lock)]).unwrap();

        let wrong_client = test_lock_record(lock_token, earlier_open_token, 38, object);
        assert_eq!(
            validate_active_state_identities(&[open.clone(), (lock_key.clone(), wrong_client)]).unwrap_err(),
            StableJournalError::Corrupt("stable lock does not match its open state")
        );

        let wrong_object = test_lock_record(
            lock_token,
            earlier_open_token,
            37,
            StableObject {
                file_id: object.file_id + 1,
                ..object
            },
        );
        assert_eq!(
            validate_active_state_identities(&[open, (lock_key, wrong_object)]).unwrap_err(),
            StableJournalError::Corrupt("stable lock does not match its open state")
        );
    }

    #[test]
    fn ordinary_snapshot_decode_rejects_duplicate_state_object_identities() {
        let limits = StableJournalLimits::default();
        let object = test_object();
        let open_token = test_state_token(1, 0x1020_3040, 71);
        let delegation_token = test_state_token(2, 0x1020_3040, 71);
        let typed = [
            client_entry(37),
            (
                JournalKey::Open {
                    state_token: open_token,
                },
                test_open_record(open_token, 37, object),
            ),
            (
                JournalKey::Delegation {
                    state_token: delegation_token,
                },
                JournalRecord::Delegation(DelegationRecord {
                    state_token: delegation_token,
                    client_id: 37,
                    object,
                    write: true,
                    requested_space: 4096,
                    persistent_object_id: Bytes::from_static(b"object-71"),
                }),
            ),
        ];
        let snapshot = StableSnapshot {
            fence_token: StableFenceToken::new(Bytes::from_static(b"test-fence")),
            generation: 1,
            records: typed
                .iter()
                .map(|(key, record)| stable_record_from_typed(key, record, limits).unwrap())
                .collect(),
        };

        assert_eq!(
            decode_snapshot(&snapshot, limits).err().unwrap(),
            StableJournalError::Corrupt("duplicate stable state object identity")
        );
    }

    #[test]
    fn active_state_identity_validation_handles_a_large_linear_image() {
        const STATE_PAIRS: u64 = 8_192;

        let object = test_object();
        let mut records = Vec::with_capacity((STATE_PAIRS as usize) * 2);
        for object_id in 1..=STATE_PAIRS {
            let open_token = test_state_token(7, 0x1020_3040, object_id);
            let saved_open_token = test_state_token(1, 0x1020_3040, object_id);
            let lock_token = test_state_token(3, 0x5060_7080, object_id);
            records.push((
                JournalKey::Open {
                    state_token: open_token,
                },
                test_open_record(open_token, 37, object),
            ));
            records.push((
                JournalKey::Lock {
                    state_token: lock_token,
                },
                test_lock_record(lock_token, saved_open_token, 37, object),
            ));
        }

        validate_active_state_identities(&records).unwrap();
    }

    #[test]
    fn migration_validation_rejects_duplicate_state_identity_with_different_sequence() {
        let limits = StableJournalLimits::default();
        let object = test_object();
        let open_token = test_state_token(1, 0x1020_3040, 81);
        let delegation_token = test_state_token(9, 0x1020_3040, 81);
        let records = vec![
            client_entry(37),
            (
                JournalKey::Open {
                    state_token: open_token,
                },
                test_open_record(open_token, 37, object),
            ),
            (
                JournalKey::Delegation {
                    state_token: delegation_token,
                },
                JournalRecord::Delegation(DelegationRecord {
                    state_token: delegation_token,
                    client_id: 37,
                    object,
                    write: false,
                    requested_space: 0,
                    persistent_object_id: Bytes::from_static(b"object-81"),
                }),
            ),
        ];
        let snapshot = migration_snapshot(records, limits);

        assert_eq!(
            validate_migration_snapshot(&snapshot, object.export_id, limits).unwrap_err(),
            StableJournalError::Corrupt("duplicate stable state object identity")
        );
    }

    #[test]
    fn durable_delegation_graph_uses_canonical_confirmed_client_identity() {
        let limits = StableJournalLimits::default();
        let object = test_object();
        let first_token = test_state_token(1, 0x1020_3040, 131);
        let second_token = test_state_token(1, 0x1020_3040, 132);
        let first_delegation =
            delegation_entry(first_token, 37, object, false, Bytes::from_static(b"shared-persistent-object"));
        let second_delegation =
            delegation_entry(second_token, 38, object, false, Bytes::from_static(b"shared-persistent-object"));
        let distinct_second_client = client_entry_with_identity(
            38,
            Bytes::from_static(b"distinct-client-owner"),
            [8; 8],
            Bytes::from_static(b"nfs/distinct@example.test"),
            true,
        );
        let distinct_reads = migration_snapshot(
            vec![
                client_entry(37),
                distinct_second_client.clone(),
                first_delegation.clone(),
                second_delegation.clone(),
            ],
            limits,
        );
        validate_migration_snapshot(&distinct_reads, object.export_id, limits).unwrap();

        let aliased_reads = migration_snapshot(
            vec![
                client_entry(37),
                client_entry(38),
                first_delegation.clone(),
                second_delegation,
            ],
            limits,
        );
        assert_eq!(
            validate_migration_snapshot(&aliased_reads, object.export_id, limits).unwrap_err(),
            StableJournalError::Corrupt("conflicting stable delegation ownership graph")
        );

        let write_pair = migration_snapshot(
            vec![
                client_entry(37),
                distinct_second_client,
                first_delegation,
                delegation_entry(second_token, 38, object, true, Bytes::from_static(b"shared-persistent-object")),
            ],
            limits,
        );
        assert_eq!(
            validate_migration_snapshot(&write_pair, object.export_id, limits).unwrap_err(),
            StableJournalError::Corrupt("conflicting stable delegation ownership graph")
        );
    }

    #[tokio::test]
    async fn migration_stage_rejects_an_identity_collision_with_existing_state() {
        let limits = StableJournalLimits::default();
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-existing-state-collision"[..]);
        let mut destination = StableJournal::initialize(store, scope, 100, limits).await.unwrap();
        let object = test_object();
        let existing_open = test_state_token(1, 0x1020_3040, 91);
        destination
            .persist_before_ack(PersistBatch::default().put(client_entry(37).0, client_entry(37).1).put(
                JournalKey::Open {
                    state_token: existing_open,
                },
                test_open_record(existing_open, 37, object),
            ))
            .await
            .unwrap();

        let imported_delegation = test_state_token(9, 0x1020_3040, 91);
        let capsule = test_migration_capsule(
            [0x21; 16],
            vec![
                client_entry(38),
                (
                    JournalKey::Delegation {
                        state_token: imported_delegation,
                    },
                    JournalRecord::Delegation(DelegationRecord {
                        state_token: imported_delegation,
                        client_id: 38,
                        object,
                        write: false,
                        requested_space: 0,
                        persistent_object_id: Bytes::from_static(b"object-91"),
                    }),
                ),
            ],
            limits,
        );

        assert_eq!(
            destination.stage_migration_import(capsule).await.unwrap_err(),
            StableJournalError::MigrationConflict
        );
        assert!(destination.migrations.is_empty());
    }

    #[tokio::test]
    async fn migration_projection_rejects_a_delegation_held_by_an_aliased_client_id() {
        let limits = StableJournalLimits::default();
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-delegation-client-alias"[..]);
        let mut destination = StableJournal::initialize(store, scope, 100, limits).await.unwrap();
        let object = test_object();
        let existing_token = test_state_token(1, 0x1020_3040, 141);
        let (existing_key, existing_delegation) =
            delegation_entry(existing_token, 37, object, false, Bytes::from_static(b"aliased-shared-object"));
        destination
            .persist_before_ack(
                PersistBatch::default()
                    .put(client_entry(37).0, client_entry(37).1)
                    .put(existing_key, existing_delegation),
            )
            .await
            .unwrap();

        let imported_token = test_state_token(1, 0x1020_3040, 142);
        let capsule = test_migration_capsule(
            [0x22; 16],
            vec![
                client_entry(38),
                delegation_entry(imported_token, 38, object, false, Bytes::from_static(b"aliased-shared-object")),
            ],
            limits,
        );

        assert_eq!(
            destination.stage_migration_import(capsule).await.unwrap_err(),
            StableJournalError::MigrationConflict
        );
    }

    #[tokio::test]
    async fn sequential_import_rejects_an_identity_committed_by_the_first_import() {
        let limits = StableJournalLimits::default();
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-sequential-state-collision"[..]);
        let mut destination = StableJournal::initialize(store, scope, 100, limits).await.unwrap();
        let object = test_object();
        let imported_open = test_state_token(1, 0x1020_3040, 101);
        let first = test_migration_capsule(
            [0x31; 16],
            vec![
                client_entry(37),
                (
                    JournalKey::Open {
                        state_token: imported_open,
                    },
                    test_open_record(imported_open, 37, object),
                ),
            ],
            limits,
        );
        assert_eq!(destination.stage_migration_import(first).await.unwrap(), MigrationStageStatus::Staged);
        destination.commit_migration_import([0x31; 16]).await.unwrap();

        let colliding_delegation = test_state_token(7, 0x1020_3040, 101);
        let second = test_migration_capsule(
            [0x32; 16],
            vec![
                client_entry(38),
                (
                    JournalKey::Delegation {
                        state_token: colliding_delegation,
                    },
                    JournalRecord::Delegation(DelegationRecord {
                        state_token: colliding_delegation,
                        client_id: 38,
                        object,
                        write: true,
                        requested_space: 4096,
                        persistent_object_id: Bytes::from_static(b"object-101"),
                    }),
                ),
            ],
            limits,
        );

        assert_eq!(
            destination.stage_migration_import(second).await.unwrap_err(),
            StableJournalError::MigrationConflict
        );
    }

    #[tokio::test]
    async fn migration_commit_revalidates_state_added_after_staging() {
        let limits = StableJournalLimits::default();
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-commit-state-collision"[..]);
        let mut destination = StableJournal::initialize(store, scope, 100, limits).await.unwrap();
        let object = test_object();
        let imported_delegation = test_state_token(7, 0x1020_3040, 111);
        let capsule = test_migration_capsule(
            [0x41; 16],
            vec![
                client_entry(37),
                (
                    JournalKey::Delegation {
                        state_token: imported_delegation,
                    },
                    JournalRecord::Delegation(DelegationRecord {
                        state_token: imported_delegation,
                        client_id: 37,
                        object,
                        write: false,
                        requested_space: 0,
                        persistent_object_id: Bytes::from_static(b"object-111"),
                    }),
                ),
            ],
            limits,
        );
        destination.stage_migration_import(capsule).await.unwrap();

        let colliding_open = test_state_token(9, 0x1020_3040, 111);
        destination
            .persist_before_ack(PersistBatch::default().put(client_entry(38).0, client_entry(38).1).put(
                JournalKey::Open {
                    state_token: colliding_open,
                },
                test_open_record(colliding_open, 38, object),
            ))
            .await
            .unwrap();

        assert_eq!(
            destination.commit_migration_import([0x41; 16]).await.unwrap_err(),
            StableJournalError::MigrationConflict
        );
        let snapshot = destination.session.recover().await.unwrap();
        let decoded = decode_snapshot(&snapshot, limits).unwrap();
        assert!(!decoded
            .records
            .iter()
            .any(|(_, record)| matches!(record, JournalRecord::Delegation(_))));
    }

    #[tokio::test]
    async fn restart_rejects_corrupt_staged_migration_capsules() {
        async fn assert_rejected(
            scope_name: &'static [u8],
            records: Vec<(JournalKey, JournalRecord)>,
            expected: StableJournalError,
        ) {
            let limits = StableJournalLimits::default();
            let store = Arc::new(DurableFakeStore::default());
            let scope = StableScope::new(Bytes::from_static(scope_name));
            let mut journal = StableJournal::initialize(store.clone(), scope.clone(), 100, limits)
                .await
                .unwrap();
            let capsule = test_migration_capsule([0x51; 16], records, limits);
            let mutation = put_mutation(
                &JournalKey::Migration {
                    export_id: capsule.export_id,
                    transfer_id: capsule.transfer_id,
                },
                &JournalRecord::Migration(capsule),
                limits,
            )
            .unwrap();
            // Simulate a corrupt or legacy store which contains a capsule
            // accepted with only per-record validation.
            journal.commit(vec![mutation]).await.unwrap();
            drop(journal);

            assert_eq!(StableJournal::initialize(store, scope, 200, limits).await.err().unwrap(), expected);
        }

        let object = test_object();
        let open_token = test_state_token(1, 0x1020_3040, 121);
        let duplicate_delegation = test_state_token(9, 0x1020_3040, 121);
        assert_rejected(
            b"migration-restart-duplicate-state",
            vec![
                client_entry(37),
                (
                    JournalKey::Open {
                        state_token: open_token,
                    },
                    test_open_record(open_token, 37, object),
                ),
                (
                    JournalKey::Delegation {
                        state_token: duplicate_delegation,
                    },
                    JournalRecord::Delegation(DelegationRecord {
                        state_token: duplicate_delegation,
                        client_id: 37,
                        object,
                        write: false,
                        requested_space: 0,
                        persistent_object_id: Bytes::from_static(b"object-121"),
                    }),
                ),
            ],
            StableJournalError::Corrupt("duplicate stable state object identity"),
        )
        .await;

        let missing_lock = test_state_token(1, 0x5060_7080, 122);
        assert_rejected(
            b"migration-restart-missing-open",
            vec![
                client_entry(37),
                (
                    JournalKey::Lock {
                        state_token: missing_lock,
                    },
                    test_lock_record(missing_lock, test_state_token(1, 0x1020_3040, 122), 37, object),
                ),
            ],
            StableJournalError::Corrupt("stable lock is missing its open state"),
        )
        .await;

        let mismatched_open = test_state_token(1, 0x1020_3040, 123);
        let mismatched_lock = test_state_token(1, 0x5060_7080, 123);
        assert_rejected(
            b"migration-restart-mismatched-open",
            vec![
                client_entry(37),
                client_entry(38),
                (
                    JournalKey::Open {
                        state_token: mismatched_open,
                    },
                    test_open_record(mismatched_open, 37, object),
                ),
                (
                    JournalKey::Lock {
                        state_token: mismatched_lock,
                    },
                    test_lock_record(mismatched_lock, mismatched_open, 38, object),
                ),
            ],
            StableJournalError::Corrupt("stable lock does not match its open state"),
        )
        .await;
    }

    #[tokio::test]
    async fn persist_before_ack_reports_cas_conflicts_without_advancing_local_generation() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let mut journal =
            StableJournal::initialize(store.clone(), scope.clone(), 1_700_000_000, StableJournalLimits::default())
                .await
                .unwrap();
        let expected = journal.generation();
        let actual = store.advance_generation(&scope);

        let error = journal.persist_before_ack(client_batch(17)).await.unwrap_err();

        assert_eq!(error, StableJournalError::CasConflict { expected, actual });
        assert_eq!(journal.generation(), expected);
    }

    #[tokio::test]
    async fn persist_before_ack_reconciles_an_exact_batch_applied_before_an_error() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let limits = StableJournalLimits {
            max_records: 5,
            ..StableJournalLimits::default()
        };
        let mut journal = StableJournal::initialize(store.clone(), scope.clone(), 1_700_000_000, limits)
            .await
            .unwrap();
        let expected = journal.generation();
        store.fail_next_commit_after_apply(&scope);

        let persisted = journal.persist_before_ack(client_batch(17)).await.unwrap();

        assert_eq!(persisted.generation, expected + 1);
        assert_eq!(journal.generation(), expected + 1);
        assert_eq!(
            journal.persist_before_ack(client_batch(23)).await.unwrap_err(),
            StableJournalError::LimitExceeded("stable record count")
        );

        journal
            .persist_before_ack(PersistBatch::new(vec![JournalMutation::Delete {
                key: client_entry(17).0,
            }]))
            .await
            .unwrap();
        journal.persist_before_ack(client_batch(23)).await.unwrap();
    }

    #[tokio::test]
    async fn persist_before_ack_preserves_unchanged_state_after_a_preapply_error() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let mut journal =
            StableJournal::initialize(store.clone(), scope.clone(), 1_700_000_000, StableJournalLimits::default())
                .await
                .unwrap();
        let expected = journal.generation();
        store.fail_next_commit(&scope);

        assert_eq!(
            journal.persist_before_ack(client_batch(17)).await.unwrap_err(),
            StableJournalError::Storage(StableStateError::Other("injected commit failure".into()))
        );
        assert_eq!(journal.generation(), expected);

        let persisted = journal.persist_before_ack(client_batch(17)).await.unwrap();
        assert_eq!(persisted.generation, expected + 1);
    }

    #[tokio::test]
    async fn persist_before_ack_rejects_an_unexpected_state_after_an_ambiguous_error() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let limits = StableJournalLimits::default();
        let mut journal = StableJournal::initialize(store.clone(), scope.clone(), 1_700_000_000, limits)
            .await
            .unwrap();
        let expected = journal.generation();
        let (unexpected_key, unexpected_record) = client_entry(19);
        store.fail_next_commit_after_apply_with_unexpected_record(
            &scope,
            stable_record_from_typed(&unexpected_key, &unexpected_record, limits).unwrap(),
        );

        let error = journal.persist_before_ack(client_batch(17)).await.unwrap_err();

        assert_eq!(
            error,
            StableJournalError::CasConflict {
                expected,
                actual: expected + 1,
            }
        );
        assert_eq!(journal.generation(), expected);
    }

    #[tokio::test]
    async fn persist_before_ack_enforces_the_live_record_limit() {
        let store = Arc::new(DurableFakeStore::default());
        let limits = StableJournalLimits {
            max_records: 5,
            ..StableJournalLimits::default()
        };
        let mut journal = StableJournal::initialize(store, test_scope(), 1_700_000_000, limits)
            .await
            .unwrap();
        journal.persist_before_ack(client_batch(17)).await.unwrap();
        let generation_at_limit = journal.generation();

        assert_eq!(
            journal.persist_before_ack(client_batch(23)).await.unwrap_err(),
            StableJournalError::LimitExceeded("stable record count")
        );
        assert_eq!(journal.generation(), generation_at_limit);

        // Replacing an existing key does not consume another live-record slot.
        journal.persist_before_ack(client_batch(17)).await.unwrap();
        journal
            .persist_before_ack(PersistBatch::new(vec![JournalMutation::Delete {
                key: client_entry(17).0,
            }]))
            .await
            .unwrap();
        journal.persist_before_ack(client_batch(23)).await.unwrap();
    }

    #[tokio::test]
    async fn a_new_scope_session_fences_the_previous_writer() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let mut first =
            StableJournal::initialize(store.clone(), scope.clone(), 1_700_000_000, StableJournalLimits::default())
                .await
                .unwrap();
        let generation = first.generation();
        let _replacement = store.open_scope(scope).await.unwrap();

        assert_eq!(first.persist_before_ack(client_batch(23)).await.unwrap_err(), StableJournalError::Fenced);
        assert_eq!(first.generation(), generation);
    }

    #[tokio::test]
    async fn recovery_distinguishes_unclean_and_clean_shutdowns_and_restores_records() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let mut first = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        first.persist_before_ack(client_batch(29)).await.unwrap();
        let first_boot = first.boot();
        drop(first);

        let mut after_crash =
            StableJournal::initialize(store.clone(), scope.clone(), 200, StableJournalLimits::default())
                .await
                .unwrap();
        assert_eq!(after_crash.recovery().previous_shutdown, PreviousShutdown::Unclean);
        assert_eq!(after_crash.recovery().previous_boot, Some(first_boot));
        assert_eq!(after_crash.recovery().records, vec![client_entry(29)]);
        assert!(!after_crash.boot().clean_shutdown);
        let clean_boot = after_crash.boot();
        after_crash.mark_clean_shutdown().await.unwrap();
        assert!(after_crash.boot().clean_shutdown);
        drop(after_crash);

        let after_clean = StableJournal::initialize(store, scope, 300, StableJournalLimits::default())
            .await
            .unwrap();
        assert_eq!(after_clean.recovery().previous_shutdown, PreviousShutdown::Clean);
        assert_eq!(
            after_clean.recovery().previous_boot,
            Some(BootRecord {
                clean_shutdown: true,
                ..clean_boot
            })
        );
        assert_eq!(after_clean.recovery().records, vec![client_entry(29)]);
    }

    #[tokio::test]
    async fn initialize_sanitizes_legacy_delegations_in_bounded_deterministic_chunks() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"legacy-revocation-cleanup"[..]);
        let default_limits = StableJournalLimits::default();
        let mut first = StableJournal::initialize(store.clone(), scope.clone(), 100, default_limits)
            .await
            .unwrap();
        let object = test_object();
        let revoked_a = test_state_token(1, 0x1020_3040, 201);
        let revoked_b = test_state_token(1, 0x1020_3040, 202);
        let revocation_only = test_state_token(1, 0x1020_3040, 203);
        let orphan = test_state_token(1, 0x1020_3040, 204);
        let unconfirmed = test_state_token(1, 0x1020_3040, 205);
        let retained = test_state_token(1, 0x1020_3040, 206);
        let unconfirmed_client = client_entry_with_identity(
            38,
            Bytes::from_static(b"unconfirmed-owner"),
            [8; 8],
            Bytes::from_static(b"nfs/unconfirmed@example.test"),
            false,
        );
        let legacy_records = vec![
            client_entry(37),
            unconfirmed_client,
            delegation_entry(revoked_a, 37, object, false, Bytes::from_static(b"revoked-object-a")),
            delegation_entry(revoked_b, 37, object, false, Bytes::from_static(b"revoked-object-b")),
            delegation_entry(orphan, 99, object, false, Bytes::from_static(b"orphan-object")),
            delegation_entry(unconfirmed, 38, object, false, Bytes::from_static(b"unconfirmed-object")),
            delegation_entry(retained, 37, object, false, Bytes::from_static(b"retained-object")),
            revocation_entry(revoked_a, 37),
            revocation_entry(revoked_b, 37),
            revocation_entry(revocation_only, 37),
        ];
        first
            .persist_before_ack(PersistBatch::new(
                legacy_records
                    .into_iter()
                    .map(|(key, record)| JournalMutation::Put { key, record })
                    .collect(),
            ))
            .await
            .unwrap();
        let generation_before_restart = first.generation();
        let batch_count_before_restart = store.committed_batches(&scope).len();
        // The first cleanup commit is applied durably but reports an error;
        // initialization must reconcile it and continue with later chunks.
        store.fail_next_delete_commit_after_apply(&scope);
        drop(first);

        let cleanup_limits = StableJournalLimits {
            max_batch_mutations: 2,
            ..default_limits
        };
        let recovered = StableJournal::initialize(store.clone(), scope.clone(), 200, cleanup_limits)
            .await
            .unwrap();

        // One boot mutation plus four cleanup batches for seven obsolete keys.
        assert_eq!(recovered.generation(), generation_before_restart + 5);
        let committed_batches = store.committed_batches(&scope);
        let restart_batches = &committed_batches[batch_count_before_restart..];
        assert_eq!(restart_batches.iter().map(Vec::len).collect::<Vec<_>>(), vec![1, 2, 2, 2, 1]);

        let mut expected_cleanup = vec![
            JournalKey::Revocation { state_token: revoked_a },
            JournalKey::Revocation { state_token: revoked_b },
            JournalKey::Revocation {
                state_token: revocation_only,
            },
            JournalKey::Delegation { state_token: revoked_a },
            JournalKey::Delegation { state_token: revoked_b },
            JournalKey::Delegation { state_token: orphan },
            JournalKey::Delegation {
                state_token: unconfirmed,
            },
        ]
        .into_iter()
        .map(|key| key.encode(cleanup_limits).unwrap())
        .collect::<Vec<_>>();
        expected_cleanup.sort_by(|left, right| {
            stable_kind_code(left.kind)
                .cmp(&stable_kind_code(right.kind))
                .then_with(|| left.key.as_ref().cmp(right.key.as_ref()))
        });
        let actual_cleanup = restart_batches[1..].iter().flatten().cloned().collect::<Vec<_>>();
        assert_eq!(actual_cleanup, expected_cleanup);

        assert!(recovered
            .recovery()
            .records
            .iter()
            .all(|(_, record)| !matches!(record, JournalRecord::Revocation(_))));
        let recovered_delegations = recovered
            .recovery()
            .records
            .iter()
            .filter_map(|(_, record)| match record {
                JournalRecord::Delegation(delegation) => Some(delegation.state_token),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(recovered_delegations, vec![retained]);

        let durable = recovered.session.recover().await.unwrap();
        let durable_keys = durable
            .records
            .iter()
            .map(|record| JournalKey::decode(&record.key, cleanup_limits).unwrap())
            .collect::<HashSet<_>>();
        assert!(expected_cleanup
            .iter()
            .all(|removed| !durable_keys.contains(&JournalKey::decode(removed, cleanup_limits).unwrap())));
    }

    #[tokio::test]
    async fn stable_handle_keys_survive_recovery_and_checkpoint_is_fenced_cas() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = test_scope();
        let mut first = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let server_identity = first.server_identity();
        let handle_key = first.handle_key();
        let original_boot = first.boot();
        let object = ObjectKey {
            file_id: 41,
            generation: 3,
        };
        let handle = first.handle_codec().encode(ExportId(7), object);
        first.mark_clean_shutdown().await.unwrap();
        drop(first);

        let mut recovered =
            StableJournal::initialize(store.clone(), scope.clone(), 200, StableJournalLimits::default())
                .await
                .unwrap();
        assert_eq!(recovered.server_identity(), server_identity);
        assert_eq!(recovered.handle_key(), handle_key);
        assert_ne!(recovered.boot().verifier, original_boot.verifier);
        assert_ne!(recovered.boot().boot_tag, original_boot.boot_tag);
        assert_eq!(recovered.handle_codec().decode(ExportId(7), &handle), Ok(object));

        let before_checkpoint = recovered.generation();
        let checkpoint = recovered.checkpoint().await.unwrap();
        assert_eq!(checkpoint.generation, before_checkpoint + 1);
        assert_eq!(store.checkpoint_count(&scope), 1);
    }

    #[tokio::test]
    async fn migration_stage_is_invisible_until_atomic_commit_and_recovers_handle_identity() {
        let source_store = Arc::new(DurableFakeStore::default());
        let mut source = StableJournal::initialize(
            source_store,
            StableScope::from(&b"migration-source"[..]),
            100,
            StableJournalLimits::default(),
        )
        .await
        .unwrap();
        let source_identity = source.server_identity();
        let source_handle_key = source.handle_key();
        let object = StableObject {
            export_id: ExportId(7),
            file_id: 41,
            generation: 3,
        };
        source
            .persist_before_ack(PersistBatch::new(Vec::new()).put(client_entry(29).0, client_entry(29).1).put(
                JournalKey::Open { state_token: [5; 16] },
                JournalRecord::Open(OpenRecord {
                    state_token: [5; 16],
                    client_id: 29,
                    owner: Bytes::from_static(b"open-owner"),
                    object,
                    share_access: 3,
                    share_deny: 0,
                    contributions: vec![
                        OpenContributionRecord {
                            share_access: 1,
                            share_deny: 0,
                            count: 2,
                        },
                        OpenContributionRecord {
                            share_access: 2,
                            share_deny: 0,
                            count: 1,
                        },
                    ],
                }),
            ))
            .await
            .unwrap();
        let snapshot = source.snapshot_for_migration(ExportId(7)).await.unwrap();
        assert_eq!(snapshot.records.len(), 2);

        let transfer_id = [9; 16];
        let capsule = MigrationCapsuleRecord {
            transfer_id,
            export_id: ExportId(7),
            fsid_major: 3,
            fsid_minor: 5,
            source_generation: snapshot.source_generation,
            coordinator_generation: 11,
            coordinator_token_digest: [6; 32],
            bundle_digest: [7; 32],
            server_identity: snapshot.server_identity,
            boot: snapshot.boot,
            handle_key: snapshot.handle_key,
            phase: MigrationPhase::Staged,
            records: snapshot.records,
        };

        let destination_store = Arc::new(DurableFakeStore::default());
        let destination_scope = StableScope::from(&b"migration-destination"[..]);
        let mut destination = StableJournal::initialize(
            destination_store.clone(),
            destination_scope.clone(),
            200,
            StableJournalLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(destination.stage_migration_import(capsule.clone()).await.unwrap(), MigrationStageStatus::Staged);
        drop(destination);

        let mut after_staging = StableJournal::initialize(
            destination_store.clone(),
            destination_scope.clone(),
            300,
            StableJournalLimits::default(),
        )
        .await
        .unwrap();
        assert!(after_staging.recovery().records.is_empty());
        assert!(after_staging.imported_handle_keys().is_empty());

        let committed = after_staging.commit_migration_import(transfer_id).await.unwrap();
        assert_eq!(committed.export_id, ExportId(7));
        assert_eq!(committed.records.len(), 2);
        drop(after_staging);

        let recovered =
            StableJournal::initialize(destination_store, destination_scope, 400, StableJournalLimits::default())
                .await
                .unwrap();
        assert_eq!(recovered.recovery().records.len(), 2);
        let imported = recovered.imported_handle_keys();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].server_identity, source_identity.identity);
        assert_eq!(imported[0].handle_key, source_handle_key);
    }

    #[tokio::test]
    async fn migration_snapshot_omits_revocations_and_their_shadowed_delegations() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-legacy-revocation-source"[..]);
        let limits = StableJournalLimits::default();
        let mut source = StableJournal::initialize(store, scope, 100, limits).await.unwrap();
        let object = test_object();
        let retained = test_state_token(1, 0x1020_3040, 301);
        let revoked = test_state_token(1, 0x1020_3040, 302);
        let records = vec![
            client_entry(37),
            delegation_entry(retained, 37, object, false, Bytes::from_static(b"migration-retained-object")),
            delegation_entry(revoked, 37, object, false, Bytes::from_static(b"migration-revoked-object")),
            revocation_entry(revoked, 37),
        ];
        source
            .persist_before_ack(PersistBatch::new(
                records
                    .into_iter()
                    .map(|(key, record)| JournalMutation::Put { key, record })
                    .collect(),
            ))
            .await
            .unwrap();

        let snapshot = source.snapshot_for_migration(object.export_id).await.unwrap();
        let typed = decode_transfer_records(&snapshot.records, limits).unwrap();
        assert_eq!(typed.len(), 2);
        assert!(typed
            .iter()
            .any(|(_, record)| matches!(record, JournalRecord::Client(client) if client.client_id == 37)));
        assert!(typed.iter().any(
            |(_, record)| matches!(record, JournalRecord::Delegation(delegation) if delegation.state_token == retained)
        ));
        assert!(typed.iter().all(|(_, record)| {
            !matches!(record, JournalRecord::Revocation(_))
                && !matches!(
                    record,
                    JournalRecord::Delegation(delegation) if delegation.state_token == revoked
                )
        }));
    }

    #[tokio::test]
    async fn legacy_migration_capsule_is_sanitized_before_limits_materialization_and_return() {
        let default_limits = StableJournalLimits::default();
        let compatibility_limits = StableJournalLimits {
            max_records: 8,
            max_batch_mutations: 4,
            ..default_limits
        };
        let object = test_object();
        let retained = test_state_token(1, 0x1020_3040, 311);
        let revoked = test_state_token(1, 0x1020_3040, 312);
        let orphan = test_state_token(1, 0x1020_3040, 313);
        let unconfirmed = test_state_token(1, 0x1020_3040, 314);
        let capsule = test_migration_capsule(
            [0x61; 16],
            vec![
                client_entry(37),
                client_entry_with_identity(
                    38,
                    Bytes::from_static(b"unconfirmed-import-owner"),
                    [8; 8],
                    Bytes::from_static(b"nfs/unconfirmed-import@example.test"),
                    false,
                ),
                delegation_entry(retained, 37, object, false, Bytes::from_static(b"import-retained-object")),
                delegation_entry(revoked, 37, object, false, Bytes::from_static(b"import-revoked-object")),
                delegation_entry(orphan, 99, object, false, Bytes::from_static(b"import-orphan-object")),
                delegation_entry(unconfirmed, 38, object, false, Bytes::from_static(b"import-unconfirmed-object")),
                revocation_entry(revoked, 37),
            ],
            compatibility_limits,
        );

        // Seven legacy records would exceed this four-mutation atomic import,
        // but obsolete records do not participate in any limit.
        let decoded_capsule = match JournalRecord::decode(
            &JournalRecord::Migration(capsule.clone()).encode(compatibility_limits).unwrap(),
            compatibility_limits,
        )
        .unwrap()
        {
            JournalRecord::Migration(capsule) => capsule,
            _ => panic!("migration payload decoded as the wrong record kind"),
        };
        assert_eq!(decoded_capsule.records.len(), 3);
        let recovered = recovery_from_migration_capsule(&capsule, compatibility_limits).unwrap();
        assert_eq!(recovered.records.len(), 3);
        assert!(recovered.records.iter().all(|(_, record)| {
            !matches!(record, JournalRecord::Revocation(_))
                && !matches!(
                    record,
                    JournalRecord::Delegation(delegation)
                        if [revoked, orphan, unconfirmed].contains(&delegation.state_token)
                )
        }));

        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-legacy-revocation-destination"[..]);
        let mut destination = StableJournal::initialize(store.clone(), scope.clone(), 100, default_limits)
            .await
            .unwrap();
        destination.limits = compatibility_limits;
        assert_eq!(destination.stage_migration_import(capsule.clone()).await.unwrap(), MigrationStageStatus::Staged);
        assert_eq!(destination.migrations.get(&capsule.transfer_id).unwrap().records.len(), 3);

        let committed = destination.commit_migration_import(capsule.transfer_id).await.unwrap();
        assert_eq!(committed.records, recovered.records);
        assert!(committed.records.iter().all(|(_, record)| {
            !matches!(record, JournalRecord::Revocation(_))
                && !matches!(
                    record,
                    JournalRecord::Delegation(delegation)
                        if [revoked, orphan, unconfirmed].contains(&delegation.state_token)
                )
        }));
        drop(destination);

        let restarted = StableJournal::initialize(store, scope, 200, compatibility_limits)
            .await
            .unwrap();
        assert_eq!(restarted.recovery().records, recovered.records);
    }

    #[tokio::test]
    async fn migration_import_rejects_conflicting_canonical_state_without_overwrite() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"migration-conflict"[..]);
        let mut destination = StableJournal::initialize(store, scope, 100, StableJournalLimits::default())
            .await
            .unwrap();
        destination.persist_before_ack(client_batch(29)).await.unwrap();

        let conflicting = JournalRecord::Client(ClientRecord {
            client_id: 29,
            owner: Bytes::from_static(b"different-owner"),
            verifier: [8; 8],
            canonical_principal: Bytes::from_static(b"nfs/other@example.test"),
            confirmed: true,
        });
        let limits = StableJournalLimits::default();
        let capsule = MigrationCapsuleRecord {
            transfer_id: [9; 16],
            export_id: ExportId(7),
            fsid_major: 3,
            fsid_minor: 5,
            source_generation: 4,
            coordinator_generation: 11,
            coordinator_token_digest: [6; 32],
            bundle_digest: [7; 32],
            server_identity: ServerIdentityRecord { identity: [2; 16] },
            boot: BootRecord {
                verifier: [3; 8],
                boot_tag: 8,
                started_at_unix_seconds: 1,
                clean_shutdown: false,
            },
            handle_key: HandleKeyRecord {
                instance_id: [4; 8],
                secret: [5; 32],
            },
            phase: MigrationPhase::Staged,
            records: vec![
                stable_record_from_typed(&JournalKey::Client { client_id: 29 }, &conflicting, limits).unwrap(),
            ],
        };

        assert_eq!(
            destination.stage_migration_import(capsule).await.unwrap_err(),
            StableJournalError::MigrationConflict
        );
        assert!(destination.imported_handle_keys().is_empty());
    }

    #[test]
    fn every_typed_key_and_payload_has_a_bounded_canonical_round_trip() {
        let limits = StableJournalLimits::default();
        let object = test_object();
        let cases = vec![
            (
                JournalKey::Schema,
                JournalRecord::Schema(SchemaRecord {
                    version: SCHEMA_VERSION,
                }),
            ),
            (
                JournalKey::ServerIdentity,
                JournalRecord::ServerIdentity(ServerIdentityRecord { identity: [1; 16] }),
            ),
            (
                JournalKey::Boot,
                JournalRecord::Boot(BootRecord {
                    verifier: [2; 8],
                    boot_tag: 9,
                    started_at_unix_seconds: -4,
                    clean_shutdown: false,
                }),
            ),
            (
                JournalKey::HandleKey,
                JournalRecord::HandleKey(HandleKeyRecord {
                    instance_id: [3; 8],
                    secret: [4; 32],
                }),
            ),
            client_entry(37),
            (
                JournalKey::Open { state_token: [5; 16] },
                JournalRecord::Open(OpenRecord {
                    state_token: [5; 16],
                    client_id: 37,
                    owner: Bytes::from_static(b"open-owner"),
                    object,
                    share_access: 3,
                    share_deny: 1,
                    contributions: vec![
                        OpenContributionRecord {
                            share_access: 1,
                            share_deny: 0,
                            count: 1,
                        },
                        OpenContributionRecord {
                            share_access: 2,
                            share_deny: 1,
                            count: 1,
                        },
                    ],
                }),
            ),
            (
                JournalKey::Lock { state_token: [6; 16] },
                JournalRecord::Lock(LockRecord {
                    state_token: [6; 16],
                    open_state_token: [5; 16],
                    client_id: 37,
                    owner: Bytes::from_static(b"lock-owner"),
                    object,
                    ranges: vec![LockRangeRecord {
                        offset: 1024,
                        length: 0,
                        write: true,
                    }],
                }),
            ),
            (
                JournalKey::Delegation { state_token: [7; 16] },
                JournalRecord::Delegation(DelegationRecord {
                    state_token: [7; 16],
                    client_id: 37,
                    object,
                    write: false,
                    requested_space: 4096,
                    persistent_object_id: Bytes::from_static(b"persistent-object-41"),
                }),
            ),
            (
                JournalKey::Revocation { state_token: [8; 16] },
                JournalRecord::Revocation(RevocationRecord {
                    state_token: [8; 16],
                    client_id: 37,
                    reason: RevocationReason::Conflict,
                    revoked_at_unix_seconds: 18,
                }),
            ),
            (
                JournalKey::Replay {
                    client_id: 37,
                    owner_kind: ReplayOwnerKind::Open,
                    owner: Bytes::from_static(b"open-owner"),
                },
                JournalRecord::Replay(ReplayRecord {
                    client_id: 37,
                    owner_kind: ReplayOwnerKind::Open,
                    owner: Bytes::from_static(b"open-owner"),
                    sequence_id: 11,
                    request_digest: [9; 32],
                    reply: Bytes::from_static(b"encoded-reply"),
                    current_object: Some(object),
                    renewal_source: ReplayRenewalSource::StateId { client_id: 37 },
                }),
            ),
        ];

        for (key, record) in cases {
            let stable_key = key.encode(limits).unwrap();
            let payload = record.encode(limits).unwrap();
            assert_eq!(JournalKey::decode(&stable_key, limits).unwrap(), key);
            assert_eq!(JournalRecord::decode(&payload, limits).unwrap(), record);
            validate_key_record(&key, &record).unwrap();
        }
    }

    #[test]
    fn delegation_record_rejects_an_unbounded_persistent_object_identity() {
        let record = JournalRecord::Delegation(DelegationRecord {
            state_token: [7; 16],
            client_id: 37,
            object: test_object(),
            write: true,
            requested_space: 4096,
            persistent_object_id: Bytes::from(vec![1; MAX_DELEGATION_OBJECT_ID_BYTES + 1]),
        });

        assert_eq!(
            record.encode(StableJournalLimits::default()).unwrap_err(),
            StableJournalError::LimitExceeded("stable opaque field")
        );
    }

    #[test]
    fn lock_record_requires_a_bounded_normalized_range_set() {
        let key = JournalKey::Lock { state_token: [9; 16] };
        let record = |ranges| {
            JournalRecord::Lock(LockRecord {
                state_token: [9; 16],
                open_state_token: [8; 16],
                client_id: 37,
                owner: Bytes::from_static(b"lock-owner"),
                object: test_object(),
                ranges,
            })
        };
        assert_eq!(
            stable_record_from_typed(&key, &record(Vec::new()), StableJournalLimits::default()).unwrap_err(),
            StableJournalError::Corrupt("invalid stable lock record")
        );
        assert_eq!(
            stable_record_from_typed(
                &key,
                &record(vec![
                    LockRangeRecord {
                        offset: 0,
                        length: 10,
                        write: true,
                    },
                    LockRangeRecord {
                        offset: 10,
                        length: 10,
                        write: true,
                    },
                ]),
                StableJournalLimits::default(),
            )
            .unwrap_err(),
            StableJournalError::Corrupt("invalid stable lock record")
        );

        let tiny_limits = StableJournalLimits {
            max_payload_bytes: ENCODED_LOCK_RANGE_BYTES * 2,
            ..StableJournalLimits::default()
        };
        assert_eq!(
            record(vec![
                LockRangeRecord {
                    offset: 0,
                    length: 1,
                    write: true,
                },
                LockRangeRecord {
                    offset: 2,
                    length: 1,
                    write: true,
                },
                LockRangeRecord {
                    offset: 4,
                    length: 1,
                    write: true,
                },
            ])
            .encode(tiny_limits)
            .unwrap_err(),
            StableJournalError::LimitExceeded("stable lock range count")
        );
    }
}
