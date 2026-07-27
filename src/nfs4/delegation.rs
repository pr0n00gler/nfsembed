//! Conservative NFSv4.0 delegation state management.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use bytes::Bytes;
use rand::RngCore;
use tokio::sync::Mutex;

use super::callback::{CallbackClientError, CallbackClock, CallbackRpcClient};
use super::stable::{
    DelegationRecord as StableDelegationRecord, JournalKey, JournalRecord, PersistBatch, RecoveredStableState,
    StableJournal, StableObject,
};
use super::types::{Bitmap, FileAttributes, NfsFileHandle, NfsStatus, StateId};
use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};
use crate::server::DelegationPolicy;
use crate::vfs::{
    DelegationEligibility, DelegationKind, DelegationRequest, DelegationReservation, ExportId, NfsError, ObjectKey,
    PersistentObjectId, RequestContext, StableFenceToken, VirtualFileSystem,
};

const PERSISTENT_RECORD_VERSION: u32 = 2;
const MAX_PERSISTENT_OBJECT_ID: usize = 1024;

#[derive(Clone, Debug)]
pub struct DelegationGrantRequest {
    pub context: RequestContext,
    pub object: ObjectKey,
    pub file_handle: NfsFileHandle,
    pub kind: DelegationKind,
    pub requested_space: u64,
    pub callback: Arc<CallbackRpcClient>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationGrant {
    pub state_id: StateId,
    pub client_id: u64,
    pub object: ObjectKey,
    pub kind: DelegationKind,
    pub lease_expires_at: Duration,
    pub persistent_record: Option<PersistentDelegationRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantDenial {
    Disabled,
    CallbackUnreachable,
    BackendIneligible,
    ResourceLimit,
    ExistingConflict,
    PersistentIdentityUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantOutcome {
    Granted(DelegationGrant),
    NotGranted(GrantDenial),
    Delay,
}

/// A durable `CLAIM_DELEGATE_PREV` replacement that has not yet been
/// committed by the surrounding OPEN transaction.
///
/// The replacement delegation is already durable and active so it can be
/// included in the OPEN replay record.  If OPEN persistence fails, the caller
/// must pass this guard to [`DelegationManager::rollback_reclaim`] to restore
/// the exact previous-boot reclaim candidate.
pub(crate) struct PreparedDelegationReclaim {
    grant: DelegationGrant,
    recovered: PersistentDelegationRecord,
}

impl PreparedDelegationReclaim {
    pub(crate) fn grant(&self) -> &DelegationGrant {
        &self.grant
    }
}

pub(crate) enum PreparedReclaimOutcome {
    Prepared(Box<PreparedDelegationReclaim>),
    NotGranted(GrantDenial),
    Delay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentDelegationRecord {
    pub client_id: u64,
    pub export_id: ExportId,
    pub object: ObjectKey,
    pub persistent_object_id: PersistentObjectId,
    pub kind: DelegationKind,
    pub requested_space: u64,
    /// The previous boot's stateid is retained as the stable record identity.
    /// A successful reclaim receives a fresh current-boot stateid.
    pub previous_state_id: StateId,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PersistentDelegationRecord {
    pub fn encode(&self) -> Result<Vec<u8>, PersistentRecordError> {
        let object_id = self.persistent_object_id.as_bytes();
        if object_id.len() > MAX_PERSISTENT_OBJECT_ID {
            return Err(PersistentRecordError::ObjectIdTooLarge(object_id.len()));
        }
        let mut encoder = Encoder::new();
        encoder.write_u32(PERSISTENT_RECORD_VERSION);
        encoder.write_u64(self.client_id);
        encoder.write_u32(self.export_id.0);
        encoder.write_u64(self.object.file_id);
        encoder.write_u64(self.object.generation);
        encoder.write_opaque(object_id)?;
        encoder.write_u32(match self.kind {
            DelegationKind::Read => 0,
            DelegationKind::Write => 1,
        });
        encoder.write_u64(self.requested_space);
        encoder.write_u32(self.previous_state_id.sequence_id);
        encoder.write_fixed(&self.previous_state_id.other);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, PersistentRecordError> {
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u32()?;
        if version != PERSISTENT_RECORD_VERSION {
            return Err(PersistentRecordError::UnsupportedVersion(version));
        }
        let client_id = decoder.read_u64()?;
        let export_id = ExportId(decoder.read_u32()?);
        let object = ObjectKey {
            file_id: decoder.read_u64()?,
            generation: decoder.read_u64()?,
        };
        let object_id = decoder.read_opaque("persistent delegation object ID", MAX_PERSISTENT_OBJECT_ID)?;
        let persistent_object_id =
            PersistentObjectId::new(Bytes::from(object_id)).map_err(|_| PersistentRecordError::InvalidObjectId)?;
        let kind = match decoder.read_u32()? {
            0 => DelegationKind::Read,
            1 => DelegationKind::Write,
            value => return Err(PersistentRecordError::InvalidKind(value)),
        };
        let requested_space = decoder.read_u64()?;
        let previous_state_id = StateId {
            sequence_id: decoder.read_u32()?,
            other: decoder.read_fixed()?,
        };
        decoder.finish()?;
        Ok(Self {
            client_id,
            export_id,
            object,
            persistent_object_id,
            kind,
            requested_space,
            previous_state_id,
        })
    }

    pub fn state_token(&self) -> [u8; 16] {
        state_token(self.previous_state_id)
    }
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum PersistentRecordError {
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("persistent delegation record version {0} is unsupported")]
    UnsupportedVersion(u32),
    #[error("persistent delegation kind {0} is invalid")]
    InvalidKind(u32),
    #[error("persistent delegation object ID is invalid")]
    InvalidObjectId,
    #[error("persistent delegation object ID has {0} bytes")]
    ObjectIdTooLarge(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecallState {
    Active,
    Pending,
    Delivered,
}

struct ActiveDelegation {
    grant: DelegationGrant,
    file_handle: NfsFileHandle,
    callback: Arc<CallbackRpcClient>,
    context: RequestContext,
    reservation: Option<DelegationReservation>,
    capacity: DelegationCapacityPermit,
    recall_state: RecallState,
}

struct RecoveredDelegation {
    record: PersistentDelegationRecord,
    capacity: DelegationCapacityPermit,
}

struct ReclaimRollbackReconciliation {
    current: PersistentDelegationRecord,
    recovered: PersistentDelegationRecord,
    capacity: DelegationCapacityPermit,
}

enum FinalGrantDecision {
    Granted,
    Denied(GrantDenial),
    Delay,
}

#[derive(Default)]
struct DelegationState {
    records: HashMap<[u8; 12], ActiveDelegation>,
    /// Delegations removed from live protocol state while a renewal fence was
    /// held.  Durable deletion and backend reservation release are completed
    /// later, after any all-export fence has been dropped.
    detached_removals: HashMap<[u8; 12], ActiveDelegation>,
    /// Previous-boot records detached by DELEGPURGE. They are removed from
    /// reclaim visibility before durable deletion, so cancellation cannot
    /// expose a stale in-memory reclaim record after stable state changes.
    detached_recovered_removals: HashMap<[u8; 16], RecoveredDelegation>,
    recovered: HashMap<[u8; 16], RecoveredDelegation>,
    reclaim_reconciliation: HashMap<[u8; 16], ReclaimRollbackReconciliation>,
    read_count: usize,
    write_count: usize,
}

impl DelegationState {
    fn has_pending_detached_removals(&self) -> bool {
        !self.detached_removals.is_empty() || !self.detached_recovered_removals.is_empty()
    }
}

#[derive(Default)]
struct DelegationClientStateInner {
    active_delegations: HashMap<u64, usize>,
    callback_path_down: HashSet<u64>,
}

/// Client-wide delegation state shared by every export manager.
///
/// NFSv4 callback reachability is a property of the SETCLIENTID callback
/// endpoint, not of an individual exported filesystem.
#[derive(Default)]
pub(crate) struct DelegationClientState {
    inner: StdMutex<DelegationClientStateInner>,
}

impl DelegationClientState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn delegation_added(&self, client_id: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = inner.active_delegations.entry(client_id).or_default();
        *active = active.saturating_add(1);
    }

    fn delegation_removed(&self, client_id: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(active) = inner.active_delegations.get_mut(&client_id) else {
            return;
        };
        *active = active.saturating_sub(1);
        if *active == 0 {
            inner.active_delegations.remove(&client_id);
            inner.callback_path_down.remove(&client_id);
        }
    }

    fn mark_callback_path_down(&self, client_id: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .callback_path_down
            .insert(client_id);
    }

    fn mark_callback_path_up(&self, client_id: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .callback_path_down
            .remove(&client_id);
    }

    fn callback_path_down(&self, client_id: u64) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .callback_path_down
            .contains(&client_id)
    }
}

struct PendingDelegationRelease {
    id: u64,
    context: RequestContext,
    reservation: DelegationReservation,
    capacity: DelegationCapacityPermit,
}

#[derive(Default)]
struct DelegationResourceState {
    read_in_use: usize,
    write_in_use: usize,
    next_release_id: u64,
    pending_releases: VecDeque<PendingDelegationRelease>,
    reclaims_in_progress: HashSet<[u8; 16]>,
}

struct DelegationResources {
    state: StdMutex<DelegationResourceState>,
    max_read: usize,
    max_write: usize,
}

struct DelegationCapacityPermitInner {
    resources: Weak<DelegationResources>,
    kind: DelegationKind,
    release_queued: AtomicBool,
}

#[derive(Clone)]
struct DelegationCapacityPermit(Arc<DelegationCapacityPermitInner>);

impl Drop for DelegationCapacityPermitInner {
    fn drop(&mut self) {
        let Some(resources) = self.resources.upgrade() else {
            return;
        };
        let mut state = resources.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.kind {
            DelegationKind::Read => state.read_in_use = state.read_in_use.saturating_sub(1),
            DelegationKind::Write => state.write_in_use = state.write_in_use.saturating_sub(1),
        }
    }
}

struct ReclaimAttemptGuard {
    resources: Arc<DelegationResources>,
    token: [u8; 16],
}

struct DelegatedSpaceGuard {
    resources: Arc<DelegationResources>,
    context: Option<RequestContext>,
    reservation: Option<DelegationReservation>,
    capacity: Option<DelegationCapacityPermit>,
}

impl DelegatedSpaceGuard {
    fn new(
        resources: Arc<DelegationResources>,
        context: RequestContext,
        reservation: DelegationReservation,
        capacity: DelegationCapacityPermit,
    ) -> Self {
        Self {
            resources,
            context: Some(context),
            reservation: Some(reservation),
            capacity: Some(capacity),
        }
    }

    fn take_for_active(&mut self) -> (DelegationReservation, DelegationCapacityPermit) {
        (
            self.reservation.take().expect("delegated-space reservation is present"),
            self.capacity.take().expect("delegation capacity is present"),
        )
    }

    fn enqueue(mut self) {
        self.enqueue_inner();
    }

    fn enqueue_inner(&mut self) {
        let (Some(context), Some(reservation), Some(capacity)) =
            (self.context.take(), self.reservation.take(), self.capacity.take())
        else {
            return;
        };
        self.resources.enqueue_release(context, reservation, capacity);
    }
}

impl Drop for DelegatedSpaceGuard {
    fn drop(&mut self) {
        self.enqueue_inner();
    }
}

impl Drop for ReclaimAttemptGuard {
    fn drop(&mut self) {
        self.resources
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reclaims_in_progress
            .remove(&self.token);
    }
}

impl DelegationResources {
    fn new(max_read: usize, max_write: usize) -> Arc<Self> {
        Arc::new(Self {
            state: StdMutex::new(DelegationResourceState::default()),
            max_read,
            max_write,
        })
    }

    fn try_reserve(self: &Arc<Self>, kind: DelegationKind) -> Option<DelegationCapacityPermit> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (in_use, limit) = match kind {
            DelegationKind::Read => (&mut state.read_in_use, self.max_read),
            DelegationKind::Write => (&mut state.write_in_use, self.max_write),
        };
        if *in_use >= limit {
            return None;
        }
        *in_use += 1;
        drop(state);
        Some(DelegationCapacityPermit(Arc::new(DelegationCapacityPermitInner {
            resources: Arc::downgrade(self),
            kind,
            release_queued: AtomicBool::new(false),
        })))
    }

    fn usage(&self, kind: DelegationKind) -> usize {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match kind {
            DelegationKind::Read => state.read_in_use,
            DelegationKind::Write => state.write_in_use,
        }
    }

    fn begin_reclaim(self: &Arc<Self>, token: [u8; 16]) -> Option<ReclaimAttemptGuard> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.reclaims_in_progress.insert(token) {
            return None;
        }
        Some(ReclaimAttemptGuard {
            resources: Arc::clone(self),
            token,
        })
    }

    fn enqueue_release(
        &self,
        context: RequestContext,
        reservation: DelegationReservation,
        capacity: DelegationCapacityPermit,
    ) {
        debug_assert_eq!(capacity.0.kind, DelegationKind::Write);
        if capacity.0.release_queued.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.pending_releases.len() < self.max_write,
            "delegation release outbox exceeded configured write-delegation capacity"
        );
        state.next_release_id = state.next_release_id.wrapping_add(1).max(1);
        let id = state.next_release_id;
        state.pending_releases.push_back(PendingDelegationRelease {
            id,
            context,
            reservation,
            capacity,
        });
    }

    fn release_ids(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_releases
            .iter()
            .map(|release| release.id)
            .collect()
    }

    fn release(&self, id: u64) -> Option<(RequestContext, DelegationReservation)> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_releases
            .iter()
            .find(|release| release.id == id)
            .map(|release| (release.context.clone(), release.reservation.clone()))
    }

    fn complete_release(&self, id: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = state.pending_releases.iter().position(|release| release.id == id) else {
            return false;
        };
        state.pending_releases[index]
            .capacity
            .0
            .release_queued
            .store(false, Ordering::Release);
        let completed = state.pending_releases.remove(index);
        drop(state);
        drop(completed);
        true
    }

    fn pending_releases(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_releases
            .len()
    }
}

/// A parsed delegation recovery image that remains invisible until migration
/// control durably commits the corresponding capsule.
#[derive(Clone, Debug)]
pub(crate) struct PreparedDelegationRecovery {
    export_id: ExportId,
    recovered: HashMap<[u8; 16], PersistentDelegationRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectivePolicy {
    enabled: bool,
    max_read: usize,
    max_write: usize,
    persistent: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PersistentDelegationObject {
    export_id: ExportId,
    persistent_object_id: PersistentObjectId,
}

#[derive(Default)]
struct PersistentDelegationClaims {
    writer: Option<u64>,
    readers: HashSet<u64>,
}

#[derive(Default)]
struct PersistentDelegationConflictIndex {
    objects: HashMap<PersistentDelegationObject, PersistentDelegationClaims>,
}

impl PersistentDelegationConflictIndex {
    /// Adds one durable delegation claim, returning `false` when it would
    /// create an impossible recovery graph.
    ///
    /// Distinct clients may concurrently hold read delegations. A write
    /// delegation is exclusive, and one logical client may never have two
    /// delegation records for the same persistent object.
    fn insert(&mut self, record: &PersistentDelegationRecord) -> bool {
        let claims = self
            .objects
            .entry(PersistentDelegationObject {
                export_id: record.export_id,
                persistent_object_id: record.persistent_object_id.clone(),
            })
            .or_default();
        match record.kind {
            DelegationKind::Read => {
                if claims.writer.is_some() || !claims.readers.insert(record.client_id) {
                    return false;
                }
            },
            DelegationKind::Write => {
                if claims.writer.is_some() || !claims.readers.is_empty() {
                    return false;
                }
                claims.writer = Some(record.client_id);
            },
        }
        true
    }
}

fn persistent_delegation_graph_accepts(
    state: &DelegationState,
    candidate: &PersistentDelegationRecord,
    replacing: Option<&PersistentDelegationRecord>,
) -> bool {
    let replacing_token = replacing.map(PersistentDelegationRecord::state_token);
    let mut conflicts = PersistentDelegationConflictIndex::default();
    for recovered in state.recovered.values() {
        if Some(recovered.record.state_token()) != replacing_token && !conflicts.insert(&recovered.record) {
            return false;
        }
    }
    for active in state.records.values() {
        if let Some(persistent) = active.grant.persistent_record.as_ref() {
            if !conflicts.insert(persistent) {
                return false;
            }
        }
    }
    conflicts.insert(candidate)
}

pub struct DelegationManager {
    state: Mutex<DelegationState>,
    client_state: Arc<DelegationClientState>,
    renewal_fence: Mutex<()>,
    maintenance: Mutex<()>,
    resources: Arc<DelegationResources>,
    pending_reconciliation: AtomicUsize,
    pending_detached_removals: AtomicUsize,
    vfs: Arc<dyn VirtualFileSystem>,
    clock: Arc<dyn CallbackClock>,
    policy: EffectivePolicy,
    lease_duration: Duration,
    boot_tag: u32,
    next_token: AtomicU64,
    stable_journal: Option<Arc<Mutex<StableJournal>>>,
    export_id: Option<ExportId>,
    reservation_scope: StableFenceToken,
}

impl std::fmt::Debug for DelegationManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegationManager")
            .field("policy", &self.policy)
            .field("lease_duration", &self.lease_duration)
            .field("boot_tag", &self.boot_tag)
            .field("durable", &self.stable_journal.is_some())
            .field("export_id", &self.export_id)
            .finish_non_exhaustive()
    }
}

impl DelegationManager {
    #[allow(dead_code)]
    pub fn new(
        vfs: Arc<dyn VirtualFileSystem>,
        policy: DelegationPolicy,
        lease_duration: Duration,
        clock: Arc<dyn CallbackClock>,
    ) -> Result<Self, DelegationError> {
        let mut random = rand::thread_rng();
        let mut boot_tag = random.next_u32();
        while boot_tag == 0 || boot_tag == u32::MAX {
            boot_tag = random.next_u32();
        }
        Self::with_boot_tag(vfs, policy, lease_duration, clock, boot_tag)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_boot_tag(
        vfs: Arc<dyn VirtualFileSystem>,
        policy: DelegationPolicy,
        lease_duration: Duration,
        clock: Arc<dyn CallbackClock>,
        boot_tag: u32,
    ) -> Result<Self, DelegationError> {
        Self::with_boot_tag_and_stable_state(vfs, policy, lease_duration, clock, boot_tag, None, None, None)
    }

    pub(crate) fn owns_stateid_namespace(&self, state_id: StateId) -> bool {
        state_id.other[..4] == self.boot_tag.to_be_bytes()
    }

    /// Serializes the runtime lease decision with delegation renewal and
    /// revocation. Callers spanning both subsystems hold this guard until all
    /// delegation managers have observed the accepted RENEW.
    pub(crate) async fn renewal_fence(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.renewal_fence.lock().await
    }

    /// Returns whether this export still holds delegation state for a
    /// confirmed client incarnation or any of its reclaimable prior-boot
    /// identities.
    pub(crate) async fn has_client_state(&self, client_id: u64, previous_client_ids: &[u64]) -> bool {
        let state = self.state.lock().await;
        let belongs_to_client = |candidate| candidate == client_id || previous_client_ids.contains(&candidate);
        state.records.values().any(|record| belongs_to_client(record.grant.client_id))
            || state
                .recovered
                .values()
                .any(|record| belongs_to_client(record.record.client_id))
            || state
                .reclaim_reconciliation
                .values()
                .any(|item| belongs_to_client(item.recovered.client_id))
    }

    #[cfg(test)]
    pub(crate) fn mark_callback_path_down_for_test(&self, client_id: u64) {
        self.client_state.mark_callback_path_down(client_id);
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_boot_tag_and_stable_state(
        vfs: Arc<dyn VirtualFileSystem>,
        policy: DelegationPolicy,
        lease_duration: Duration,
        clock: Arc<dyn CallbackClock>,
        boot_tag: u32,
        stable_journal: Option<Arc<Mutex<StableJournal>>>,
        recovered: Option<&RecoveredStableState>,
        export_id: Option<ExportId>,
    ) -> Result<Self, DelegationError> {
        Self::with_boot_tag_stable_state_and_scope(
            vfs,
            policy,
            lease_duration,
            clock,
            boot_tag,
            stable_journal,
            recovered,
            export_id,
            StableFenceToken::new(Bytes::copy_from_slice(&boot_tag.to_be_bytes())),
            DelegationClientState::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_boot_tag_stable_state_and_scope(
        vfs: Arc<dyn VirtualFileSystem>,
        policy: DelegationPolicy,
        lease_duration: Duration,
        clock: Arc<dyn CallbackClock>,
        boot_tag: u32,
        stable_journal: Option<Arc<Mutex<StableJournal>>>,
        recovered: Option<&RecoveredStableState>,
        export_id: Option<ExportId>,
        reservation_scope: StableFenceToken,
        client_state: Arc<DelegationClientState>,
    ) -> Result<Self, DelegationError> {
        if reservation_scope.as_bytes().is_empty() {
            return Err(DelegationError::InvalidConfiguration);
        }
        if lease_duration.is_zero() || boot_tag == 0 || boot_tag == u32::MAX {
            return Err(DelegationError::InvalidConfiguration);
        }
        let policy = match policy {
            DelegationPolicy::Disabled => EffectivePolicy {
                enabled: false,
                max_read: 0,
                max_write: 0,
                persistent: false,
            },
            DelegationPolicy::Conservative {
                max_read_delegations,
                max_write_delegations,
                persistent,
            } => {
                if max_read_delegations == 0 || max_write_delegations == 0 {
                    return Err(DelegationError::InvalidConfiguration);
                }
                EffectivePolicy {
                    enabled: true,
                    max_read: max_read_delegations,
                    max_write: max_write_delegations,
                    persistent,
                }
            },
        };
        if policy.persistent && (stable_journal.is_some() != export_id.is_some()) {
            return Err(DelegationError::InvalidConfiguration);
        }
        let parsed_recovered = recovered_delegations(recovered, export_id, policy.max_read, policy.max_write)?;
        if !parsed_recovered.is_empty() && (!policy.enabled || !policy.persistent) {
            return Err(DelegationError::RecoveryConflict);
        }
        if parsed_recovered
            .values()
            .any(|record| delegation_state_identity(record.state_token())[..4] == (!boot_tag).to_be_bytes())
        {
            // A migrated or recovered prior-boot state object must never
            // overlap the namespace used by this incarnation's allocator.
            return Err(DelegationError::RecoveryConflict);
        }
        let resources = DelegationResources::new(policy.max_read, policy.max_write);
        let mut recovered = HashMap::with_capacity(parsed_recovered.len());
        for (token, record) in parsed_recovered {
            let capacity = resources.try_reserve(record.kind).ok_or(DelegationError::RecoveryConflict)?;
            recovered.insert(token, RecoveredDelegation { record, capacity });
        }
        // Managers are per-export but share one journal and boot tag. Reserve
        // the high half of the allocation token for the export so stable
        // delegation keys cannot collide across managers.
        let next_token = export_id.map_or(1, |export_id| (u64::from(export_id.0) << 32) | 1);
        Ok(Self {
            state: Mutex::new(DelegationState {
                recovered,
                ..DelegationState::default()
            }),
            client_state,
            renewal_fence: Mutex::new(()),
            maintenance: Mutex::new(()),
            resources,
            pending_reconciliation: AtomicUsize::new(0),
            pending_detached_removals: AtomicUsize::new(0),
            vfs,
            clock,
            policy,
            lease_duration,
            // Runtime OPEN/LOCK stateids use the recovered boot tag directly.
            // Its complement is a disjoint, equally boot-scoped namespace for
            // delegation stateids, so identical index/generation words can
            // never collide across the two registries.
            boot_tag: !boot_tag,
            next_token: AtomicU64::new(next_token),
            stable_journal,
            export_id,
            reservation_scope,
        })
    }

    /// Parses and bounds a migration recovery image without changing live
    /// delegation state.
    pub(crate) async fn prepare_recovery_import(
        &self,
        recovered: &RecoveredStableState,
    ) -> Result<PreparedDelegationRecovery, DelegationError> {
        let export_id = self.export_id.ok_or(DelegationError::InvalidConfiguration)?;
        let prepared = PreparedDelegationRecovery {
            export_id,
            recovered: recovered_delegations(
                Some(recovered),
                Some(export_id),
                self.policy.max_read,
                self.policy.max_write,
            )?,
        };
        self.validate_recovery_import(&prepared).await?;
        Ok(prepared)
    }

    /// Revalidates a prepared image against live state. Migration control
    /// invokes this immediately before the durable commit while the export is
    /// quiesced.
    pub(crate) async fn validate_recovery_import(
        &self,
        prepared: &PreparedDelegationRecovery,
    ) -> Result<(), DelegationError> {
        let state = self.state.lock().await;
        self.validate_prepared_recovery(&state, prepared)
    }

    /// Makes a previously validated recovery image visible after its durable
    /// migration commit.
    pub(crate) async fn activate_recovery_import(
        &self,
        prepared: PreparedDelegationRecovery,
    ) -> Result<(), DelegationError> {
        let mut state = self.state.lock().await;
        self.validate_prepared_recovery(&state, &prepared)?;
        let mut additions = Vec::new();
        for (token, record) in prepared.recovered {
            if state.recovered.contains_key(&token) {
                continue;
            }
            let capacity = self
                .resources
                .try_reserve(record.kind)
                .ok_or(DelegationError::RecoveryConflict)?;
            additions.push((token, record, capacity));
        }
        for (token, record, capacity) in additions {
            state.recovered.insert(token, RecoveredDelegation { record, capacity });
        }
        Ok(())
    }

    fn validate_prepared_recovery(
        &self,
        state: &DelegationState,
        prepared: &PreparedDelegationRecovery,
    ) -> Result<(), DelegationError> {
        if self.export_id != Some(prepared.export_id)
            || (!prepared.recovered.is_empty() && (!self.policy.enabled || !self.policy.persistent))
            || !state.reclaim_reconciliation.is_empty()
        {
            return Err(DelegationError::InvalidConfiguration);
        }

        let mut state_identities = HashSet::with_capacity(
            state
                .recovered
                .len()
                .saturating_add(state.records.len())
                .saturating_add(prepared.recovered.len()),
        );
        let mut conflicts = PersistentDelegationConflictIndex::default();
        for (token, recovered) in &state.recovered {
            if *token != recovered.record.state_token()
                || recovered.record.export_id != prepared.export_id
                || !state_identities.insert(delegation_state_identity(*token))
                || !conflicts.insert(&recovered.record)
            {
                return Err(DelegationError::RecoveryConflict);
            }
        }
        for active in state.records.values() {
            let Some(persistent) = active.grant.persistent_record.as_ref() else {
                if self.policy.persistent {
                    return Err(DelegationError::RecoveryConflict);
                }
                continue;
            };
            if persistent.export_id != prepared.export_id
                || !state_identities.insert(delegation_state_identity(persistent.state_token()))
                || !conflicts.insert(persistent)
            {
                return Err(DelegationError::RecoveryConflict);
            }
        }

        let mut additional_read = 0usize;
        let mut additional_write = 0usize;
        for (token, imported) in &prepared.recovered {
            if *token != imported.state_token()
                || imported.export_id != prepared.export_id
                || delegation_state_identity(*token)[..4] == self.boot_tag.to_be_bytes()
            {
                return Err(DelegationError::RecoveryConflict);
            }
            if let Some(existing) = state.recovered.get(token) {
                if existing.record != *imported {
                    return Err(DelegationError::RecoveryConflict);
                }
                continue;
            }
            if !state_identities.insert(delegation_state_identity(*token)) || !conflicts.insert(imported) {
                return Err(DelegationError::RecoveryConflict);
            }
            match imported.kind {
                DelegationKind::Read => additional_read += 1,
                DelegationKind::Write => additional_write += 1,
            }
        }

        if self.resources.usage(DelegationKind::Read).saturating_add(additional_read) > self.policy.max_read
            || self.resources.usage(DelegationKind::Write).saturating_add(additional_write) > self.policy.max_write
        {
            return Err(DelegationError::RecoveryConflict);
        }
        Ok(())
    }

    /// Performs callback and backend work without holding the delegation
    /// state lock, then atomically revalidates the grant.
    pub async fn grant(&self, request: DelegationGrantRequest) -> Result<GrantOutcome, DelegationError> {
        self.grant_replacing(request, None).await
    }

    async fn grant_replacing(
        &self,
        request: DelegationGrantRequest,
        replacing: Option<&PersistentDelegationRecord>,
    ) -> Result<GrantOutcome, DelegationError> {
        if !self.policy.enabled {
            return Ok(GrantOutcome::NotGranted(GrantDenial::Disabled));
        }
        if self.export_id.is_some_and(|export_id| export_id != request.context.export_id) {
            return Err(DelegationError::InvalidConfiguration);
        }
        let client_id = request.context.client_id.ok_or(DelegationError::MissingClientId)?;
        self.revoke_expired().await?;

        let reclaim_guard = if let Some(replacing) = replacing {
            match self.resources.begin_reclaim(replacing.state_token()) {
                Some(guard) => Some(guard),
                None => return Ok(GrantOutcome::Delay),
            }
        } else {
            None
        };
        let mut capacity = if let Some(replacing) = replacing {
            let state = self.state.lock().await;
            if state.has_pending_detached_removals() {
                return Ok(GrantOutcome::Delay);
            }
            if !state.reclaim_reconciliation.is_empty() {
                return Ok(GrantOutcome::Delay);
            }
            match state
                .recovered
                .get(&replacing.state_token())
                .filter(|stored| stored.record == *replacing)
            {
                Some(recovered) if recovered.capacity.0.release_queued.load(Ordering::Acquire) => {
                    return Ok(GrantOutcome::Delay);
                },
                Some(recovered) => Some(recovered.capacity.clone()),
                None if self.stable_journal.is_none() => self.resources.try_reserve(request.kind),
                None => return Err(DelegationError::ReclaimMismatch),
            }
        } else {
            self.resources.try_reserve(request.kind)
        };
        if capacity.is_none() {
            return Ok(GrantOutcome::NotGranted(GrantDenial::ResourceLimit));
        }

        {
            let state = self.state.lock().await;
            if state.has_pending_detached_removals() {
                return Ok(GrantOutcome::Delay);
            }
            if !state.reclaim_reconciliation.is_empty() {
                return Ok(GrantOutcome::Delay);
            }
            if let Some(denial) = self.precheck(&state, client_id, request.object, request.kind) {
                return Ok(GrantOutcome::NotGranted(denial));
            }
        }

        if request.callback.probe_once().await.is_err() {
            return Ok(GrantOutcome::NotGranted(GrantDenial::CallbackUnreachable));
        }

        let eligibility = self
            .vfs
            .nfs4_delegation_eligibility(
                &request.context,
                request.object,
                DelegationRequest {
                    kind: request.kind,
                    client_id,
                    requested_space: request.requested_space,
                },
            )
            .await;
        match eligibility {
            Ok(DelegationEligibility::Eligible) => {},
            Ok(DelegationEligibility::Delay) | Err(NfsError::Jukebox) => return Ok(GrantOutcome::Delay),
            Ok(DelegationEligibility::Ineligible) | Err(NfsError::NotSupported) => {
                return Ok(GrantOutcome::NotGranted(GrantDenial::BackendIneligible));
            },
            Err(error) => return Err(DelegationError::Vfs(error)),
        }

        let persistent_object_id = if self.policy.persistent {
            match self.vfs.nfs4_persistent_object_id(&request.context, request.object).await {
                Ok(identity) => Some(identity),
                Err(NfsError::NotSupported) => {
                    return Ok(GrantOutcome::NotGranted(GrantDenial::PersistentIdentityUnavailable));
                },
                Err(error) => return Err(DelegationError::Vfs(error)),
            }
        } else {
            None
        };

        let mut delegated_space = if request.kind == DelegationKind::Write {
            match self
                .vfs
                .nfs4_reserve_delegated_space(
                    &request.context,
                    request.object,
                    request.requested_space,
                    &self.reservation_scope,
                )
                .await
            {
                Ok(reservation) => {
                    let validation = reservation.validate(request.requested_space);
                    let guard = DelegatedSpaceGuard::new(
                        Arc::clone(&self.resources),
                        request.context.clone(),
                        reservation,
                        capacity.take().expect("write delegation capacity is reserved"),
                    );
                    if let Err(error) = validation {
                        guard.enqueue();
                        let _ = self.maintain_cleanup().await;
                        return Err(DelegationError::Vfs(error));
                    }
                    Some(guard)
                },
                Err(NfsError::NotSupported) => {
                    return Ok(GrantOutcome::NotGranted(GrantDenial::BackendIneligible));
                },
                Err(NfsError::Jukebox) => return Ok(GrantOutcome::Delay),
                Err(error) => return Err(DelegationError::Vfs(error)),
            }
        } else {
            None
        };

        let state_id = self.allocate_state_id()?;
        let lease_expires_at = self.clock.now().saturating_add(self.lease_duration);
        let persistent_record = persistent_object_id.map(|persistent_object_id| PersistentDelegationRecord {
            client_id,
            export_id: request.context.export_id,
            object: request.object,
            persistent_object_id,
            kind: request.kind,
            requested_space: request.requested_space,
            previous_state_id: state_id,
        });
        let grant = DelegationGrant {
            state_id,
            client_id,
            object: request.object,
            kind: request.kind,
            lease_expires_at,
            persistent_record: persistent_record.clone(),
        };

        let finalized = {
            let mut state = self.state.lock().await;
            if state.has_pending_detached_removals() {
                Ok(FinalGrantDecision::Delay)
            } else if let Some(denial) = self.precheck(&state, client_id, request.object, request.kind) {
                Ok(FinalGrantDecision::Denied(denial))
            } else if self.stable_journal.is_some()
                && replacing.is_some_and(|record| {
                    state
                        .recovered
                        .get(&record.state_token())
                        .is_none_or(|stored| stored.record != *record)
                })
            {
                Err(DelegationError::ReclaimMismatch)
            } else if persistent_record
                .as_ref()
                .is_some_and(|candidate| !persistent_delegation_graph_accepts(&state, candidate, replacing))
            {
                Ok(FinalGrantDecision::Denied(GrantDenial::ExistingConflict))
            } else {
                match self.persist_grant(persistent_record.as_ref(), replacing).await {
                    Ok(()) => {
                        let (reservation, active_capacity) = match delegated_space.as_mut() {
                            Some(space) => {
                                let (reservation, capacity) = space.take_for_active();
                                (Some(reservation), capacity)
                            },
                            None => (None, capacity.take().expect("read delegation capacity is reserved")),
                        };
                        increment_count(&mut state, request.kind);
                        state.records.insert(
                            state_id.other,
                            ActiveDelegation {
                                grant: grant.clone(),
                                file_handle: request.file_handle.clone(),
                                callback: request.callback.clone(),
                                context: request.context.clone(),
                                reservation,
                                capacity: active_capacity,
                                recall_state: RecallState::Active,
                            },
                        );
                        self.client_state.delegation_added(client_id);
                        if let Some(replacing) = replacing {
                            state.recovered.remove(&replacing.state_token());
                        }
                        Ok(FinalGrantDecision::Granted)
                    },
                    Err(error) => Err(error),
                }
            }
        };

        drop(reclaim_guard);
        match finalized {
            Ok(FinalGrantDecision::Granted) => Ok(GrantOutcome::Granted(grant)),
            Ok(FinalGrantDecision::Denied(denial)) => {
                if let Some(space) = delegated_space {
                    space.enqueue();
                    let _ = self.maintain_cleanup().await;
                }
                Ok(GrantOutcome::NotGranted(denial))
            },
            Ok(FinalGrantDecision::Delay) => {
                if let Some(space) = delegated_space {
                    space.enqueue();
                    let _ = self.maintain_cleanup().await;
                }
                Ok(GrantOutcome::Delay)
            },
            Err(error) => {
                if let Some(space) = delegated_space {
                    space.enqueue();
                    let _ = self.maintain_cleanup().await;
                }
                Err(error)
            },
        }
    }

    /// Validates CLAIM_DELEGATE_CUR against an active current-boot delegation.
    #[cfg(test)]
    pub async fn claim_delegate_current(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        state_id: StateId,
    ) -> Result<DelegationGrant, NfsStatus> {
        let _renewal_fence = self.renewal_fence().await;
        self.revoke_expired_while_fenced().await.map_err(|error| error.status())?;
        self.claim_delegate_current_while_fenced(context, object, state_id).await
    }

    /// Validates CLAIM_DELEGATE_CUR while the caller holds
    /// [`Self::renewal_fence`].  Lease extension is deliberately performed
    /// by the compound executor after every export is fenced.
    pub(crate) async fn claim_delegate_current_while_fenced(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        state_id: StateId,
    ) -> Result<DelegationGrant, NfsStatus> {
        let client_id = context.client_id.ok_or(NfsStatus::StaleClientId)?;
        let state = self.state.lock().await;
        let record = state.records.get(&state_id.other).ok_or(NfsStatus::BadStateId)?;
        validate_state_id(state_id, record.grant.state_id)?;
        if record.grant.client_id != client_id
            || record.grant.object != object
            || record.context.principal != context.principal
        {
            return Err(NfsStatus::BadStateId);
        }
        Ok(record.grant.clone())
    }

    /// Validates a delegation stateid for READ, WRITE, or size-changing
    /// SETATTR and returns the authenticated owning client while the caller
    /// holds [`Self::renewal_fence`].
    pub(crate) async fn validate_io_delegation_while_fenced(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        state_id: StateId,
        access: DelegationKind,
    ) -> Result<u64, NfsStatus> {
        let state = self.state.lock().await;
        let record = state.records.get(&state_id.other).ok_or(NfsStatus::BadStateId)?;
        validate_state_id(state_id, record.grant.state_id)?;
        if record.grant.object != object
            || record.context.principal != context.principal
            || context.client_id.is_some_and(|client_id| client_id != record.grant.client_id)
        {
            return Err(NfsStatus::BadStateId);
        }
        if access == DelegationKind::Write && record.grant.kind != DelegationKind::Write {
            return Err(NfsStatus::OpenMode);
        }
        Ok(record.grant.client_id)
    }

    /// Validates a delegation stateid supplied with a SETATTR that does not
    /// change the file size while the caller holds [`Self::renewal_fence`].
    ///
    /// RFC 7530 section 9.1.4.6 requires the server to accept a valid
    /// delegation stateid for these requests, including a read delegation.
    /// Unlike size-changing SETATTR, this operation is not a write-range
    /// access and therefore must not require a write delegation.
    pub(crate) async fn validate_setattr_delegation_while_fenced(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        state_id: StateId,
    ) -> Result<u64, NfsStatus> {
        let state = self.state.lock().await;
        let record = state.records.get(&state_id.other).ok_or(NfsStatus::BadStateId)?;
        validate_state_id(state_id, record.grant.state_id)?;
        if record.grant.object != object
            || record.context.principal != context.principal
            || context.client_id.is_some_and(|client_id| client_id != record.grant.client_id)
        {
            return Err(NfsStatus::BadStateId);
        }
        Ok(record.grant.client_id)
    }

    /// Extends every active delegation owned by an authenticated client.
    ///
    /// A known failed callback path is reported only after all matching
    /// delegation leases have been extended.  This is the explicit RENEW
    /// exception required by RFC 7530 section 10.4.6.
    pub async fn renew_client(&self, context: &RequestContext, client_id: u64) -> Result<(), NfsStatus> {
        self.renew_client_inner(context, client_id, true).await
    }

    /// Records a lease-renewing stateid operation for `client_id` while the
    /// caller holds [`Self::renewal_fence`].
    ///
    /// RFC 7530 section 10.4.6 excludes stateid operations other than RENEW
    /// from extending delegation leases after callback-path failure.  The
    /// shared runtime lease is renewed by the protocol executor; this method
    /// updates every delegation in this manager only while callbacks remain
    /// usable.
    pub(crate) async fn renew_client_from_stateid_while_fenced(
        &self,
        context: &RequestContext,
        client_id: u64,
    ) -> Result<(), NfsStatus> {
        self.renew_client_inner(context, client_id, false).await
    }

    /// Extends every delegation after a valid clientid operation while the
    /// caller holds [`Self::renewal_fence`].
    ///
    /// RFC 7530 section 10.4.6 limits only operations *taking a stateid*
    /// after callback-path failure.  Valid clientid operations still renew
    /// the known delegation leases, but only RENEW reports
    /// `NFS4ERR_CB_PATH_DOWN` to its caller.
    pub(crate) async fn renew_client_from_clientid_while_fenced(
        &self,
        context: &RequestContext,
        client_id: u64,
    ) -> Result<(), NfsStatus> {
        match self.renew_client_inner(context, client_id, true).await {
            Ok(()) | Err(NfsStatus::CallbackPathDown) => Ok(()),
            Err(status) => Err(status),
        }
    }

    async fn renew_client_inner(
        &self,
        context: &RequestContext,
        client_id: u64,
        renew_after_callback_failure: bool,
    ) -> Result<(), NfsStatus> {
        let next_expiry = self.clock.now().saturating_add(self.lease_duration);
        let mut state = self.state.lock().await;
        if state
            .records
            .values()
            .any(|record| record.grant.client_id == client_id && record.context.principal != context.principal)
        {
            return Err(NfsStatus::ClientIdInUse);
        }
        let callback_path_down = self.client_state.callback_path_down(client_id);
        if !callback_path_down || renew_after_callback_failure {
            for record in state.records.values_mut().filter(|record| record.grant.client_id == client_id) {
                record.grant.lease_expires_at = next_expiry;
            }
        }
        if callback_path_down && renew_after_callback_failure {
            return Err(NfsStatus::CallbackPathDown);
        }
        Ok(())
    }

    /// Obtains size/change metadata held under an active write delegation.
    /// Any unreclaimed previous-boot delegation on the object keeps those
    /// attributes behind the grace barrier until reclaim or revocation.
    pub async fn delegated_getattr(
        &self,
        object: ObjectKey,
        requested_attributes: Bitmap,
    ) -> Result<Option<(FileAttributes, u64)>, NfsStatus> {
        self.revoke_expired().await.map_err(|error| error.status())?;
        let selected = {
            let state = self.state.lock().await;
            if state.recovered.values().any(|record| record.record.object == object)
                || state
                    .reclaim_reconciliation
                    .values()
                    .any(|item| item.recovered.object == object || item.current.object == object)
            {
                return Err(NfsStatus::Grace);
            }
            state
                .records
                .values()
                .find(|record| record.grant.object == object && record.grant.kind == DelegationKind::Write)
                .map(|record| {
                    (
                        record.grant.state_id.other,
                        record.grant.client_id,
                        record.file_handle.clone(),
                        record.callback.clone(),
                        record.grant.lease_expires_at,
                    )
                })
        };
        let Some((state_key, client_id, file_handle, callback, lease_expires_at)) = selected else {
            return Ok(None);
        };
        let remaining = lease_expires_at.saturating_sub(self.clock.now());
        let callback_deadline = callback.deadline_after(remaining.min(callback.attempt_timeout()));
        let attributes = callback
            .getattr_until(file_handle, requested_attributes, callback_deadline)
            .await
            .map_err(|_| NfsStatus::Delay)?;
        let mut state = self.state.lock().await;
        let Some(record) = state.records.get_mut(&state_key) else {
            return Ok(None);
        };
        record.grant.lease_expires_at = self.clock.now().saturating_add(self.lease_duration);
        self.client_state.mark_callback_path_up(client_id);
        Ok(Some((attributes, client_id)))
    }

    /// Validates a durable CLAIM_DELEGATE_PREV record and performs a fresh
    /// conservative grant. Grace/reclaim admission remains the runtime's
    /// responsibility.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn reclaim_previous(
        &self,
        request: DelegationGrantRequest,
        recovered: &PersistentDelegationRecord,
    ) -> Result<GrantOutcome, DelegationError> {
        match self.prepare_reclaim_previous(request, recovered).await? {
            PreparedReclaimOutcome::Prepared(prepared) => Ok(GrantOutcome::Granted(Self::commit_reclaim(prepared))),
            PreparedReclaimOutcome::NotGranted(denial) => Ok(GrantOutcome::NotGranted(denial)),
            PreparedReclaimOutcome::Delay => Ok(GrantOutcome::Delay),
        }
    }

    /// Prepares a durable delegation reclaim for inclusion in OPEN.
    ///
    /// The caller must either commit the guard after OPEN's stable-state
    /// transaction succeeds or roll it back if OPEN fails.
    pub(crate) async fn prepare_reclaim_previous(
        &self,
        mut request: DelegationGrantRequest,
        recovered: &PersistentDelegationRecord,
    ) -> Result<PreparedReclaimOutcome, DelegationError> {
        if !self.policy.persistent {
            return Ok(PreparedReclaimOutcome::NotGranted(GrantDenial::Disabled));
        }
        let client_id = request.context.client_id.ok_or(DelegationError::MissingClientId)?;
        // A durable server allocates client IDs from a new boot epoch. The
        // caller must admit the current client through the runtime's recovered
        // client-identity/grace checks; membership in `state.recovered` below
        // proves that `recovered.client_id` is an authentic previous-boot ID.
        if (self.stable_journal.is_none() && recovered.client_id != client_id)
            || recovered.export_id != request.context.export_id
            || recovered.object != request.object
            || recovered.kind != request.kind
            || recovered.requested_space != request.requested_space
        {
            return Err(DelegationError::ReclaimMismatch);
        }
        let current_identity = self
            .vfs
            .nfs4_persistent_object_id(&request.context, request.object)
            .await
            .map_err(DelegationError::Vfs)?;
        if current_identity != recovered.persistent_object_id {
            return Err(DelegationError::ReclaimMismatch);
        }
        request.kind = recovered.kind;
        match self.grant_replacing(request, Some(recovered)).await? {
            GrantOutcome::Granted(grant) => Ok(PreparedReclaimOutcome::Prepared(Box::new(PreparedDelegationReclaim {
                grant,
                recovered: recovered.clone(),
            }))),
            GrantOutcome::NotGranted(denial) => Ok(PreparedReclaimOutcome::NotGranted(denial)),
            GrantOutcome::Delay => Ok(PreparedReclaimOutcome::Delay),
        }
    }

    /// Commits a prepared reclaim after OPEN has become durable.
    pub(crate) fn commit_reclaim(prepared: Box<PreparedDelegationReclaim>) -> DelegationGrant {
        prepared.grant
    }

    /// Restores the previous-boot delegation after OPEN persistence fails.
    ///
    /// Stable storage is repaired before the replacement becomes reclaimable
    /// again in memory. An indeterminate repair is retained as bounded
    /// reconciliation work and fences new delegation grants until maintenance
    /// confirms the exact predecessor record is durable.
    pub(crate) async fn rollback_reclaim(
        &self,
        prepared: Box<PreparedDelegationReclaim>,
    ) -> Result<(), DelegationError> {
        let (removed, reconciliation_token) = {
            let mut state = self.state.lock().await;
            let record = state
                .records
                .get(&prepared.grant.state_id.other)
                .ok_or(DelegationError::ReclaimMismatch)?;
            if record.grant != prepared.grant {
                return Err(DelegationError::ReclaimMismatch);
            }
            let current = record
                .grant
                .persistent_record
                .as_ref()
                .ok_or(DelegationError::InvalidConfiguration)?
                .clone();
            let removed = remove_record(&mut state, prepared.grant.state_id.other, &self.client_state)
                .expect("validated prepared delegation exists");
            let token = current.state_token();
            let previous = state.reclaim_reconciliation.insert(
                token,
                ReclaimRollbackReconciliation {
                    current,
                    recovered: prepared.recovered,
                    capacity: removed.capacity.clone(),
                },
            );
            debug_assert!(previous.is_none());
            if previous.is_none() {
                self.pending_reconciliation.fetch_add(1, Ordering::Release);
            }
            (removed, token)
        };
        self.enqueue_record_release(removed);
        let progress = self.maintain_cleanup().await;
        if self
            .state
            .lock()
            .await
            .reclaim_reconciliation
            .contains_key(&reconciliation_token)
        {
            return Err(progress
                .first_error
                .unwrap_or_else(|| DelegationError::stable("delegation reclaim rollback remains indeterminate")));
        }
        Ok(())
    }

    /// Returns the durable, previous-boot records that remain eligible for a
    /// reclaim attempt. These are candidates rather than live delegations:
    /// callback reachability and backend reservations are re-established by
    /// [`Self::reclaim_previous`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn recovered_delegations(&self) -> Vec<PersistentDelegationRecord> {
        let state = self.state.lock().await;
        let mut records = state.recovered.values().map(|record| record.record.clone()).collect::<Vec<_>>();
        records.sort_by_key(PersistentDelegationRecord::state_token);
        records
    }

    /// Finds one previous-boot delegation by the stable client and object
    /// identities carried by the recovery image.
    pub async fn recovered_delegation(
        &self,
        previous_client_id: u64,
        persistent_object_id: &PersistentObjectId,
        kind: DelegationKind,
    ) -> Option<PersistentDelegationRecord> {
        let state = self.state.lock().await;
        state
            .recovered
            .values()
            .find(|record| {
                record.record.client_id == previous_client_id
                    && record.record.persistent_object_id == *persistent_object_id
                    && record.record.kind == kind
            })
            .map(|record| record.record.clone())
    }

    /// Durably revokes every previous-boot reclaim candidate. The server can
    /// call this when its grace period closes so unreclaimed records cannot be
    /// resurrected by a later restart.
    pub async fn revoke_unreclaimed(&self, _reason: RevocationReason) -> Result<usize, DelegationError> {
        let mut state = self.state.lock().await;
        let keys = state.recovered.keys().copied().collect::<Vec<_>>();
        let mut revoked = 0usize;
        for key in keys {
            let Some(record) = state.recovered.get(&key).map(|record| record.record.clone()) else {
                continue;
            };
            self.persist_delegation_deletes(std::slice::from_ref(&record)).await?;
            state.recovered.remove(&key);
            revoked = revoked.saturating_add(1);
        }
        Ok(revoked)
    }

    /// Marks active conflicting delegations for recall and returns DELAY.
    /// An unreclaimed conflicting delegation has no callback path yet and
    /// returns GRACE instead. The caller should execute each returned work item
    /// outside the COMPOUND state lock with [`Self::execute_recall`].
    pub async fn begin_conflict(
        &self,
        object: ObjectKey,
        requesting_client: u64,
        access: DelegationKind,
        truncate: bool,
    ) -> Result<ConflictResult, DelegationError> {
        self.revoke_expired().await?;
        let mut state = self.state.lock().await;
        let recovered_conflict = state
            .recovered
            .values()
            .any(|record| record.record.object == object && delegation_conflicts(record.record.kind, access))
            || state
                .reclaim_reconciliation
                .values()
                .any(|item| item.recovered.object == object || item.current.object == object);
        let mut recalls = Vec::new();
        let mut conflict = false;
        for record in state.records.values_mut() {
            if record.grant.object != object
                || record.grant.client_id == requesting_client
                || !delegation_conflicts(record.grant.kind, access)
            {
                continue;
            }
            conflict = true;
            if record.recall_state == RecallState::Active {
                record.recall_state = RecallState::Pending;
                recalls.push(PendingRecall {
                    state_key: record.grant.state_id.other,
                    state_id: record.grant.state_id,
                    truncate,
                    file_handle: record.file_handle.clone(),
                    callback: record.callback.clone(),
                    lease_expires_at: record.grant.lease_expires_at,
                });
            }
        }
        Ok(ConflictResult {
            status: if recovered_conflict {
                NfsStatus::Grace
            } else if conflict {
                NfsStatus::Delay
            } else {
                NfsStatus::Ok
            },
            recalls,
        })
    }

    /// Delivers one recall without holding manager state. A client that
    /// acknowledges CB_RECALL retains the delegation until DELEGRETURN; a
    /// callback path that remains unusable through lease expiry is revoked.
    pub async fn execute_recall(&self, recall: PendingRecall) -> Result<RecallOutcome, DelegationError> {
        let mut attempted_expiry = recall.lease_expires_at;
        loop {
            // Callback clocks may use a different monotonic origin from the
            // manager clock. Translate the manager's absolute expiry into a
            // remaining duration before handing it to the callback client.
            let remaining_lease = attempted_expiry.saturating_sub(self.clock.now());
            let callback_expiry = recall.callback.deadline_after(remaining_lease);
            let result = recall
                .callback
                .recall_until(recall.state_id, recall.truncate, recall.file_handle.clone(), callback_expiry)
                .await;
            match result {
                Ok(()) => {
                    let mut state = self.state.lock().await;
                    let Some(record) = state.records.get_mut(&recall.state_key) else {
                        return Ok(RecallOutcome::AlreadyReturned);
                    };
                    if record.grant.state_id != recall.state_id {
                        return Ok(RecallOutcome::AlreadyReturned);
                    }
                    match record.recall_state {
                        RecallState::Pending => {
                            let client_id = record.grant.client_id;
                            record.recall_state = RecallState::Delivered;
                            self.client_state.mark_callback_path_up(client_id);
                            return Ok(RecallOutcome::Delivered);
                        },
                        RecallState::Delivered => return Ok(RecallOutcome::Delivered),
                        RecallState::Active => return Ok(RecallOutcome::AlreadyReturned),
                    }
                },
                Err(callback_error) => {
                    enum FailureAction {
                        Retry(Duration),
                        AlreadyReturned,
                        Delivered,
                        Revoked(Box<ActiveDelegation>),
                    }

                    let renewal_fence = self.renewal_fence.lock().await;
                    let action = {
                        let mut state = self.state.lock().await;
                        let Some(record) = state.records.get(&recall.state_key) else {
                            return Ok(RecallOutcome::AlreadyReturned);
                        };
                        if record.grant.state_id != recall.state_id {
                            return Ok(RecallOutcome::AlreadyReturned);
                        }
                        match record.recall_state {
                            RecallState::Delivered => FailureAction::Delivered,
                            RecallState::Active => FailureAction::AlreadyReturned,
                            RecallState::Pending => {
                                let client_id = record.grant.client_id;
                                let live_expiry = record.grant.lease_expires_at;
                                if callback_error_indicates_path_down(&callback_error) {
                                    self.client_state.mark_callback_path_down(client_id);
                                }
                                if live_expiry > attempted_expiry {
                                    FailureAction::Retry(live_expiry)
                                } else {
                                    let record = state
                                        .records
                                        .get(&recall.state_key)
                                        .expect("validated recalled delegation exists");
                                    self.persist_active_removal(record, Some(RevocationReason::LeaseExpired))
                                        .await?;
                                    let removed = remove_record(&mut state, recall.state_key, &self.client_state)
                                        .expect("validated recalled delegation exists");
                                    FailureAction::Revoked(Box::new(removed))
                                }
                            },
                        }
                    };
                    drop(renewal_fence);

                    match action {
                        FailureAction::Retry(live_expiry) => attempted_expiry = live_expiry,
                        FailureAction::AlreadyReturned => return Ok(RecallOutcome::AlreadyReturned),
                        FailureAction::Delivered => return Ok(RecallOutcome::Delivered),
                        FailureAction::Revoked(record) => {
                            let record = *record;
                            let revoked = revoked_delegation(&record, RevocationReason::LeaseExpired);
                            self.release_record(record).await;
                            return Ok(RecallOutcome::Revoked {
                                callback_error,
                                revoked: Some(revoked),
                            });
                        },
                    }
                },
            }
        }
    }

    pub async fn delegreturn(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        state_id: StateId,
    ) -> Result<(), DelegationError> {
        let renewal_fence = self.renewal_fence.lock().await;
        {
            let mut state = self.state.lock().await;
            let record = state
                .records
                .get(&state_id.other)
                .ok_or(DelegationError::Status(NfsStatus::BadStateId))?;
            validate_state_id(state_id, record.grant.state_id).map_err(DelegationError::Status)?;
            if record.grant.object != object
                || record.context.principal != context.principal
                || context.client_id.is_some_and(|client_id| client_id != record.grant.client_id)
            {
                return Err(DelegationError::Status(NfsStatus::BadStateId));
            }
            let removed =
                remove_record(&mut state, state_id.other, &self.client_state).expect("validated delegation exists");
            assert!(
                state.detached_removals.insert(state_id.other, removed).is_none(),
                "a live delegation may be detached only once"
            );
            // Publish the pending count in the same critical section as the
            // outbox insertion.  A maintenance pass can otherwise observe
            // and durably remove the record before this increment, leaving a
            // stale count that pins grace mode forever.
            self.pending_detached_removals.fetch_add(1, Ordering::Release);
        }
        drop(renewal_fence);
        self.finalize_detached_removals().await?;
        Ok(())
    }

    /// Authenticates a DELEGRETURN stateid without removing its delegation.
    ///
    /// The protocol executor uses the returned client ID to renew the shared
    /// NFSv4 client lease while holding [`Self::renewal_fence`], then invokes
    /// [`Self::delegreturn`] with that ID in its request context.  Keeping the
    /// record live across those steps prevents a concurrent recall-expiry path
    /// from racing lease renewal with delegation removal.
    pub async fn validate_delegreturn(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        state_id: StateId,
    ) -> Result<u64, DelegationError> {
        let state = self.state.lock().await;
        let record = state
            .records
            .get(&state_id.other)
            .ok_or(DelegationError::Status(NfsStatus::BadStateId))?;
        validate_state_id(state_id, record.grant.state_id).map_err(DelegationError::Status)?;
        if record.grant.object != object
            || record.context.principal != context.principal
            || context.client_id.is_some_and(|client_id| client_id != record.grant.client_id)
        {
            return Err(DelegationError::Status(NfsStatus::BadStateId));
        }
        Ok(record.grant.client_id)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn delegpurge(&self, context: &RequestContext, client_id: u64) -> Result<usize, DelegationError> {
        self.delegpurge_with_recovered_client_ids(context, client_id, &[]).await
    }

    /// Purges current-boot state plus durable state owned by authenticated
    /// predecessor client IDs. The runtime must only pass IDs established by
    /// its client-recovery mapping for `current_client_id`.
    pub(crate) async fn delegpurge_with_recovered_client_ids(
        &self,
        context: &RequestContext,
        current_client_id: u64,
        previous_client_ids: &[u64],
    ) -> Result<usize, DelegationError> {
        let renewal_fence = self.renewal_fence.lock().await;
        let (active_count, recovered) = {
            let mut state = self.state.lock().await;
            if state.records.values().any(|record| {
                record.grant.client_id == current_client_id && record.context.principal != context.principal
            }) {
                return Err(DelegationError::Status(NfsStatus::ClientIdInUse));
            }
            let keys: Vec<_> = state
                .records
                .iter()
                .filter_map(|(key, record)| (record.grant.client_id == current_client_id).then_some(*key))
                .collect();
            let active_count = keys.len();
            let recovered_keys = state
                .recovered
                .iter()
                .filter_map(|(key, record)| {
                    (record.record.client_id == current_client_id
                        || previous_client_ids.contains(&record.record.client_id))
                    .then_some(*key)
                })
                .collect::<Vec<_>>();
            let recovered = recovered_keys
                .iter()
                .filter_map(|key| state.recovered.get(key).map(|record| (*key, record.record.clone())))
                .collect::<Vec<_>>();
            for key in keys {
                let removed =
                    remove_record(&mut state, key, &self.client_state).expect("selected live delegation exists");
                assert!(
                    state.detached_removals.insert(key, removed).is_none(),
                    "a live delegation may be detached only once"
                );
            }
            for (key, expected) in &recovered {
                let removed = state.recovered.remove(key).expect("selected recovered delegation exists");
                assert_eq!(removed.record, *expected, "recovered delegation changed while being detached");
                assert!(
                    state.detached_recovered_removals.insert(*key, removed).is_none(),
                    "a recovered delegation may be detached only once"
                );
            }
            self.pending_detached_removals
                .fetch_add(active_count.saturating_add(recovered.len()), Ordering::Release);
            (active_count, recovered)
        };
        drop(renewal_fence);
        self.finalize_detached_removals().await?;
        Ok(active_count.saturating_add(recovered.len()))
    }

    pub async fn revoke_expired(&self) -> Result<Vec<RevokedDelegation>, DelegationError> {
        let _renewal_fence = self.renewal_fence.lock().await;
        let revoked = self.revoke_expired_while_fenced().await?;
        drop(_renewal_fence);
        // Persistence and VFS cleanup intentionally occur after releasing
        // the renewal fence.  A detached outbox record cannot be renewed,
        // while unrelated exports remain free to make lease progress.
        // A prior fenced operation may already have detached an expired
        // record.  Drain every pending durable tombstone before allowing a
        // new grant or conflicting backend work to regard that delegation as
        // revoked, even when this pass found no additional expiry.
        self.finalize_detached_removals().await?;
        Ok(revoked)
    }

    /// Revokes expired delegations while the caller holds
    /// [`Self::renewal_fence`].
    pub(crate) async fn revoke_expired_while_fenced(&self) -> Result<Vec<RevokedDelegation>, DelegationError> {
        let now = self.clock.now();
        let mut state = self.state.lock().await;
        let keys = state
            .records
            .iter()
            .filter_map(|(key, record)| (record.grant.lease_expires_at <= now).then_some(*key))
            .collect::<Vec<_>>();
        let revoked = keys
            .into_iter()
            .filter_map(|key| detach_record(&mut state, key, &self.client_state))
            .collect::<Vec<_>>();
        self.pending_detached_removals.fetch_add(revoked.len(), Ordering::Release);
        Ok(revoked)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn active_counts(&self) -> (usize, usize) {
        let state = self.state.lock().await;
        (state.read_count, state.write_count)
    }

    fn precheck(
        &self,
        state: &DelegationState,
        client_id: u64,
        object: ObjectKey,
        kind: DelegationKind,
    ) -> Option<GrantDenial> {
        let at_limit = match kind {
            DelegationKind::Read => state.read_count >= self.policy.max_read,
            DelegationKind::Write => state.write_count >= self.policy.max_write,
        };
        if at_limit {
            return Some(GrantDenial::ResourceLimit);
        }
        let conflict = state.records.values().any(|record| {
            record.grant.object == object
                && (record.grant.client_id == client_id
                    || delegation_conflicts(record.grant.kind, kind)
                    || delegation_conflicts(kind, record.grant.kind))
        });
        conflict.then_some(GrantDenial::ExistingConflict)
    }

    fn allocate_state_id(&self) -> Result<StateId, DelegationError> {
        let token = self
            .next_token
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if current == 0 || current == u64::MAX {
                    return None;
                }
                if let Some(export_id) = self.export_id {
                    let export_prefix = u64::from(export_id.0);
                    if current >> 32 != export_prefix || current as u32 == u32::MAX {
                        return None;
                    }
                }
                current.checked_add(1)
            })
            .map_err(|_| DelegationError::StateIdExhausted)?;
        let mut other = [0; 12];
        other[..4].copy_from_slice(&self.boot_tag.to_be_bytes());
        other[4..].copy_from_slice(&token.to_be_bytes());
        Ok(StateId { sequence_id: 1, other })
    }

    async fn persist_grant(
        &self,
        record: Option<&PersistentDelegationRecord>,
        replacing: Option<&PersistentDelegationRecord>,
    ) -> Result<(), DelegationError> {
        let Some(journal) = &self.stable_journal else {
            return Ok(());
        };
        let record = record.ok_or(DelegationError::InvalidConfiguration)?;
        let stable = stable_delegation_record(record);
        let mut batch = PersistBatch::default().put(
            JournalKey::Delegation {
                state_token: record.state_token(),
            },
            JournalRecord::Delegation(stable),
        );
        if let Some(replacing) = replacing {
            batch = batch.delete(JournalKey::Delegation {
                state_token: replacing.state_token(),
            });
        }
        journal
            .lock()
            .await
            .persist_before_ack(batch)
            .await
            .map(|_| ())
            .map_err(DelegationError::stable)
    }

    async fn persist_reclaim_rollback(
        &self,
        current: &PersistentDelegationRecord,
        recovered: &PersistentDelegationRecord,
    ) -> Result<(), DelegationError> {
        let Some(journal) = &self.stable_journal else {
            return Ok(());
        };
        let batch = PersistBatch::default()
            .put(
                JournalKey::Delegation {
                    state_token: recovered.state_token(),
                },
                JournalRecord::Delegation(stable_delegation_record(recovered)),
            )
            .delete(JournalKey::Delegation {
                state_token: current.state_token(),
            });
        journal
            .lock()
            .await
            .persist_before_ack(batch)
            .await
            .map(|_| ())
            .map_err(DelegationError::stable)
    }

    async fn persist_delegation_deletes(&self, records: &[PersistentDelegationRecord]) -> Result<(), DelegationError> {
        let Some(journal) = &self.stable_journal else {
            return Ok(());
        };
        if records.is_empty() {
            return Ok(());
        }
        let batch = records.iter().fold(PersistBatch::default(), |batch, record| {
            batch.delete(JournalKey::Delegation {
                state_token: record.state_token(),
            })
        });
        journal
            .lock()
            .await
            .persist_before_ack(batch)
            .await
            .map(|_| ())
            .map_err(DelegationError::stable)
    }

    async fn persist_active_removal(
        &self,
        record: &ActiveDelegation,
        _reason: Option<RevocationReason>,
    ) -> Result<(), DelegationError> {
        if self.stable_journal.is_none() {
            return Ok(());
        }
        let persistent = record
            .grant
            .persistent_record
            .as_ref()
            .ok_or(DelegationError::InvalidConfiguration)?;
        // Stable state is a fenced positive-set image, not an event log.
        // Removing the exact delegation key is the durable revocation:
        // recovery and CLAIM_DELEGATE_PREV can reclaim only keys that remain.
        self.persist_delegation_deletes(std::slice::from_ref(persistent)).await
    }

    /// Commits detached delegation removals to stable state and queues their
    /// backend releases.  The outbox remains intact on a durable failure, so
    /// cancellation or a retry cannot resurrect a delegation that was already
    /// removed from live protocol state.
    pub(crate) async fn finalize_detached_removals(&self) -> Result<(), DelegationError> {
        // Most maintenance passes are for existing backend-release or
        // reconciliation work. Do not consume one of those retries merely
        // because this caller had no newly detached delegation to finalize.
        let state = self.state.lock().await;
        let empty = state.detached_removals.is_empty() && state.detached_recovered_removals.is_empty();
        drop(state);
        if empty {
            return Ok(());
        }
        let progress = self.maintain_cleanup().await;
        let state = self.state.lock().await;
        let pending = state
            .detached_removals
            .len()
            .saturating_add(state.detached_recovered_removals.len());
        if pending == 0 {
            Ok(())
        } else {
            Err(progress
                .first_error
                .unwrap_or_else(|| DelegationError::stable("detached delegation removal remains pending")))
        }
    }

    fn enqueue_record_release(&self, record: ActiveDelegation) {
        if let Some(reservation) = record.reservation {
            self.resources.enqueue_release(record.context, reservation, record.capacity);
        }
    }

    async fn release_record(&self, record: ActiveDelegation) {
        self.enqueue_record_release(record);
        let _ = self.maintain_cleanup().await;
    }

    /// Returns the number of stable-repair and backend-release items that
    /// still require retry.
    pub fn pending_cleanup(&self) -> usize {
        self.resources
            .pending_releases()
            .saturating_add(self.pending_reconciliation.load(Ordering::Acquire))
            .saturating_add(self.pending_detached_removals.load(Ordering::Acquire))
    }

    /// Performs one bounded, deterministic pass over cleanup work that was
    /// pending when the pass began. Failed or cancelled work remains queued.
    pub async fn maintain_cleanup(&self) -> DelegationCleanupProgress {
        let _maintenance = self.maintenance.lock().await;
        let mut progress = DelegationCleanupProgress::default();

        // Stable deletion is deliberately completed from the detached outbox
        // rather than while an all-export renewal fence is held.  Until this
        // succeeds the record is absent from `records`, so a renewal cannot
        // bring it back to life; on cancellation it remains here for the next
        // bounded cleanup pass.
        let (detached, detached_recovered) = {
            let state = self.state.lock().await;
            (
                state
                    .detached_removals
                    .iter()
                    .map(|(key, record)| (*key, record.grant.persistent_record.clone()))
                    .collect::<Vec<_>>(),
                state
                    .detached_recovered_removals
                    .iter()
                    .map(|(key, record)| (*key, record.record.clone()))
                    .collect::<Vec<_>>(),
            )
        };
        if !detached.is_empty() || !detached_recovered.is_empty() {
            let detached_count = detached.len().saturating_add(detached_recovered.len());
            progress.attempted = progress.attempted.saturating_add(detached_count);
            let mut persistent = detached.iter().filter_map(|(_, record)| record.clone()).collect::<Vec<_>>();
            persistent.extend(detached_recovered.iter().map(|(_, record)| record.clone()));
            let durable_shape_is_valid = self.stable_journal.is_none() || persistent.len() == detached_count;
            let result = if durable_shape_is_valid {
                self.persist_delegation_deletes(&persistent).await
            } else {
                Err(DelegationError::InvalidConfiguration)
            };
            match result {
                Ok(()) => {
                    let (removed, removed_recovered) = {
                        let mut state = self.state.lock().await;
                        let active_keys = detached
                            .iter()
                            .filter(|(key, record)| {
                                state
                                    .detached_removals
                                    .get(key)
                                    .is_some_and(|active| active.grant.persistent_record == *record)
                            })
                            .map(|(key, _)| *key)
                            .collect::<Vec<_>>();
                        let recovered_keys = detached_recovered
                            .iter()
                            .filter(|(key, record)| {
                                state
                                    .detached_recovered_removals
                                    .get(key)
                                    .is_some_and(|recovered| recovered.record == *record)
                            })
                            .map(|(key, _)| *key)
                            .collect::<Vec<_>>();
                        let removed = (
                            active_keys
                                .into_iter()
                                .map(|key| {
                                    state
                                        .detached_removals
                                        .remove(&key)
                                        .expect("validated detached delegation exists")
                                })
                                .collect::<Vec<_>>(),
                            recovered_keys
                                .into_iter()
                                .map(|key| {
                                    state
                                        .detached_recovered_removals
                                        .remove(&key)
                                        .expect("validated detached recovered delegation exists")
                                })
                                .collect::<Vec<_>>(),
                        );
                        let removed_count = removed.0.len().saturating_add(removed.1.len());
                        if removed_count != 0 {
                            let previous = self.pending_detached_removals.fetch_sub(removed_count, Ordering::AcqRel);
                            assert!(previous >= removed_count, "detached-removal accounting underflow");
                        }
                        removed
                    };
                    let removed_count = removed.len().saturating_add(removed_recovered.len());
                    for record in removed {
                        self.enqueue_record_release(record);
                    }
                    // The recovered permits are intentionally dropped here:
                    // until durable deletion commits, their outbox entries
                    // continue to consume delegation capacity.
                    drop(removed_recovered);
                    progress.reconciled = progress.reconciled.saturating_add(removed_count);
                },
                Err(error) => {
                    progress.first_reconciliation_error.get_or_insert(error.clone());
                    progress.first_error.get_or_insert(error);
                },
            }
        }

        // Backend reservations are retired first. A reclaim predecessor must
        // not become visible while its replacement's reservation still owns
        // the shared capacity permit.
        let release_ids = self.resources.release_ids();
        for id in release_ids {
            let Some((context, reservation)) = self.resources.release(id) else {
                continue;
            };
            progress.attempted = progress.attempted.saturating_add(1);
            match self.vfs.nfs4_release_delegated_space(&context, reservation).await {
                Ok(()) => {
                    if self.resources.complete_release(id) {
                        progress.released = progress.released.saturating_add(1);
                    }
                },
                Err(error) => {
                    let error = DelegationError::Vfs(error);
                    progress.first_release_error.get_or_insert(error.clone());
                    progress.first_error.get_or_insert(error);
                },
            }
        }

        let reconciliation = {
            let state = self.state.lock().await;
            let mut work = state
                .reclaim_reconciliation
                .iter()
                .filter(|(_, item)| !item.capacity.0.release_queued.load(Ordering::Acquire))
                .map(|(token, item)| (*token, item.current.clone(), item.recovered.clone()))
                .collect::<Vec<_>>();
            work.sort_by_key(|(token, _, _)| *token);
            work
        };
        for (token, current, recovered) in reconciliation {
            progress.attempted = progress.attempted.saturating_add(1);
            match self.persist_reclaim_rollback(&current, &recovered).await {
                Ok(()) => {
                    let mut state = self.state.lock().await;
                    let matches = state
                        .reclaim_reconciliation
                        .get(&token)
                        .is_some_and(|item| item.current == current && item.recovered == recovered);
                    if matches {
                        let item = state
                            .reclaim_reconciliation
                            .remove(&token)
                            .expect("validated reconciliation exists");
                        let recovered_token = item.recovered.state_token();
                        match state.recovered.get(&recovered_token) {
                            Some(existing) if existing.record != item.recovered => {
                                state.reclaim_reconciliation.insert(token, item);
                                let error = DelegationError::RecoveryConflict;
                                progress.first_reconciliation_error.get_or_insert(error.clone());
                                progress.first_error.get_or_insert(error);
                            },
                            Some(_) => {
                                self.pending_reconciliation.fetch_sub(1, Ordering::AcqRel);
                                progress.reconciled = progress.reconciled.saturating_add(1);
                            },
                            None => {
                                state.recovered.insert(
                                    recovered_token,
                                    RecoveredDelegation {
                                        record: item.recovered,
                                        capacity: item.capacity,
                                    },
                                );
                                self.pending_reconciliation.fetch_sub(1, Ordering::AcqRel);
                                progress.reconciled = progress.reconciled.saturating_add(1);
                            },
                        }
                    }
                },
                Err(error) => {
                    progress.first_reconciliation_error.get_or_insert(error.clone());
                    progress.first_error.get_or_insert(error);
                },
            }
        }

        progress.pending_releases = self.resources.pending_releases();
        progress.pending_reconciliation = self.pending_reconciliation.load(Ordering::Acquire);
        progress.pending_detached_removals = self.pending_detached_removals.load(Ordering::Acquire);
        progress.pending = progress
            .pending_releases
            .saturating_add(progress.pending_reconciliation)
            .saturating_add(progress.pending_detached_removals);
        progress.drained = progress.pending == 0;
        progress
    }

    /// Extracts all current-boot delegation state without deleting durable
    /// reclaim records, queues every backend reservation, and performs one
    /// bounded cleanup pass. Repeated calls are safe and retry pending work.
    pub async fn shutdown_cleanup(&self) -> DelegationCleanupProgress {
        let removed = {
            let mut state = self.state.lock().await;
            let keys = state.records.keys().copied().collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| remove_record(&mut state, key, &self.client_state))
                .collect::<Vec<_>>()
        };
        for record in removed {
            self.enqueue_record_release(record);
        }
        let mut progress = self.maintain_cleanup().await;
        let active = !self.state.lock().await.records.is_empty();
        progress.drained = !active && progress.pending == 0;
        progress
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DelegationCleanupProgress {
    pub attempted: usize,
    pub released: usize,
    pub reconciled: usize,
    pub pending_releases: usize,
    pub pending_reconciliation: usize,
    pub pending_detached_removals: usize,
    pub pending: usize,
    pub drained: bool,
    pub first_release_error: Option<DelegationError>,
    pub first_reconciliation_error: Option<DelegationError>,
    pub first_error: Option<DelegationError>,
}

#[derive(Clone)]
pub struct PendingRecall {
    state_key: [u8; 12],
    state_id: StateId,
    truncate: bool,
    file_handle: NfsFileHandle,
    callback: Arc<CallbackRpcClient>,
    lease_expires_at: Duration,
}

impl std::fmt::Debug for PendingRecall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRecall")
            .field("state_id", &self.state_id)
            .field("truncate", &self.truncate)
            .field("file_handle", &self.file_handle)
            .field("lease_expires_at", &self.lease_expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct ConflictResult {
    pub status: NfsStatus,
    pub recalls: Vec<PendingRecall>,
}

#[derive(Debug)]
pub enum RecallOutcome {
    Delivered,
    AlreadyReturned,
    Revoked {
        callback_error: CallbackClientError,
        revoked: Option<RevokedDelegation>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    LeaseExpired,
    #[allow(dead_code)]
    Conflict,
    #[cfg_attr(not(test), allow(dead_code))]
    Administration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokedDelegation {
    pub state_id: StateId,
    pub client_id: u64,
    pub object: ObjectKey,
    pub reason: RevocationReason,
    pub persistent_record: Option<PersistentDelegationRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegationError {
    #[error("delegation manager configuration is invalid")]
    InvalidConfiguration,
    #[error("confirmed NFSv4 client ID is required")]
    MissingClientId,
    #[error("delegation stateid space is exhausted")]
    StateIdExhausted,
    #[error("persistent delegation reclaim record does not match the client or object")]
    ReclaimMismatch,
    #[error("delegation migration recovery conflicts with live state or configured limits")]
    RecoveryConflict,
    #[error("delegation operation failed with {0:?}")]
    Status(NfsStatus),
    #[error("delegation VFS hook failed: {0}")]
    Vfs(NfsError),
    #[error("delegation stable-state update failed: {0}")]
    StableState(String),
}

impl DelegationError {
    fn stable(error: impl std::fmt::Display) -> Self {
        Self::StableState(error.to_string())
    }

    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::InvalidConfiguration | Self::StateIdExhausted => NfsStatus::ServerFault,
            Self::MissingClientId => NfsStatus::StaleClientId,
            Self::ReclaimMismatch => NfsStatus::ReclaimBad,
            Self::RecoveryConflict => NfsStatus::Resource,
            Self::Status(status) => *status,
            Self::Vfs(error) => map_vfs_error(*error),
            Self::StableState(_) => NfsStatus::Resource,
        }
    }
}

const fn map_vfs_error(error: NfsError) -> NfsStatus {
    match error {
        NfsError::Permission => NfsStatus::Permission,
        NfsError::NotFound => NfsStatus::NotFound,
        NfsError::Io | NfsError::NotSynchronized => NfsStatus::Io,
        NfsError::NoDeviceOrAddress | NfsError::NoDevice => NfsStatus::NoDeviceOrAddress,
        NfsError::Access => NfsStatus::Access,
        NfsError::Exists => NfsStatus::Exists,
        NfsError::CrossDevice => NfsStatus::CrossDevice,
        NfsError::NotDirectory => NfsStatus::NotDirectory,
        NfsError::IsDirectory => NfsStatus::IsDirectory,
        NfsError::Invalid => NfsStatus::Invalid,
        NfsError::FileTooLarge => NfsStatus::FileTooLarge,
        NfsError::NoSpace => NfsStatus::NoSpace,
        NfsError::ReadOnly => NfsStatus::ReadOnly,
        NfsError::TooManyLinks => NfsStatus::TooManyLinks,
        NfsError::NameTooLong => NfsStatus::NameTooLong,
        NfsError::NotEmpty => NfsStatus::NotEmpty,
        NfsError::Quota => NfsStatus::Quota,
        NfsError::Stale => NfsStatus::Stale,
        NfsError::Remote => NfsStatus::Moved,
        NfsError::BadCookie => NfsStatus::BadCookie,
        NfsError::NotSupported => NfsStatus::NotSupported,
        NfsError::TooSmall => NfsStatus::TooSmall,
        NfsError::ServerFault => NfsStatus::ServerFault,
        NfsError::BadType => NfsStatus::BadType,
        NfsError::Jukebox => NfsStatus::Delay,
    }
}

fn validate_state_id(provided: StateId, current: StateId) -> Result<(), NfsStatus> {
    if provided.other != current.other {
        return Err(NfsStatus::BadStateId);
    }
    if provided.sequence_id == 0 || provided.sequence_id == current.sequence_id {
        Ok(())
    } else if (provided.sequence_id.wrapping_sub(current.sequence_id) as i32).is_negative() {
        Err(NfsStatus::OldStateId)
    } else {
        Err(NfsStatus::BadStateId)
    }
}

fn delegation_conflicts(held: DelegationKind, requested: DelegationKind) -> bool {
    matches!((held, requested), (DelegationKind::Write, _) | (DelegationKind::Read, DelegationKind::Write))
}

fn callback_error_indicates_path_down(error: &CallbackClientError) -> bool {
    match error {
        CallbackClientError::Transport(_) => true,
        CallbackClientError::LeaseExpired { last } => callback_error_indicates_path_down(last),
        // A decoded callback NFS result, RPC rejection, or malformed reply
        // proves that the endpoint was contacted. Those failures may still
        // lead to revocation, but they are not NFS4ERR_CB_PATH_DOWN evidence.
        _ => false,
    }
}

fn increment_count(state: &mut DelegationState, kind: DelegationKind) {
    match kind {
        DelegationKind::Read => state.read_count += 1,
        DelegationKind::Write => state.write_count += 1,
    }
}

fn decrement_count(state: &mut DelegationState, kind: DelegationKind) {
    match kind {
        DelegationKind::Read => state.read_count = state.read_count.saturating_sub(1),
        DelegationKind::Write => state.write_count = state.write_count.saturating_sub(1),
    }
}

fn remove_record(
    state: &mut DelegationState,
    key: [u8; 12],
    client_state: &DelegationClientState,
) -> Option<ActiveDelegation> {
    let record = state.records.remove(&key)?;
    decrement_count(state, record.grant.kind);
    client_state.delegation_removed(record.grant.client_id);
    Some(record)
}

/// Removes a delegation from live protocol state while retaining its durable
/// deletion and backend-release obligation in the manager's outbox.  Callers
/// hold the renewal fence, so no concurrent renewal can resurrect the record
/// between this decision and post-fence cleanup.
fn detach_record(
    state: &mut DelegationState,
    key: [u8; 12],
    client_state: &DelegationClientState,
) -> Option<RevokedDelegation> {
    let record = remove_record(state, key, client_state)?;
    let revoked = revoked_delegation(&record, RevocationReason::LeaseExpired);
    let previous = state.detached_removals.insert(key, record);
    assert!(previous.is_none(), "a live delegation may be detached only once");
    Some(revoked)
}

fn revoked_delegation(record: &ActiveDelegation, reason: RevocationReason) -> RevokedDelegation {
    RevokedDelegation {
        state_id: record.grant.state_id,
        client_id: record.grant.client_id,
        object: record.grant.object,
        reason,
        persistent_record: record.grant.persistent_record.clone(),
    }
}

fn state_token(state_id: StateId) -> [u8; 16] {
    let mut token = [0; 16];
    token[..4].copy_from_slice(&state_id.sequence_id.to_be_bytes());
    token[4..].copy_from_slice(&state_id.other);
    token
}

fn delegation_state_identity(token: [u8; 16]) -> [u8; 12] {
    token[4..]
        .try_into()
        .expect("a delegation state token always contains a 12-byte object identity")
}

fn state_id_from_token(token: [u8; 16]) -> Result<StateId, DelegationError> {
    let state_id = StateId {
        sequence_id: u32::from_be_bytes(token[..4].try_into().expect("four-byte stateid sequence")),
        other: token[4..].try_into().expect("twelve-byte stateid body"),
    };
    if state_id.sequence_id == 0 || state_id.other == [0; 12] || state_id.other == [u8::MAX; 12] {
        return Err(DelegationError::stable("invalid recovered delegation stateid"));
    }
    Ok(state_id)
}

fn stable_delegation_record(record: &PersistentDelegationRecord) -> StableDelegationRecord {
    StableDelegationRecord {
        state_token: record.state_token(),
        client_id: record.client_id,
        object: StableObject {
            export_id: record.export_id,
            file_id: record.object.file_id,
            generation: record.object.generation,
        },
        write: record.kind == DelegationKind::Write,
        requested_space: record.requested_space,
        persistent_object_id: Bytes::copy_from_slice(record.persistent_object_id.as_bytes()),
    }
}

fn persistent_delegation_record(
    record: &StableDelegationRecord,
) -> Result<PersistentDelegationRecord, DelegationError> {
    let persistent_object_id = PersistentObjectId::new(record.persistent_object_id.clone())
        .map_err(|_| DelegationError::stable("invalid recovered persistent object identity"))?;
    Ok(PersistentDelegationRecord {
        client_id: record.client_id,
        export_id: record.object.export_id,
        object: ObjectKey {
            file_id: record.object.file_id,
            generation: record.object.generation,
        },
        persistent_object_id,
        kind: if record.write {
            DelegationKind::Write
        } else {
            DelegationKind::Read
        },
        requested_space: record.requested_space,
        previous_state_id: state_id_from_token(record.state_token)?,
    })
}

fn recovered_delegations(
    recovered: Option<&RecoveredStableState>,
    export_id: Option<ExportId>,
    max_read: usize,
    max_write: usize,
) -> Result<HashMap<[u8; 16], PersistentDelegationRecord>, DelegationError> {
    let (Some(recovered), Some(export_id)) = (recovered, export_id) else {
        return Ok(HashMap::new());
    };
    let mut delegations: HashMap<[u8; 16], PersistentDelegationRecord> = HashMap::new();
    let mut state_identities = HashSet::new();
    let mut conflicts = PersistentDelegationConflictIndex::default();
    let mut read_count = 0usize;
    let mut write_count = 0usize;
    for (key, record) in &recovered.records {
        let (JournalKey::Delegation { state_token: key_token }, JournalRecord::Delegation(record)) = (key, record)
        else {
            continue;
        };
        if record.object.export_id != export_id {
            continue;
        }
        if *key_token != record.state_token {
            return Err(DelegationError::stable("recovered delegation key does not match its record"));
        }
        // A durable candidate can survive several crashes before it is
        // reclaimed. Its originating boot is encoded in the stable client ID,
        // so comparing only with the immediately previous Boot record would
        // incorrectly reject a second restart during grace.
        let client_boot_tag = (record.client_id >> 32) as u32;
        if client_boot_tag != 0
            && delegation_state_identity(record.state_token)[..4] != (!client_boot_tag).to_be_bytes()
        {
            return Err(DelegationError::stable(
                "recovered delegation stateid is outside its client incarnation namespace",
            ));
        }
        let persistent = persistent_delegation_record(record)?;
        if !state_identities.insert(delegation_state_identity(record.state_token)) {
            return Err(DelegationError::stable("duplicate recovered delegation state object identity"));
        }
        match persistent.kind {
            DelegationKind::Read => {
                read_count = read_count.checked_add(1).ok_or(DelegationError::RecoveryConflict)?;
                if read_count > max_read {
                    return Err(DelegationError::RecoveryConflict);
                }
            },
            DelegationKind::Write => {
                write_count = write_count.checked_add(1).ok_or(DelegationError::RecoveryConflict)?;
                if write_count > max_write {
                    return Err(DelegationError::RecoveryConflict);
                }
            },
        }
        if !conflicts.insert(&persistent) {
            return Err(DelegationError::RecoveryConflict);
        }
        if delegations.insert(record.state_token, persistent).is_some() {
            return Err(DelegationError::stable("duplicate recovered delegation stateid"));
        }
    }
    Ok(delegations)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use tokio::sync::{Barrier, Notify};

    use super::*;
    use crate::nfs4::codec::DecodeLimits;
    use crate::nfs4::stable::tests::{test_scope, DurableFakeStore};
    use crate::nfs4::stable::{BootRecord, ClientRecord as StableClientRecord, PreviousShutdown, StableJournalLimits};
    use crate::nfs4::types::{
        CallbackArgOp, CallbackCompoundArgs, CallbackCompoundRes, CallbackResOp, NfsResult,
        CALLBACK_COMPOUND_PROCEDURE, CALLBACK_NULL_PROCEDURE,
    };
    use crate::server::{CallbackConnector, CallbackError, CallbackTarget, CallbackTransport};
    use crate::vfs::{
        ChangeId, CreatedObject, FileAttributes, FileType, Nfs4Capabilities, NfsName, Principal, ProtocolVersion,
        StableBatch, StableFenceToken, StableSnapshot, StableStateError, StableStateSession, StableStateStore,
        VfsCapabilities,
    };

    #[derive(Clone, Default)]
    struct FailOnceStore {
        inner: DurableFakeStore,
        fail_next_commit: Arc<AtomicBool>,
    }

    impl FailOnceStore {
        fn fail_next_commit(&self) {
            self.fail_next_commit.store(true, Ordering::SeqCst);
        }
    }

    struct FailOnceSession {
        inner: Arc<dyn StableStateSession>,
        fail_next_commit: Arc<AtomicBool>,
    }

    #[async_trait]
    impl StableStateStore for FailOnceStore {
        async fn open_scope(
            &self,
            scope: crate::vfs::StableScope,
        ) -> Result<Arc<dyn StableStateSession>, StableStateError> {
            Ok(Arc::new(FailOnceSession {
                inner: self.inner.open_scope(scope).await?,
                fail_next_commit: Arc::clone(&self.fail_next_commit),
            }))
        }
    }

    #[async_trait]
    impl StableStateSession for FailOnceSession {
        fn fence_token(&self) -> StableFenceToken {
            self.inner.fence_token()
        }

        fn generation(&self) -> u64 {
            self.inner.generation()
        }

        async fn recover(&self) -> Result<StableSnapshot, StableStateError> {
            self.inner.recover().await
        }

        async fn commit(&self, expected_generation: u64, batch: StableBatch) -> Result<u64, StableStateError> {
            if self.fail_next_commit.swap(false, Ordering::SeqCst) {
                return Err(StableStateError::Unavailable("injected OPEN journal failure".into()));
            }
            self.inner.commit(expected_generation, batch).await
        }

        async fn checkpoint(&self, expected_generation: u64) -> Result<u64, StableStateError> {
            self.inner.checkpoint(expected_generation).await
        }
    }

    #[derive(Default)]
    struct ManualClock {
        nanoseconds: AtomicU64,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.nanoseconds
                .fetch_add(duration.as_nanos().min(u128::from(u64::MAX)) as u64, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CallbackClock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.nanoseconds.load(Ordering::SeqCst))
        }

        async fn sleep(&self, duration: Duration) {
            self.advance(duration);
            tokio::task::yield_now().await;
        }
    }

    #[derive(Default)]
    struct ControlledClock {
        nanoseconds: AtomicU64,
        advanced: Notify,
    }

    impl ControlledClock {
        fn advance_to(&self, now: Duration) {
            self.nanoseconds
                .store(now.as_nanos().min(u128::from(u64::MAX)) as u64, Ordering::SeqCst);
            self.advanced.notify_waiters();
        }
    }

    #[async_trait]
    impl CallbackClock for ControlledClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.nanoseconds.load(Ordering::SeqCst))
        }

        async fn sleep(&self, duration: Duration) {
            let deadline = self.now().saturating_add(duration);
            loop {
                let advanced = self.advanced.notified();
                if self.now() >= deadline {
                    return;
                }
                advanced.await;
            }
        }
    }

    struct MockVfs {
        eligibility: DelegationEligibility,
        barrier: Option<Arc<Barrier>>,
        eligibility_calls: AtomicUsize,
        reservations: AtomicUsize,
        reservation_token_size: AtomicUsize,
        releases: AtomicUsize,
        successful_releases: AtomicUsize,
        release_failures: AtomicUsize,
        block_releases: AtomicBool,
        release_entered: Notify,
        continue_release: Notify,
        released_tokens: StdMutex<Vec<Bytes>>,
        reservation_scopes: StdMutex<Vec<Bytes>>,
        persistent_id: PersistentObjectId,
    }

    impl MockVfs {
        fn new(eligibility: DelegationEligibility) -> Self {
            Self {
                eligibility,
                barrier: None,
                eligibility_calls: AtomicUsize::new(0),
                reservations: AtomicUsize::new(0),
                reservation_token_size: AtomicUsize::new(std::mem::size_of::<usize>()),
                releases: AtomicUsize::new(0),
                successful_releases: AtomicUsize::new(0),
                release_failures: AtomicUsize::new(0),
                block_releases: AtomicBool::new(false),
                release_entered: Notify::new(),
                continue_release: Notify::new(),
                released_tokens: StdMutex::new(Vec::new()),
                reservation_scopes: StdMutex::new(Vec::new()),
                persistent_id: PersistentObjectId::new(Bytes::from_static(b"object-1")).unwrap(),
            }
        }

        fn fail_releases(&self, attempts: usize) {
            self.release_failures.store(attempts, Ordering::SeqCst);
        }

        fn block_releases(&self) {
            self.block_releases.store(true, Ordering::SeqCst);
        }

        fn unblock_releases(&self) {
            self.block_releases.store(false, Ordering::SeqCst);
            self.continue_release.notify_waiters();
        }
    }

    #[async_trait]
    impl VirtualFileSystem for MockVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_WRITE
        }

        fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
            Some(Nfs4Capabilities {
                delegations: true,
                persistent_object_ids: true,
                ..Nfs4Capabilities::READ_WRITE
            })
        }

        fn root(&self) -> ObjectKey {
            object(1)
        }

        async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            Ok(FileAttributes {
                file_type: FileType::Regular,
                mode: 0o644,
                links: 1,
                uid: 1,
                gid: 1,
                size: 0,
                used: 0,
                device: None,
                fs_id: 1,
                file_id: object.file_id,
                change_id: ChangeId(1),
                access_time: crate::vfs::NfsTime::default(),
                modify_time: crate::vfs::NfsTime::default(),
                change_time: crate::vfs::NfsTime::default(),
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

        async fn nfs4_delegation_eligibility(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            _request: DelegationRequest,
        ) -> Result<DelegationEligibility, NfsError> {
            self.eligibility_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(barrier) = &self.barrier {
                barrier.wait().await;
            }
            Ok(self.eligibility)
        }

        async fn nfs4_reserve_delegated_space(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            bytes: u64,
            scope: &StableFenceToken,
        ) -> Result<DelegationReservation, NfsError> {
            self.reservation_scopes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Bytes::copy_from_slice(scope.as_bytes()));
            let token = self.reservations.fetch_add(1, Ordering::SeqCst) + 1;
            let token_size = self.reservation_token_size.load(Ordering::SeqCst);
            let token = if token_size == std::mem::size_of::<usize>() {
                Bytes::from(token.to_be_bytes().to_vec())
            } else {
                Bytes::from(vec![u8::try_from(token & 0xff).unwrap(); token_size])
            };
            Ok(DelegationReservation {
                token,
                reserved_bytes: bytes,
            })
        }

        async fn nfs4_release_delegated_space(
            &self,
            _context: &RequestContext,
            reservation: DelegationReservation,
        ) -> Result<(), NfsError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.released_tokens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(reservation.token.clone());
            if self.block_releases.load(Ordering::SeqCst) {
                self.release_entered.notify_one();
                self.continue_release.notified().await;
            }
            if self
                .release_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| remaining.checked_sub(1))
                .is_ok()
            {
                return Err(NfsError::Io);
            }
            self.successful_releases.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn nfs4_persistent_object_id(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
        ) -> Result<PersistentObjectId, NfsError> {
            Ok(self.persistent_id.clone())
        }
    }

    struct CallbackTransportMock {
        reachable: bool,
        fail_recall: bool,
        recalls: AtomicUsize,
    }

    #[async_trait]
    impl CallbackTransport for CallbackTransportMock {
        async fn call(&self, call: Bytes, _timeout: Duration) -> Result<Bytes, CallbackError> {
            if !self.reachable {
                return Err(CallbackError::Unavailable("down".into()));
            }
            let (xid, procedure, body) = decode_rpc_call(&call);
            let body = match procedure {
                CALLBACK_NULL_PROCEDURE => Vec::new(),
                CALLBACK_COMPOUND_PROCEDURE => {
                    if self.fail_recall {
                        return Err(CallbackError::Unavailable("recall path down".into()));
                    }
                    let request = CallbackCompoundArgs::decode(&body, DecodeLimits::default())
                        .map_err(|error| CallbackError::Protocol(error.to_string()))?;
                    let results = request
                        .operations
                        .iter()
                        .map(|operation| match operation {
                            CallbackArgOp::Recall(_) => {
                                self.recalls.fetch_add(1, Ordering::SeqCst);
                                CallbackResOp::Recall(NfsStatus::Ok)
                            },
                            CallbackArgOp::GetAttr(_) => {
                                CallbackResOp::GetAttr(NfsResult::Err(NfsStatus::NotSupported))
                            },
                            CallbackArgOp::Illegal { .. } => CallbackResOp::Illegal(NfsStatus::OperationIllegal),
                        })
                        .collect();
                    CallbackCompoundRes::from_operations(request.tag, results)
                        .encode()
                        .map_err(|error| CallbackError::Protocol(error.to_string()))?
                },
                _ => return Err(CallbackError::Protocol("unexpected procedure".into())),
            };
            Ok(accepted_reply(xid, &body))
        }
    }

    #[derive(Default)]
    struct ControlledRecallTransport {
        fail_recall: AtomicBool,
        recall_attempted: Notify,
        recall_attempts: AtomicUsize,
    }

    #[async_trait]
    impl CallbackTransport for ControlledRecallTransport {
        async fn call(&self, call: Bytes, _timeout: Duration) -> Result<Bytes, CallbackError> {
            let (xid, procedure, body) = decode_rpc_call(&call);
            let body = match procedure {
                CALLBACK_NULL_PROCEDURE => Vec::new(),
                CALLBACK_COMPOUND_PROCEDURE => {
                    self.recall_attempts.fetch_add(1, Ordering::SeqCst);
                    self.recall_attempted.notify_one();
                    if self.fail_recall.load(Ordering::SeqCst) {
                        return Err(CallbackError::Unavailable("recall path down".into()));
                    }
                    let request = CallbackCompoundArgs::decode(&body, DecodeLimits::default())
                        .map_err(|error| CallbackError::Protocol(error.to_string()))?;
                    let results = request
                        .operations
                        .iter()
                        .map(|operation| match operation {
                            CallbackArgOp::Recall(_) => CallbackResOp::Recall(NfsStatus::Ok),
                            CallbackArgOp::GetAttr(_) => {
                                CallbackResOp::GetAttr(NfsResult::Err(NfsStatus::NotSupported))
                            },
                            CallbackArgOp::Illegal { .. } => CallbackResOp::Illegal(NfsStatus::OperationIllegal),
                        })
                        .collect();
                    CallbackCompoundRes::from_operations(request.tag, results)
                        .encode()
                        .map_err(|error| CallbackError::Protocol(error.to_string()))?
                },
                _ => return Err(CallbackError::Protocol("unexpected procedure".into())),
            };
            Ok(accepted_reply(xid, &body))
        }
    }

    struct ConnectorMock {
        transport: Arc<dyn CallbackTransport>,
    }

    #[async_trait]
    impl CallbackConnector for ConnectorMock {
        async fn connect(&self, _target: &CallbackTarget) -> Result<Arc<dyn CallbackTransport>, CallbackError> {
            Ok(self.transport.clone())
        }
    }

    fn decode_rpc_call(call: &[u8]) -> (u32, u32, Vec<u8>) {
        let mut decoder = Decoder::new(call);
        let xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert_eq!(decoder.read_u32().unwrap(), 2);
        let _program = decoder.read_u32().unwrap();
        let _version = decoder.read_u32().unwrap();
        let procedure = decoder.read_u32().unwrap();
        let _credential_flavor = decoder.read_u32().unwrap();
        let _credential = decoder.read_opaque("credential", 400).unwrap();
        let _verifier_flavor = decoder.read_u32().unwrap();
        let _verifier = decoder.read_opaque("verifier", 400).unwrap();
        (xid, procedure, call[decoder.position()..].to_vec())
    }

    fn accepted_reply(xid: u32, body: &[u8]) -> Bytes {
        let mut encoder = Encoder::new();
        encoder.write_u32(xid);
        encoder.write_u32(1);
        encoder.write_u32(0);
        encoder.write_u32(0);
        encoder.write_u32(0);
        encoder.write_u32(0);
        encoder.write_fixed(body);
        Bytes::from(encoder.into_bytes())
    }

    fn callback(clock: Arc<dyn CallbackClock>, reachable: bool) -> Arc<CallbackRpcClient> {
        callback_with_behavior(clock, reachable, false)
    }

    fn callback_with_behavior(
        clock: Arc<dyn CallbackClock>,
        reachable: bool,
        fail_recall: bool,
    ) -> Arc<CallbackRpcClient> {
        callback_for_transport(
            clock,
            Arc::new(CallbackTransportMock {
                reachable,
                fail_recall,
                recalls: AtomicUsize::new(0),
            }),
        )
    }

    fn callback_for_transport(
        clock: Arc<dyn CallbackClock>,
        transport: Arc<dyn CallbackTransport>,
    ) -> Arc<CallbackRpcClient> {
        Arc::new(
            CallbackRpcClient::new(
                Arc::new(ConnectorMock { transport }),
                CallbackTarget {
                    network_id: "tcp".into(),
                    universal_address: "127.0.0.1.8.1".into(),
                },
                0x4000_0001,
                1,
                super::super::callback::CallbackAuth::AuthNone,
                super::super::callback::CallbackClientConfig {
                    attempt_timeout: Duration::from_millis(50),
                    initial_backoff: Duration::from_millis(10),
                    max_backoff: Duration::from_millis(20),
                    ..super::super::callback::CallbackClientConfig::default()
                },
                clock,
            )
            .unwrap(),
        )
    }

    fn object(file_id: u64) -> ObjectKey {
        ObjectKey { file_id, generation: 1 }
    }

    fn context(client_id: u64) -> RequestContext {
        RequestContext {
            principal: Principal::Anonymous,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            export_id: ExportId(7),
            protocol: ProtocolVersion::V4,
            client_id: Some(client_id),
        }
    }

    fn request(
        client_id: u64,
        object: ObjectKey,
        kind: DelegationKind,
        callback: Arc<CallbackRpcClient>,
    ) -> DelegationGrantRequest {
        DelegationGrantRequest {
            context: context(client_id),
            object,
            file_handle: NfsFileHandle(vec![object.file_id as u8]),
            kind,
            requested_space: 4096,
            callback,
        }
    }

    fn policy(max_read: usize, max_write: usize, persistent: bool) -> DelegationPolicy {
        DelegationPolicy::Conservative {
            max_read_delegations: max_read,
            max_write_delegations: max_write,
            persistent,
        }
    }

    #[test]
    fn only_callback_reachability_errors_mark_the_path_down() {
        assert!(callback_error_indicates_path_down(&CallbackClientError::LeaseExpired {
            last: Box::new(CallbackClientError::Transport(CallbackError::Unavailable(
                "callback unreachable".to_owned(),
            ))),
        }));
        assert!(!callback_error_indicates_path_down(&CallbackClientError::LeaseExpired {
            last: Box::new(CallbackClientError::Nfs(NfsStatus::BadHandle)),
        }));
        assert!(!callback_error_indicates_path_down(&CallbackClientError::UnexpectedReply(
            "valid transport, malformed callback response",
        )));
    }

    async fn seed_test_clients(journal: &mut StableJournal) {
        let known_clients = [1_u64, 2, 3, 7, 10, 11, 17, 20, 41, 42, 43];
        let recovered_clients = journal
            .recovery()
            .records
            .iter()
            .filter_map(|(_, record)| match record {
                JournalRecord::Client(client) => Some(client.client_id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let mut batch = PersistBatch::default();
        for client_id in known_clients {
            if recovered_clients.contains(&client_id) {
                continue;
            }
            batch = batch.put(
                JournalKey::Client { client_id },
                JournalRecord::Client(StableClientRecord {
                    client_id,
                    owner: Bytes::from(format!("delegation-test-client-{client_id}")),
                    verifier: client_id.to_be_bytes(),
                    canonical_principal: Bytes::from_static(b"anonymous"),
                    confirmed: true,
                }),
            );
        }
        if !batch.is_empty() {
            journal.persist_before_ack(batch).await.unwrap();
        }
    }

    async fn durable_journal(store: Arc<DurableFakeStore>, started_at: i64) -> StableJournal {
        let mut journal = StableJournal::initialize(store, test_scope(), started_at, StableJournalLimits::default())
            .await
            .unwrap();
        seed_test_clients(&mut journal).await;
        journal
    }

    async fn fail_once_journal(store: Arc<FailOnceStore>, started_at: i64) -> StableJournal {
        let mut journal = StableJournal::initialize(store, test_scope(), started_at, StableJournalLimits::default())
            .await
            .unwrap();
        seed_test_clients(&mut journal).await;
        journal
    }

    fn durable_manager(vfs: Arc<MockVfs>, clock: Arc<ManualClock>, journal: StableJournal) -> DelegationManager {
        let boot_tag = journal.boot().boot_tag;
        let recovered = journal.recovery().clone();
        let reservation_scope = journal.fence_token().clone();
        DelegationManager::with_boot_tag_stable_state_and_scope(
            vfs,
            policy(4, 4, true),
            Duration::from_secs(30),
            clock,
            boot_tag,
            Some(Arc::new(Mutex::new(journal))),
            Some(&recovered),
            Some(ExportId(7)),
            reservation_scope,
            DelegationClientState::new(),
        )
        .unwrap()
    }

    fn persistent_record(
        client_id: u64,
        object: ObjectKey,
        persistent_object_id: &'static [u8],
        kind: DelegationKind,
        token_byte: u8,
    ) -> PersistentDelegationRecord {
        let mut other = [token_byte; 12];
        other[..4].copy_from_slice(&(!0x5a5a_5a5a_u32).to_be_bytes());
        PersistentDelegationRecord {
            client_id,
            export_id: ExportId(7),
            object,
            persistent_object_id: PersistentObjectId::new(Bytes::from_static(persistent_object_id)).unwrap(),
            kind,
            requested_space: u64::from(kind == DelegationKind::Write) * 4096,
            previous_state_id: StateId { sequence_id: 1, other },
        }
    }

    fn recovered_image(records: impl IntoIterator<Item = PersistentDelegationRecord>) -> RecoveredStableState {
        let records = records.into_iter().collect::<Vec<_>>();
        let mut client_ids = records.iter().map(|record| record.client_id).collect::<Vec<_>>();
        client_ids.sort_unstable();
        client_ids.dedup();
        let mut stable_records = client_ids
            .into_iter()
            .map(|client_id| {
                (
                    JournalKey::Client { client_id },
                    JournalRecord::Client(StableClientRecord {
                        client_id,
                        owner: Bytes::from(format!("recovered-test-client-{client_id}")),
                        verifier: client_id.to_be_bytes(),
                        canonical_principal: Bytes::from_static(b"anonymous"),
                        confirmed: true,
                    }),
                )
            })
            .collect::<Vec<_>>();
        stable_records.extend(records.into_iter().map(|record| {
            (
                JournalKey::Delegation {
                    state_token: record.state_token(),
                },
                JournalRecord::Delegation(stable_delegation_record(&record)),
            )
        }));
        RecoveredStableState {
            previous_shutdown: PreviousShutdown::Unclean,
            previous_boot: Some(BootRecord {
                verifier: [0x51; 8],
                boot_tag: 0x5a5a_5a5a,
                started_at_unix_seconds: 1,
                clean_shutdown: false,
            }),
            records: stable_records,
        }
    }

    #[test]
    fn export_scoped_state_ids_exhaust_before_entering_another_export_prefix() {
        let manager = DelegationManager::with_boot_tag_and_stable_state(
            Arc::new(MockVfs::new(DelegationEligibility::Eligible)),
            policy(2, 2, false),
            Duration::from_secs(30),
            Arc::new(ManualClock::default()),
            9,
            None,
            None,
            Some(ExportId(7)),
        )
        .unwrap();
        let final_token = (u64::from(ExportId(7).0) << 32) | u64::from(u32::MAX - 1);
        manager.next_token.store(final_token, Ordering::Relaxed);

        let state_id = manager.allocate_state_id().unwrap();
        assert_eq!(u32::from_be_bytes(state_id.other[..4].try_into().unwrap()), !9_u32);
        assert_eq!(u64::from_be_bytes(state_id.other[4..].try_into().unwrap()), final_token);
        assert!(matches!(manager.allocate_state_id(), Err(DelegationError::StateIdExhausted)));
        assert_eq!(manager.next_token.load(Ordering::Relaxed) >> 32, u64::from(ExportId(7).0));
    }

    #[tokio::test]
    async fn callback_reachability_gates_backend_eligibility() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(2, 2, false),
            Duration::from_secs(30),
            clock.clone(),
            9,
        )
        .unwrap();
        let outcome = manager
            .grant(request(1, object(1), DelegationKind::Read, callback(clock, false)))
            .await
            .unwrap();
        assert_eq!(outcome, GrantOutcome::NotGranted(GrantDenial::CallbackUnreachable));
        assert_eq!(vfs.eligibility_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn client_state_query_covers_live_and_previous_boot_delegations() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager =
            DelegationManager::with_boot_tag(vfs, policy(4, 4, true), Duration::from_secs(30), clock.clone(), 9)
                .unwrap();
        let GrantOutcome::Granted(grant) = manager
            .grant(request(7, object(1), DelegationKind::Read, callback(clock, true)))
            .await
            .unwrap()
        else {
            panic!("delegation not granted");
        };

        assert!(manager.has_client_state(7, &[]).await);
        assert!(!manager.has_client_state(8, &[]).await);

        let recovered = grant.persistent_record.expect("persistent delegation record");
        assert_eq!(manager.delegpurge(&context(7), 7).await.unwrap(), 1);
        let capacity = manager.resources.try_reserve(recovered.kind).unwrap();
        manager.state.lock().await.recovered.insert(
            recovered.state_token(),
            RecoveredDelegation {
                record: recovered,
                capacity,
            },
        );

        assert!(manager.has_client_state(8, &[7]).await);
        assert!(!manager.has_client_state(8, &[6]).await);
    }

    #[tokio::test]
    async fn configured_read_limit_declines_without_extra_backend_work() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(1, 1, false),
            Duration::from_secs(30),
            clock.clone(),
            9,
        )
        .unwrap();
        assert!(matches!(
            manager
                .grant(request(1, object(1), DelegationKind::Read, callback(clock.clone(), true),))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));
        assert_eq!(
            manager
                .grant(request(2, object(2), DelegationKind::Read, callback(clock, true),))
                .await
                .unwrap(),
            GrantOutcome::NotGranted(GrantDenial::ResourceLimit)
        );
        assert_eq!(vfs.eligibility_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn live_persistent_delegations_enforce_backend_object_identity() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = durable_manager(vfs, clock.clone(), durable_journal(store, 100).await);

        assert!(matches!(
            manager
                .grant(request(1, object(1), DelegationKind::Read, callback(clock.clone(), true)))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));
        assert!(matches!(
            manager
                .grant(request(2, object(2), DelegationKind::Read, callback(clock.clone(), true)))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));
        assert_eq!(
            manager
                .grant(request(3, object(3), DelegationKind::Write, callback(clock, true)))
                .await
                .unwrap(),
            GrantOutcome::NotGranted(GrantDenial::ExistingConflict)
        );
    }

    #[tokio::test]
    async fn recovery_import_rejects_exact_and_semantic_active_duplicates() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = durable_manager(vfs, clock.clone(), durable_journal(store, 100).await);
        let GrantOutcome::Granted(grant) = manager
            .grant(request(1, object(1), DelegationKind::Read, callback(clock, true)))
            .await
            .unwrap()
        else {
            panic!("delegation not granted");
        };
        let active = grant.persistent_record.unwrap();
        let exact = PreparedDelegationRecovery {
            export_id: ExportId(7),
            recovered: HashMap::from([(active.state_token(), active.clone())]),
        };
        assert_eq!(manager.validate_recovery_import(&exact).await, Err(DelegationError::RecoveryConflict));

        let mut same_identity = active;
        same_identity.previous_state_id.other[11] ^= 0x55;
        let semantic = PreparedDelegationRecovery {
            export_id: ExportId(7),
            recovered: HashMap::from([(same_identity.state_token(), same_identity)]),
        };
        assert_eq!(manager.validate_recovery_import(&semantic).await, Err(DelegationError::RecoveryConflict));

        let distinct_reader = persistent_record(2, object(2), b"object-1", DelegationKind::Read, 0x45);
        let compatible = PreparedDelegationRecovery {
            export_id: ExportId(7),
            recovered: HashMap::from([(distinct_reader.state_token(), distinct_reader)]),
        };
        manager.validate_recovery_import(&compatible).await.unwrap();

        let conflicting_writer = persistent_record(2, object(2), b"object-1", DelegationKind::Write, 0x46);
        let incompatible = PreparedDelegationRecovery {
            export_id: ExportId(7),
            recovered: HashMap::from([(conflicting_writer.state_token(), conflicting_writer)]),
        };
        assert_eq!(manager.validate_recovery_import(&incompatible).await, Err(DelegationError::RecoveryConflict));
    }

    #[tokio::test]
    async fn recovery_activation_capacity_race_is_atomic() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let journal = durable_journal(store, 100).await;
        let boot_tag = journal.boot().boot_tag;
        let recovered = journal.recovery().clone();
        let manager = DelegationManager::with_boot_tag_and_stable_state(
            vfs,
            policy(2, 2, true),
            Duration::from_secs(30),
            clock.clone(),
            boot_tag,
            Some(Arc::new(Mutex::new(journal))),
            Some(&recovered),
            Some(ExportId(7)),
        )
        .unwrap();
        let recovered_record = |client_id, suffix, token_byte| PersistentDelegationRecord {
            client_id,
            export_id: ExportId(7),
            object: object(suffix),
            persistent_object_id: PersistentObjectId::new(Bytes::from(vec![b'm', token_byte])).unwrap(),
            kind: DelegationKind::Read,
            requested_space: 4096,
            previous_state_id: StateId {
                sequence_id: 1,
                other: [token_byte; 12],
            },
        };
        let first = recovered_record(10, 10, 10);
        let second = recovered_record(11, 11, 11);
        let prepared = PreparedDelegationRecovery {
            export_id: ExportId(7),
            recovered: HashMap::from([(first.state_token(), first), (second.state_token(), second)]),
        };
        manager.validate_recovery_import(&prepared).await.unwrap();

        assert!(matches!(
            manager
                .grant(request(20, object(20), DelegationKind::Read, callback(clock, true)))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));
        assert_eq!(manager.activate_recovery_import(prepared).await, Err(DelegationError::RecoveryConflict));
        assert!(manager.recovered_delegations().await.is_empty());
        assert_eq!(manager.resources.usage(DelegationKind::Read), 1);
    }

    #[tokio::test]
    async fn write_reservation_is_released_on_delegreturn_and_purge() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(4, 4, false),
            Duration::from_secs(30),
            clock.clone(),
            9,
        )
        .unwrap();
        let first = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap();
        let GrantOutcome::Granted(first) = first else {
            panic!("write delegation not granted");
        };
        manager.delegreturn(&context(1), object(1), first.state_id).await.unwrap();

        let second = manager
            .grant(request(2, object(2), DelegationKind::Write, callback(clock, true)))
            .await
            .unwrap();
        assert!(matches!(second, GrantOutcome::Granted(_)));
        assert_eq!(manager.delegpurge(&context(2), 2).await.unwrap(), 1);
        assert_eq!(vfs.reservations.load(Ordering::SeqCst), 2);
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn durable_write_reservations_are_bound_to_the_stable_fence_scope() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let journal = durable_journal(store, 100).await;
        let expected_scope = Bytes::copy_from_slice(journal.fence_token().as_bytes());
        let manager = durable_manager(vfs.clone(), clock.clone(), journal);

        assert!(matches!(
            manager
                .grant(request(17, object(1), DelegationKind::Write, callback(clock, true)))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));
        assert_eq!(
            *vfs.reservation_scopes.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![expected_scope]
        );
    }

    #[tokio::test]
    async fn failed_release_stays_in_bounded_outbox_until_retry_succeeds() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(1, 1, false),
            Duration::from_secs(30),
            clock.clone(),
            9,
        )
        .unwrap();
        let GrantOutcome::Granted(grant) = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("write delegation not granted");
        };
        vfs.fail_releases(2);

        manager.delegreturn(&context(1), object(1), grant.state_id).await.unwrap();
        assert_eq!(manager.active_counts().await, (0, 0));
        assert_eq!(manager.pending_cleanup(), 1);
        assert_eq!(
            manager
                .grant(request(2, object(2), DelegationKind::Write, callback(clock, true)))
                .await
                .unwrap(),
            GrantOutcome::NotGranted(GrantDenial::ResourceLimit)
        );

        let failed = manager.maintain_cleanup().await;
        assert_eq!(failed.released, 0);
        assert_eq!(failed.pending_releases, 1);
        assert_eq!(failed.pending_reconciliation, 0);
        assert!(matches!(failed.first_release_error, Some(DelegationError::Vfs(NfsError::Io))));
        assert_eq!(failed.first_reconciliation_error, None);

        let progress = manager.maintain_cleanup().await;
        assert_eq!(progress.released, 1);
        assert!(progress.drained);
        assert_eq!(manager.pending_cleanup(), 0);
        assert_eq!(vfs.successful_releases.load(Ordering::SeqCst), 1);
        let tokens = vfs.released_tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(tokens.len(), 3);
        assert!(tokens.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[tokio::test]
    async fn durable_expiry_tombstone_blocks_conflicting_grant_before_backend_work() {
        let store = Arc::new(FailOnceStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = durable_manager(vfs.clone(), clock.clone(), fail_once_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(grant) = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("durable delegation not granted");
        };

        clock.advance(Duration::from_secs(30));
        let fence = manager.renewal_fence().await;
        assert_eq!(manager.revoke_expired_while_fenced().await.unwrap().len(), 1);
        drop(fence);

        // The deletion is the authorization boundary.  A failed tombstone
        // commit must reach the caller before a conflicting WRITE grant can
        // probe eligibility or reserve backend space.
        store.fail_next_commit();
        let eligibility_before = vfs.eligibility_calls.load(Ordering::SeqCst);
        assert!(matches!(
            manager
                .grant(request(2, object(1), DelegationKind::Write, callback(clock.clone(), true)))
                .await,
            Err(DelegationError::StableState(_))
        ));
        assert_eq!(vfs.eligibility_calls.load(Ordering::SeqCst), eligibility_before);
        assert_eq!(manager.active_counts().await, (0, 0));
        assert_eq!(manager.pending_detached_removals.load(Ordering::Acquire), 1);

        let GrantOutcome::Granted(replacement) = manager
            .grant(request(2, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .expect("retry drains the tombstone before grant persistence")
        else {
            panic!("durably revoked delegation blocked replacement grant");
        };
        let replacement_record = replacement
            .persistent_record
            .clone()
            .expect("durable replacement retains a stable record");
        assert_ne!(replacement.state_id, grant.state_id);
        assert_eq!(manager.pending_detached_removals.load(Ordering::Acquire), 0);
        drop(manager);
        let restarted = durable_manager(vfs, clock, fail_once_journal(store, 200).await);
        assert_eq!(restarted.recovered_delegations().await, vec![replacement_record]);
    }

    #[tokio::test]
    async fn detached_outbox_publication_is_atomic_with_concurrent_maintenance() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = Arc::new(
            DelegationManager::with_boot_tag(vfs, policy(1, 1, false), Duration::from_secs(30), clock.clone(), 9)
                .unwrap(),
        );
        let GrantOutcome::Granted(grant) = manager
            .grant(request(1, object(1), DelegationKind::Read, callback(clock, true)))
            .await
            .unwrap()
        else {
            panic!("delegation not granted");
        };

        // This is the former publication window: maintenance is started
        // after map insertion but before the state guard is released.  The
        // count is now published under that same guard, so maintenance can
        // only observe both pieces of the outbox state or neither.
        let mut state = manager.state.lock().await;
        let removed =
            remove_record(&mut state, grant.state_id.other, &manager.client_state).expect("granted delegation is live");
        assert!(state.detached_removals.insert(grant.state_id.other, removed).is_none());
        manager.pending_detached_removals.fetch_add(1, Ordering::Release);
        let maintenance = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.maintain_cleanup().await })
        };
        tokio::task::yield_now().await;
        drop(state);
        let progress = maintenance.await.expect("maintenance task did not panic");
        assert!(progress.drained);
        assert_eq!(progress.pending_detached_removals, 0);
        assert_eq!(manager.pending_cleanup(), 0);
    }

    #[tokio::test]
    async fn oversized_backend_reservation_token_is_rejected_and_cleaned_up() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        vfs.reservation_token_size
            .store(crate::vfs::MAX_DELEGATION_RESERVATION_TOKEN_SIZE + 1, Ordering::SeqCst);
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(1, 1, false),
            Duration::from_secs(30),
            clock.clone(),
            9,
        )
        .unwrap();

        assert_eq!(
            manager
                .grant(request(1, object(1), DelegationKind::Write, callback(clock, true)))
                .await,
            Err(DelegationError::Vfs(NfsError::Invalid))
        );
        assert_eq!(manager.active_counts().await, (0, 0));
        assert_eq!(manager.pending_cleanup(), 0);
        assert_eq!(vfs.successful_releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_release_attempt_retains_token_for_maintenance() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = Arc::new(
            DelegationManager::with_boot_tag(
                vfs.clone(),
                policy(1, 1, false),
                Duration::from_secs(30),
                clock.clone(),
                9,
            )
            .unwrap(),
        );
        let GrantOutcome::Granted(grant) = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock, true)))
            .await
            .unwrap()
        else {
            panic!("write delegation not granted");
        };
        vfs.block_releases();
        let task = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.delegreturn(&context(1), object(1), grant.state_id).await })
        };
        tokio::time::timeout(Duration::from_secs(1), vfs.release_entered.notified())
            .await
            .expect("release attempt entered backend");
        task.abort();
        assert!(tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cancelled release task stopped")
            .unwrap_err()
            .is_cancelled());
        assert_eq!(manager.pending_cleanup(), 1);
        assert_eq!(manager.active_counts().await, (0, 0));

        vfs.unblock_releases();
        let progress = tokio::time::timeout(Duration::from_secs(1), manager.maintain_cleanup())
            .await
            .expect("release retry completed");
        assert_eq!(progress.released, 1);
        assert!(progress.drained);
    }

    #[tokio::test]
    async fn shutdown_extracts_active_reservations_without_deleting_stable_records() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(grant) = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("write delegation not granted");
        };
        let persistent = grant.persistent_record.unwrap();
        vfs.fail_releases(1);

        let first = manager.shutdown_cleanup().await;
        assert!(!first.drained);
        assert_eq!(first.pending, 1);
        assert_eq!(manager.active_counts().await, (0, 0));

        let second = manager.shutdown_cleanup().await;
        assert!(second.drained);
        assert_eq!(second.released, 1);
        drop(manager);

        let restarted = durable_manager(vfs, clock, durable_journal(store, 200).await);
        assert_eq!(restarted.recovered_delegations().await, vec![persistent]);
    }

    #[tokio::test]
    async fn concurrent_write_grant_race_releases_losing_reservation() {
        let mut raw_vfs = MockVfs::new(DelegationEligibility::Eligible);
        raw_vfs.barrier = Some(Arc::new(Barrier::new(2)));
        let vfs = Arc::new(raw_vfs);
        let clock = Arc::new(ManualClock::default());
        let manager = Arc::new(
            DelegationManager::with_boot_tag(
                vfs.clone(),
                policy(4, 4, false),
                Duration::from_secs(30),
                clock.clone(),
                9,
            )
            .unwrap(),
        );
        let left = {
            let manager = manager.clone();
            let callback = callback(clock.clone(), true);
            tokio::spawn(async move {
                manager
                    .grant(request(1, object(1), DelegationKind::Write, callback))
                    .await
                    .unwrap()
            })
        };
        let right = {
            let manager = manager.clone();
            let callback = callback(clock, true);
            tokio::spawn(async move {
                manager
                    .grant(request(2, object(1), DelegationKind::Write, callback))
                    .await
                    .unwrap()
            })
        };
        let outcomes = [left.await.unwrap(), right.await.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, GrantOutcome::Granted(_)))
                .count(),
            1
        );
        assert_eq!(vfs.reservations.load(Ordering::SeqCst), 2);
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn conflict_marks_recall_and_returns_delay_until_delegreturn() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager =
            DelegationManager::with_boot_tag(vfs, policy(4, 4, false), Duration::from_secs(30), clock.clone(), 9)
                .unwrap();
        let outcome = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock, true)))
            .await
            .unwrap();
        let GrantOutcome::Granted(grant) = outcome else {
            panic!("delegation not granted");
        };

        let conflict = manager.begin_conflict(object(1), 2, DelegationKind::Read, false).await.unwrap();
        assert_eq!(conflict.status, NfsStatus::Delay);
        assert_eq!(conflict.recalls.len(), 1);
        assert!(matches!(
            manager
                .execute_recall(conflict.recalls.into_iter().next().unwrap())
                .await
                .unwrap(),
            RecallOutcome::Delivered
        ));
        let repeated = manager.begin_conflict(object(1), 2, DelegationKind::Read, false).await.unwrap();
        assert_eq!(repeated.status, NfsStatus::Delay);
        assert!(repeated.recalls.is_empty());

        manager.delegreturn(&context(1), object(1), grant.state_id).await.unwrap();
        assert_eq!(
            manager
                .begin_conflict(object(1), 2, DelegationKind::Read, false)
                .await
                .unwrap()
                .status,
            NfsStatus::Ok
        );
    }

    #[tokio::test]
    async fn recall_translates_deadline_between_clock_origins() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let manager_clock = Arc::new(ManualClock::default());
        let callback_clock = Arc::new(ManualClock::default());
        callback_clock.advance(Duration::from_secs(100));
        let manager =
            DelegationManager::with_boot_tag(vfs, policy(4, 4, false), Duration::from_secs(30), manager_clock, 9)
                .unwrap();
        assert!(matches!(
            manager
                .grant(request(1, object(1), DelegationKind::Write, callback(callback_clock, true),))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));

        let conflict = manager.begin_conflict(object(1), 2, DelegationKind::Read, false).await.unwrap();
        assert!(matches!(
            manager
                .execute_recall(conflict.recalls.into_iter().next().unwrap())
                .await
                .unwrap(),
            RecallOutcome::Delivered
        ));
    }

    #[tokio::test]
    async fn failed_recall_retries_to_expiry_then_revokes_and_releases() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(4, 4, false),
            Duration::from_millis(25),
            clock.clone(),
            9,
        )
        .unwrap();
        assert!(matches!(
            manager
                .grant(request(1, object(1), DelegationKind::Write, callback_with_behavior(clock, true, true),))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));
        let conflict = manager.begin_conflict(object(1), 2, DelegationKind::Read, false).await.unwrap();
        let outcome = manager
            .execute_recall(conflict.recalls.into_iter().next().unwrap())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            RecallOutcome::Revoked {
                revoked: Some(RevokedDelegation {
                    reason: RevocationReason::LeaseExpired,
                    ..
                }),
                ..
            }
        ));
        assert_eq!(manager.active_counts().await, (0, 0));
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn renew_during_failed_recall_prevents_stale_revocation_and_reports_path_down() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ControlledClock::default());
        let transport = Arc::new(ControlledRecallTransport::default());
        transport.fail_recall.store(true, Ordering::SeqCst);
        let manager = Arc::new(
            DelegationManager::with_boot_tag(
                vfs.clone(),
                policy(4, 4, false),
                Duration::from_secs(30),
                clock.clone(),
                9,
            )
            .unwrap(),
        );
        let GrantOutcome::Granted(grant) = manager
            .grant(request(
                1,
                object(1),
                DelegationKind::Write,
                callback_for_transport(clock.clone(), transport.clone()),
            ))
            .await
            .unwrap()
        else {
            panic!("delegation not granted");
        };

        let conflict = manager.begin_conflict(object(1), 2, DelegationKind::Read, false).await.unwrap();
        let recall = conflict.recalls.into_iter().next().unwrap();
        let recall_manager = manager.clone();
        let recall_task = tokio::spawn(async move { recall_manager.execute_recall(recall).await });
        tokio::time::timeout(Duration::from_secs(1), transport.recall_attempted.notified())
            .await
            .expect("first callback attempt started");

        // Mirror the production RENEW critical section: the accepted runtime
        // renewal and delegation update are fenced against a callback that is
        // simultaneously exhausting begin_conflict's captured deadline.
        let renewal_fence = manager.renewal_fence().await;
        clock.advance_to(Duration::from_millis(29_990));
        tokio::task::yield_now().await;
        clock.advance_to(Duration::from_secs(30));
        tokio::task::yield_now().await;
        assert_eq!(manager.renew_client(&context(1), 1).await, Ok(()));
        drop(renewal_fence);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if manager.client_state.callback_path_down(1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed callback path was recorded");

        // CB_PATH_DOWN is advisory: this RENEW still extends the live
        // delegation, and the in-flight recall continues against that lease.
        assert_eq!(manager.renew_client(&context(1), 1).await, Err(NfsStatus::CallbackPathDown));
        assert_eq!(
            manager
                .state
                .lock()
                .await
                .records
                .get(&grant.state_id.other)
                .expect("renewed delegation remains active")
                .grant
                .lease_expires_at,
            Duration::from_secs(60)
        );
        assert_eq!(manager.active_counts().await, (0, 1));
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 0);

        transport.fail_recall.store(false, Ordering::SeqCst);
        clock.advance_to(Duration::from_secs(31));
        let outcome = tokio::time::timeout(Duration::from_secs(1), recall_task)
            .await
            .expect("renewed recall completed")
            .expect("recall task joined")
            .unwrap();
        assert!(matches!(outcome, RecallOutcome::Delivered));
        assert_eq!(manager.active_counts().await, (0, 1));
        assert_eq!(manager.renew_client(&context(1), 1).await, Ok(()));
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn callback_health_is_shared_across_export_managers_until_the_path_recovers() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let client_state = DelegationClientState::new();
        let manager = |boot_tag| {
            DelegationManager::with_boot_tag_stable_state_and_scope(
                vfs.clone(),
                policy(4, 4, false),
                Duration::from_secs(30),
                clock.clone(),
                boot_tag,
                None,
                None,
                None,
                StableFenceToken::new(Bytes::copy_from_slice(&boot_tag.to_be_bytes())),
                client_state.clone(),
            )
            .unwrap()
        };
        let first = manager(9);
        let second = manager(10);
        let GrantOutcome::Granted(first_grant) = first
            .grant(request(1, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("first export delegation not granted");
        };
        assert!(matches!(
            second
                .grant(request(1, object(2), DelegationKind::Write, callback(clock.clone(), true)))
                .await
                .unwrap(),
            GrantOutcome::Granted(_)
        ));

        client_state.mark_callback_path_down(1);
        first.delegreturn(&context(1), object(1), first_grant.state_id).await.unwrap();
        assert_eq!(second.renew_client(&context(1), 1).await, Err(NfsStatus::CallbackPathDown));

        let conflict = second.begin_conflict(object(2), 2, DelegationKind::Read, false).await.unwrap();
        assert!(matches!(
            second
                .execute_recall(conflict.recalls.into_iter().next().unwrap())
                .await
                .unwrap(),
            RecallOutcome::Delivered
        ));
        assert_eq!(second.renew_client(&context(1), 1).await, Ok(()));
    }

    #[tokio::test]
    async fn lease_expiry_revokes_and_releases_write_space() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = DelegationManager::with_boot_tag(
            vfs.clone(),
            policy(4, 4, false),
            Duration::from_secs(5),
            clock.clone(),
            9,
        )
        .unwrap();
        let outcome = manager
            .grant(request(1, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap();
        assert!(matches!(outcome, GrantOutcome::Granted(_)));
        clock.advance(Duration::from_secs(5));
        let revoked = manager.revoke_expired().await.unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].reason, RevocationReason::LeaseExpired);
        assert_eq!(manager.active_counts().await, (0, 0));
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn durable_grants_hydrate_as_reclaim_candidates_after_clean_and_unclean_restart() {
        for clean_shutdown in [false, true] {
            let store = Arc::new(DurableFakeStore::default());
            let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
            let clock = Arc::new(ManualClock::default());
            let first = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);
            let outcome = first
                .grant(request(41, object(1), DelegationKind::Read, callback(clock.clone(), true)))
                .await
                .unwrap();
            let GrantOutcome::Granted(grant) = outcome else {
                panic!("durable delegation not granted");
            };
            let persistent = grant.persistent_record.unwrap();
            if clean_shutdown {
                first
                    .stable_journal
                    .as_ref()
                    .unwrap()
                    .lock()
                    .await
                    .mark_clean_shutdown()
                    .await
                    .unwrap();
            }
            drop(first);

            let restarted_journal = durable_journal(store, 200).await;
            assert_eq!(
                restarted_journal.recovery().previous_shutdown,
                if clean_shutdown {
                    PreviousShutdown::Clean
                } else {
                    PreviousShutdown::Unclean
                }
            );
            let restarted = durable_manager(vfs, clock, restarted_journal);
            assert_eq!(restarted.recovered_delegations().await, vec![persistent.clone()]);
            assert_eq!(
                restarted
                    .recovered_delegation(persistent.client_id, &persistent.persistent_object_id, persistent.kind,)
                    .await,
                Some(persistent)
            );
            assert_eq!(restarted.active_counts().await, (0, 0));
            let removed = if clean_shutdown {
                restarted.revoke_unreclaimed(RevocationReason::Administration).await.unwrap()
            } else {
                restarted
                    .delegpurge_with_recovered_client_ids(&context(42), 42, &[41])
                    .await
                    .unwrap()
            };
            assert_eq!(removed, 1);
            assert!(restarted.recovered_delegations().await.is_empty());
        }
    }

    #[tokio::test]
    async fn recovered_delegations_remain_visible_by_object_until_revoked() {
        for kind in [DelegationKind::Read, DelegationKind::Write] {
            let store = Arc::new(DurableFakeStore::default());
            let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
            let clock = Arc::new(ManualClock::default());
            let first = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);
            let GrantOutcome::Granted(grant) = first
                .grant(request(41, object(1), kind, callback(clock.clone(), true)))
                .await
                .unwrap()
            else {
                panic!("durable delegation not granted");
            };
            let persistent = grant.persistent_record.unwrap();
            drop(first);

            let restarted = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 200).await);
            assert_eq!(persistent.object, object(1));
            assert_eq!(restarted.recovered_delegations().await, vec![persistent]);
            assert_eq!(restarted.delegated_getattr(object(1), Vec::new()).await, Err(NfsStatus::Grace));
            assert_eq!(restarted.delegated_getattr(object(2), Vec::new()).await, Ok(None));

            let conflicting_access = match kind {
                DelegationKind::Read => DelegationKind::Write,
                DelegationKind::Write => DelegationKind::Read,
            };
            let conflict = restarted
                .begin_conflict(object(1), 42, conflicting_access, false)
                .await
                .unwrap();
            assert_eq!(conflict.status, NfsStatus::Grace);
            assert!(conflict.recalls.is_empty());
            assert_eq!(
                restarted
                    .begin_conflict(object(2), 42, conflicting_access, false)
                    .await
                    .unwrap()
                    .status,
                NfsStatus::Ok
            );
            if kind == DelegationKind::Read {
                assert_eq!(
                    restarted
                        .begin_conflict(object(1), 42, DelegationKind::Read, false)
                        .await
                        .unwrap()
                        .status,
                    NfsStatus::Ok
                );
            }

            assert_eq!(restarted.revoke_unreclaimed(RevocationReason::Administration).await.unwrap(), 1);
            assert_eq!(restarted.delegated_getattr(object(1), Vec::new()).await, Ok(None));
            assert_eq!(
                restarted
                    .begin_conflict(object(1), 42, conflicting_access, false)
                    .await
                    .unwrap()
                    .status,
                NfsStatus::Ok
            );
        }
    }

    #[tokio::test]
    async fn failed_durable_commit_never_exposes_a_grant() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);
        store.advance_generation(&test_scope());

        assert!(matches!(
            manager
                .grant(request(41, object(1), DelegationKind::Write, callback(clock, true)))
                .await,
            Err(DelegationError::StableState(_))
        ));
        assert_eq!(manager.active_counts().await, (0, 0));
        assert_eq!(vfs.reservations.load(Ordering::SeqCst), 1);
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn construction_rejects_recovery_over_current_delegation_policy() {
        let store = Arc::new(DurableFakeStore::default());
        let journal = durable_journal(store, 100).await;
        let recovered = recovered_image([
            persistent_record(1, object(1), b"object-one", DelegationKind::Read, 1),
            persistent_record(2, object(2), b"object-two", DelegationKind::Read, 2),
        ]);
        assert!(matches!(
            DelegationManager::with_boot_tag_and_stable_state(
                Arc::new(MockVfs::new(DelegationEligibility::Eligible)),
                policy(1, 1, true),
                Duration::from_secs(30),
                Arc::new(ManualClock::default()),
                journal.boot().boot_tag,
                Some(Arc::new(Mutex::new(journal))),
                Some(&recovered),
                Some(ExportId(7)),
            ),
            Err(DelegationError::RecoveryConflict)
        ));
    }

    #[tokio::test]
    async fn construction_validates_the_complete_persistent_delegation_graph() {
        let shared_identity = b"shared-persistent-object";
        let first_read = persistent_record(1, object(1), shared_identity, DelegationKind::Read, 1);
        let second_read = persistent_record(2, object(2), shared_identity, DelegationKind::Read, 2);
        let compatible = recovered_image([first_read.clone(), second_read.clone()]);
        let journal = durable_journal(Arc::new(DurableFakeStore::default()), 100).await;
        let manager = DelegationManager::with_boot_tag_and_stable_state(
            Arc::new(MockVfs::new(DelegationEligibility::Eligible)),
            policy(2, 1, true),
            Duration::from_secs(30),
            Arc::new(ManualClock::default()),
            journal.boot().boot_tag,
            Some(Arc::new(Mutex::new(journal))),
            Some(&compatible),
            Some(ExportId(7)),
        )
        .unwrap();
        assert_eq!(manager.recovered_delegations().await.len(), 2);

        let duplicate_client = recovered_image([
            first_read.clone(),
            persistent_record(1, object(2), shared_identity, DelegationKind::Read, 3),
        ]);
        let journal = durable_journal(Arc::new(DurableFakeStore::default()), 200).await;
        assert!(matches!(
            DelegationManager::with_boot_tag_and_stable_state(
                Arc::new(MockVfs::new(DelegationEligibility::Eligible)),
                policy(2, 1, true),
                Duration::from_secs(30),
                Arc::new(ManualClock::default()),
                journal.boot().boot_tag,
                Some(Arc::new(Mutex::new(journal))),
                Some(&duplicate_client),
                Some(ExportId(7)),
            ),
            Err(DelegationError::RecoveryConflict)
        ));

        let mut reused_state_identity = persistent_record(2, object(2), b"other-object", DelegationKind::Read, 1);
        reused_state_identity.previous_state_id.other = second_read.previous_state_id.other;
        reused_state_identity.previous_state_id.sequence_id = 2;
        let duplicate_state_identity = recovered_image([second_read, reused_state_identity]);
        let journal = durable_journal(Arc::new(DurableFakeStore::default()), 250).await;
        assert!(matches!(
            DelegationManager::with_boot_tag_and_stable_state(
                Arc::new(MockVfs::new(DelegationEligibility::Eligible)),
                policy(2, 1, true),
                Duration::from_secs(30),
                Arc::new(ManualClock::default()),
                journal.boot().boot_tag,
                Some(Arc::new(Mutex::new(journal))),
                Some(&duplicate_state_identity),
                Some(ExportId(7)),
            ),
            Err(DelegationError::StableState(_))
        ));

        let read_write_conflict = recovered_image([
            first_read,
            persistent_record(2, object(2), shared_identity, DelegationKind::Write, 4),
        ]);
        let journal = durable_journal(Arc::new(DurableFakeStore::default()), 300).await;
        assert!(matches!(
            DelegationManager::with_boot_tag_and_stable_state(
                Arc::new(MockVfs::new(DelegationEligibility::Eligible)),
                policy(2, 1, true),
                Duration::from_secs(30),
                Arc::new(ManualClock::default()),
                journal.boot().boot_tag,
                Some(Arc::new(Mutex::new(journal))),
                Some(&read_write_conflict),
                Some(ExportId(7)),
            ),
            Err(DelegationError::RecoveryConflict)
        ));
    }

    #[tokio::test]
    async fn durable_reclaim_atomically_replaces_the_previous_record() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let first = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(first_grant) = first
            .grant(request(41, object(1), DelegationKind::Read, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("durable delegation not granted");
        };
        let previous = first_grant.persistent_record.unwrap();
        drop(first);

        let restarted = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 200).await);
        let GrantOutcome::Granted(reclaimed) = restarted
            .reclaim_previous(request(42, object(1), DelegationKind::Read, callback(clock, true)), &previous)
            .await
            .unwrap()
        else {
            panic!("durable delegation not reclaimed");
        };
        assert_ne!(reclaimed.state_id, previous.previous_state_id);
        assert_eq!(reclaimed.client_id, 42);
        assert!(restarted.recovered_delegations().await.is_empty());
        let current = reclaimed.persistent_record.unwrap();
        drop(restarted);

        let recovered = durable_journal(store, 300).await.recovery().records.clone();
        let delegations = recovered
            .iter()
            .filter_map(|(_, record)| match record {
                JournalRecord::Delegation(record) => Some(persistent_delegation_record(record).unwrap()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(delegations, vec![current]);
    }

    #[tokio::test]
    async fn open_journal_failure_rolls_reclaim_back_for_retry() {
        let store = Arc::new(FailOnceStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let first = durable_manager(vfs.clone(), clock.clone(), fail_once_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(first_grant) = first
            .grant(request(41, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("durable delegation not granted");
        };
        let previous = first_grant.persistent_record.unwrap();
        drop(first);

        let restarted = durable_manager(vfs.clone(), clock.clone(), fail_once_journal(store.clone(), 200).await);
        let PreparedReclaimOutcome::Prepared(prepared) = restarted
            .prepare_reclaim_previous(
                request(42, object(1), DelegationKind::Write, callback(clock.clone(), true)),
                &previous,
            )
            .await
            .unwrap()
        else {
            panic!("durable delegation reclaim was not prepared");
        };
        let replacement = prepared
            .grant()
            .persistent_record
            .clone()
            .expect("durable reclaim has a persistent record");
        assert!(restarted.recovered_delegations().await.is_empty());
        assert_eq!(restarted.active_counts().await, (0, 1));

        // Runtime OPEN and delegation persistence share this journal. Inject
        // the failure at the next commit, after the delegation replacement
        // has succeeded but before OPEN can be acknowledged.
        store.fail_next_commit();
        let open_commit = restarted
            .stable_journal
            .as_ref()
            .expect("durable manager has a journal")
            .lock()
            .await
            .persist_before_ack(PersistBatch::default().put(
                JournalKey::Delegation {
                    state_token: replacement.state_token(),
                },
                JournalRecord::Delegation(stable_delegation_record(&replacement)),
            ))
            .await;
        assert!(open_commit.is_err());

        restarted.rollback_reclaim(prepared).await.unwrap();
        assert_eq!(restarted.active_counts().await, (0, 0));
        assert_eq!(restarted.recovered_delegations().await, vec![previous.clone()]);
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
        drop(restarted);

        let retry = durable_manager(vfs, clock.clone(), fail_once_journal(store, 300).await);
        assert_eq!(retry.recovered_delegations().await, vec![previous.clone()]);
        let GrantOutcome::Granted(reclaimed) = retry
            .reclaim_previous(request(43, object(1), DelegationKind::Write, callback(clock, true)), &previous)
            .await
            .unwrap()
        else {
            panic!("rolled-back delegation was not reclaimable on retry");
        };
        assert_ne!(reclaimed.state_id, replacement.previous_state_id);
        assert!(retry.recovered_delegations().await.is_empty());
    }

    #[tokio::test]
    async fn failed_reclaim_rollback_is_fenced_until_maintenance_repairs_stable_state() {
        let store = Arc::new(FailOnceStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let first = durable_manager(vfs.clone(), clock.clone(), fail_once_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(first_grant) = first
            .grant(request(41, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("durable delegation not granted");
        };
        let previous = first_grant.persistent_record.unwrap();
        drop(first);

        let manager = durable_manager(vfs, clock.clone(), fail_once_journal(store.clone(), 200).await);
        let PreparedReclaimOutcome::Prepared(prepared) = manager
            .prepare_reclaim_previous(
                request(42, object(1), DelegationKind::Write, callback(clock.clone(), true)),
                &previous,
            )
            .await
            .unwrap()
        else {
            panic!("durable delegation reclaim was not prepared");
        };
        store.fail_next_commit();
        assert!(matches!(manager.rollback_reclaim(prepared).await, Err(DelegationError::StableState(_))));
        assert_eq!(manager.active_counts().await, (0, 0));
        assert!(manager.recovered_delegations().await.is_empty());
        assert_eq!(manager.pending_cleanup(), 1);
        assert_eq!(
            manager
                .reclaim_previous(request(43, object(1), DelegationKind::Write, callback(clock, true)), &previous,)
                .await
                .unwrap(),
            GrantOutcome::Delay
        );

        store.fail_next_commit();
        let failed = manager.maintain_cleanup().await;
        assert_eq!(failed.pending_releases, 0);
        assert_eq!(failed.pending_reconciliation, 1);
        assert_eq!(failed.first_release_error, None);
        assert!(matches!(failed.first_reconciliation_error, Some(DelegationError::StableState(_))));

        let progress = manager.maintain_cleanup().await;
        assert_eq!(progress.reconciled, 1);
        assert!(progress.drained);
        assert_eq!(manager.recovered_delegations().await, vec![previous]);
    }

    #[tokio::test]
    async fn restart_after_indeterminate_reclaim_rollback_has_only_replacement_identity() {
        let store = Arc::new(FailOnceStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let first = durable_manager(vfs.clone(), clock.clone(), fail_once_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(first_grant) = first
            .grant(request(41, object(1), DelegationKind::Read, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("durable delegation not granted");
        };
        let previous = first_grant.persistent_record.unwrap();
        drop(first);

        let manager = durable_manager(vfs.clone(), clock.clone(), fail_once_journal(store.clone(), 200).await);
        let PreparedReclaimOutcome::Prepared(prepared) = manager
            .prepare_reclaim_previous(
                request(42, object(1), DelegationKind::Read, callback(clock.clone(), true)),
                &previous,
            )
            .await
            .unwrap()
        else {
            panic!("durable delegation reclaim was not prepared");
        };
        let replacement = prepared.grant().persistent_record.clone().unwrap();
        store.fail_next_commit();
        assert!(manager.rollback_reclaim(prepared).await.is_err());
        assert!(manager.recovered_delegations().await.is_empty());
        drop(manager);

        let restarted = durable_manager(vfs, clock, fail_once_journal(store, 300).await);
        let recovered = restarted.recovered_delegations().await;
        assert_eq!(recovered, vec![replacement]);
        assert!(!recovered.contains(&previous));
    }

    #[tokio::test]
    async fn durable_reclaim_requires_the_exact_recovered_object_key() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let first = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);
        let GrantOutcome::Granted(first_grant) = first
            .grant(request(41, object(1), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("durable delegation not granted");
        };
        let previous = first_grant.persistent_record.unwrap();
        drop(first);

        let restarted = durable_manager(vfs, clock.clone(), durable_journal(store, 200).await);
        assert!(matches!(
            restarted
                .reclaim_previous(
                    request(42, object(2), DelegationKind::Write, callback(clock.clone(), true),),
                    &previous,
                )
                .await,
            Err(DelegationError::ReclaimMismatch)
        ));
        assert_eq!(
            restarted
                .begin_conflict(object(1), 42, DelegationKind::Read, false)
                .await
                .unwrap()
                .status,
            NfsStatus::Grace
        );

        let GrantOutcome::Granted(reclaimed) = restarted
            .reclaim_previous(request(42, object(1), DelegationKind::Write, callback(clock, true)), &previous)
            .await
            .unwrap()
        else {
            panic!("durable delegation not reclaimed");
        };
        assert_eq!(reclaimed.object, object(1));
        assert!(restarted.recovered_delegations().await.is_empty());
        assert_eq!(
            restarted
                .begin_conflict(object(1), 42, DelegationKind::Read, false)
                .await
                .unwrap()
                .status,
            NfsStatus::Ok
        );
        let conflict = restarted
            .begin_conflict(object(1), 43, DelegationKind::Read, false)
            .await
            .unwrap();
        assert_eq!(conflict.status, NfsStatus::Delay);
        assert_eq!(conflict.recalls.len(), 1);
    }

    #[tokio::test]
    async fn durable_return_purge_and_expiry_remove_reclaimable_records() {
        let store = Arc::new(DurableFakeStore::default());
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 100).await);

        let GrantOutcome::Granted(returned) = manager
            .grant(request(1, object(1), DelegationKind::Read, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("return delegation not granted");
        };
        manager.delegreturn(&context(1), object(1), returned.state_id).await.unwrap();

        let GrantOutcome::Granted(expired) = manager
            .grant(request(2, object(2), DelegationKind::Write, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("expiry delegation not granted");
        };
        clock.advance(Duration::from_secs(30));
        assert_eq!(manager.revoke_expired().await.unwrap().len(), 1);
        drop(manager);

        let restarted = durable_manager(vfs.clone(), clock.clone(), durable_journal(store.clone(), 200).await);
        assert!(restarted.recovered_delegations().await.is_empty());
        let recovery = restarted
            .stable_journal
            .as_ref()
            .unwrap()
            .lock()
            .await
            .recovery()
            .records
            .clone();
        assert!(recovery.iter().all(|(key, record)| {
            !matches!(
                (key, record),
                (
                    JournalKey::Delegation {
                        state_token: durable_token
                    },
                    JournalRecord::Delegation(_)
                ) if *durable_token == state_token(expired.state_id)
            ) && !matches!(record, JournalRecord::Revocation(_))
        }));

        let GrantOutcome::Granted(purged) = restarted
            .grant(request(3, object(3), DelegationKind::Read, callback(clock.clone(), true)))
            .await
            .unwrap()
        else {
            panic!("purge delegation not granted");
        };
        assert!(purged.persistent_record.is_some());
        assert_eq!(restarted.delegpurge(&context(3), 3).await.unwrap(), 1);
        drop(restarted);

        let final_journal = durable_journal(store, 300).await;
        assert!(!final_journal
            .recovery()
            .records
            .iter()
            .any(|(_, record)| matches!(record, JournalRecord::Delegation(_))));
    }

    #[tokio::test]
    async fn persistent_record_round_trip_and_previous_reclaim_gets_fresh_stateid() {
        let vfs = Arc::new(MockVfs::new(DelegationEligibility::Eligible));
        let clock = Arc::new(ManualClock::default());
        let manager =
            DelegationManager::with_boot_tag(vfs, policy(4, 4, true), Duration::from_secs(30), clock.clone(), 9)
                .unwrap();
        let outcome = manager
            .grant(request(1, object(1), DelegationKind::Read, callback(clock.clone(), true)))
            .await
            .unwrap();
        let GrantOutcome::Granted(grant) = outcome else {
            panic!("persistent delegation not granted");
        };
        let record = grant.persistent_record.unwrap();
        let encoded = record.encode().unwrap();
        assert_eq!(PersistentDelegationRecord::decode(&encoded).unwrap(), record);
        assert_eq!(&encoded[..16], &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7]);

        manager.delegpurge(&context(1), 1).await.unwrap();
        let reclaimed = manager
            .reclaim_previous(request(1, object(1), DelegationKind::Read, callback(clock, true)), &record)
            .await
            .unwrap();
        let GrantOutcome::Granted(reclaimed) = reclaimed else {
            panic!("persistent delegation not reclaimed");
        };
        assert_ne!(reclaimed.state_id, record.previous_state_id);
        assert!(manager
            .claim_delegate_current(&context(1), object(1), reclaimed.state_id)
            .await
            .is_ok());
    }

    #[test]
    fn persistent_record_rejects_unbounded_object_identity() {
        let mut encoded = Encoder::new();
        encoded.write_u32(PERSISTENT_RECORD_VERSION);
        encoded.write_u64(1);
        encoded.write_u32(7);
        encoded.write_u64(1);
        encoded.write_u64(1);
        encoded.write_u32((MAX_PERSISTENT_OBJECT_ID + 1) as u32);
        assert!(matches!(
            PersistentDelegationRecord::decode(&encoded.into_bytes()),
            Err(PersistentRecordError::Decode(DecodeError::LimitExceeded { .. }))
        ));
    }
}
