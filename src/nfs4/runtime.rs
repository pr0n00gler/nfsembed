//! Shared, bounded NFSv4.0 client and locking state.
//!
//! The runtime is process-wide rather than connection-local so owner sequence
//! replay, leases, share reservations, and byte-range locks survive transport
//! reconnects.  Stateful operations use reservation/finalization APIs: no
//! registry mutex is held while an application VFS future is awaited.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedMutexGuard};

use super::codec::{decode_compound_res, encode_compound_res};
use super::stable::{
    ClientRecord as StableClientRecord, JournalKey, JournalRecord, LockRangeRecord as StableLockRangeRecord,
    LockRecord as StableLockRecord, OpenContributionRecord as StableOpenContributionRecord,
    OpenRecord as StableOpenRecord, PersistBatch, PreviousShutdown, RecoveredStableState, ReplayOwnerKind,
    ReplayRecord, ReplayRenewalSource, StableJournal, StableObject,
};
use super::state::lease::{LeaseClock, LeaseError, LeaseTable, SystemLeaseClock};
use super::state::locks::{LockAccess, LockRange, LockRecord, LockTable};
use super::state::owner::{OwnerRequestDigest, OwnerSequence, SequenceDecision};
use super::state::recovery::{RecoveryError, RecoveryMode, RecoveryState};
use super::state::share::{ShareAccess, ShareContributions, ShareDeny, ShareOpenError, ShareTable};
use super::state::stateid::{StateDisposition, StateIdTable, StateIdValidation, StateIdValidationError, StateKind};
use super::types::{
    Bitmap, CallbackClient, ChangeInfo, ClientAddress, CompoundRes, ExistingLockOwner, LockArgs, LockDenied, LockOwner,
    LockResult, LockTestArgs, LockTestResult, LockType, LockUnlockArgs, Locker, NfsResult, NfsStatus, OpenDelegation,
    OpenOk, OpenOwner, OpenToLockOwner, ResOp, SetClientIdArgs, SetClientIdOk, SetClientIdResult, StateId,
};
use crate::server::Nfs4Limits;
use crate::vfs::{DelegationKind, ExportId, ObjectKey, Principal};

const STATE_SHARDS: usize = 64;
const OPEN4_RESULT_CONFIRM: u32 = 0x0000_0002;
const OPEN4_RESULT_LOCKTYPE_POSIX: u32 = 0x0000_0004;

#[derive(Clone)]
pub(crate) struct RuntimeConfig {
    pub lease_duration: Duration,
    pub grace_duration: Duration,
    pub limits: Nfs4Limits,
    pub boot_tag: u32,
    pub write_verifier: [u8; 8],
    pub stable_journal: Option<Arc<AsyncMutex<StableJournal>>>,
    pub recovered: Option<RecoveredStableState>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RuntimeFile {
    pub export_id: ExportId,
    pub object: ObjectKey,
}

impl RuntimeFile {
    fn stable(self) -> StableObject {
        StableObject {
            export_id: self.export_id,
            file_id: self.object.file_id,
            generation: self.object.generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReplayEffect {
    pub current_file: Option<RuntimeFile>,
    /// A delegation stateid authenticated while executing an OPEN claim.
    ///
    /// This is retained with the owner replay so an exact
    /// `CLAIM_DELEGATE_CUR` retry renews delegation leases by the stateid
    /// rule rather than treating its clientid as an ordinary OPEN renewal.
    pub stateid_renewal_client: Option<u64>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum StatefulDecision<T> {
    Execute(T),
    Replay { result: ResOp, effect: ReplayEffect },
    Error(NfsStatus),
}

/// OPEN owner sequencing together with the client identity authenticated by a
/// valid clientid.  The identity is retained for every post-authentication
/// result, including BAD_SEQID and RESOURCE, so the compound layer can apply
/// RFC 7530 §9.5 renewal before committing the cached owner response.
pub(crate) enum OpenDecision {
    Execute(OpenReservation),
    Replay {
        result: ResOp,
        effect: ReplayEffect,
        client_id: Option<u64>,
    },
    Error {
        status: NfsStatus,
        client_id: Option<u64>,
    },
}

/// Result of an OPEN-state operation after owner sequencing has established
/// whether the supplied stateid authenticated a client.  The optional client
/// on an error is intentionally separate from its status: RFC 7530 section
/// 9.5 renews a lease once state identity was authenticated even when a later
/// state or sequence check rejects the operation.
pub(crate) enum OpenStateDecision {
    Execute(OpenStateReservation),
    Replay {
        result: ResOp,
        #[cfg_attr(not(test), allow(dead_code))]
        effect: ReplayEffect,
        client_id: u64,
    },
    Error {
        status: NfsStatus,
        client_id: Option<u64>,
    },
}

/// Stateid I/O validation error with the client identity that was
/// authenticated before the later operation-specific error occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoValidationError {
    pub status: NfsStatus,
    pub client_id: Option<u64>,
}

/// The final status of client authentication together with evidence that a
/// confirmed clientid or non-special stateid was valid before a later lease
/// or recovery gate rejected the operation.  RFC 7530 §9.5 renewal depends
/// on that evidence, not on whether the final operation status is success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientAuthenticationError {
    status: NfsStatus,
    client_id: Option<u64>,
}

impl ClientAuthenticationError {
    const fn unauthenticated(status: NfsStatus) -> Self {
        Self {
            status,
            client_id: None,
        }
    }

    const fn authenticated(status: NfsStatus, client_id: u64) -> Self {
        Self {
            status,
            client_id: Some(client_id),
        }
    }
}

/// Owner-sequencing result for LOCK and LOCKU before their supplied stateid is
/// sequence-validated.  This preserves the RFC 7530 owner-seqid precedence:
/// an exact replay is returned even after a successful operation advanced the
/// stateid, and BAD_SEQID wins over an old or otherwise bad stateid.
pub(crate) enum LockPreflight {
    Execute { client_id: u64 },
    Replay { client_id: u64, result: ResOp },
    Error { status: NfsStatus, client_id: Option<u64> },
}

/// LOCKT's result together with any clientid that was authenticated before a
/// later recovery or lease gate selected its final status.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LockTestDecision {
    pub result: LockTestResult,
    pub client_id: Option<u64>,
}

/// RELEASE_LOCKOWNER's authenticated preflight result.  Stable replay-record
/// deletion is intentionally deferred until after delegation renewal fences
/// have been dropped by the compound executor.
pub(crate) enum ReleaseLockOwnerDecision {
    Execute { client_id: u64 },
    Error { status: NfsStatus, client_id: Option<u64> },
}

impl IoValidationError {
    const fn unauthenticated(status: NfsStatus) -> Self {
        Self {
            status,
            client_id: None,
        }
    }

    const fn authenticated(status: NfsStatus, client_id: u64) -> Self {
        Self {
            status,
            client_id: Some(client_id),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Nfs4Runtime {
    core: Arc<RuntimeCore>,
}

struct RuntimeCore {
    clients: AsyncMutex<ClientRegistry>,
    state: Mutex<StateRegistry>,
    files: Box<[Mutex<FileShard>]>,
    operation_gates: Box<[Arc<AsyncMutex<()>>]>,
    client_state_transition_gate: Arc<AsyncMutex<()>>,
    limits: Nfs4Limits,
    lease_duration: Duration,
    grace_duration: Duration,
    write_verifier: [u8; 8],
    stable_journal: Option<Arc<AsyncMutex<StableJournal>>>,
    critical_tasks: Arc<CriticalTaskTracker>,
}

#[derive(Default)]
struct CriticalTaskTracker {
    active: AtomicUsize,
    failed: AtomicBool,
    idle: Notify,
}

impl CriticalTaskTracker {
    fn start(self: &Arc<Self>) -> CriticalTaskGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        CriticalTaskGuard {
            tracker: Arc::clone(self),
        }
    }

    async fn wait(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                assert!(!self.failed.load(Ordering::Acquire), "a cancellation-shielded protocol transition failed");
                return;
            }
            notified.await;
        }
    }
}

struct CriticalTaskGuard {
    tracker: Arc<CriticalTaskTracker>,
}

impl Drop for CriticalTaskGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.tracker.failed.store(true, Ordering::Release);
        }
        let previous = self.tracker.active.fetch_sub(1, Ordering::AcqRel);
        assert_ne!(previous, 0, "critical-task tracker underflow");
        if previous == 1 {
            self.tracker.idle.notify_waiters();
        }
    }
}

struct ClientRegistry {
    slots: HashMap<Vec<u8>, ClientSlot>,
    client_owners: HashMap<u64, Vec<u8>>,
    expired: HashSet<u64>,
    pending_expiry: HashSet<u64>,
    moved_leases: MovedLeaseTracker,
    leases: LeaseTable<u64, Arc<dyn LeaseClock>>,
    recovery: RecoveryState<u64, Arc<dyn LeaseClock>>,
    recovered_clients: HashMap<RecoveredClientIdentity, Vec<u64>>,
    current_to_previous: HashMap<u64, Vec<u64>>,
    recovery_had_grace: bool,
    grace_cleanup_complete: bool,
    clock: Arc<dyn LeaseClock>,
    lease_duration: Duration,
    grace_duration: Duration,
    boot_tag: u32,
    next_client: u32,
    next_confirmation: u64,
}

/// Bounded RFC 7931 lease-migration notifications.
///
/// One entry represents one confirmed client's obligation to discover the
/// location of one moved export.  The state-object limit is a conservative
/// upper bound. The additional client allowance covers an OPEN that discovers
/// migration before it can acquire its first state object.
#[derive(Debug)]
struct MovedLeaseTracker {
    by_client: HashMap<u64, HashMap<ExportId, MovedLeaseObligation>>,
    entries: usize,
    capacity: usize,
    legacy_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MovedLeaseObligation {
    Pending { first_notified: Duration },
    LegacyTimedOut,
}

impl MovedLeaseTracker {
    fn new(capacity: usize, lease_duration: Duration) -> Self {
        Self {
            by_client: HashMap::new(),
            entries: 0,
            capacity,
            legacy_timeout: lease_duration.saturating_mul(2),
        }
    }

    fn note(&mut self, client_id: u64, export_id: ExportId, now: Duration) -> Result<(), NfsStatus> {
        self.expire_all(now);
        if self
            .by_client
            .get(&client_id)
            .is_some_and(|exports| exports.contains_key(&export_id))
        {
            return Ok(());
        }
        if self.entries >= self.capacity {
            return Err(NfsStatus::Resource);
        }
        self.by_client
            .entry(client_id)
            .or_default()
            .insert(export_id, MovedLeaseObligation::Pending { first_notified: now });
        self.entries += 1;
        Ok(())
    }

    fn clear(&mut self, client_id: u64, export_id: ExportId) -> bool {
        let Some(exports) = self.by_client.get_mut(&client_id) else {
            return false;
        };
        let removed = exports.remove(&export_id).is_some();
        if removed {
            self.entries = self.entries.saturating_sub(1);
        }
        if exports.is_empty() {
            self.by_client.remove(&client_id);
        }
        removed
    }

    fn has_live(&mut self, client_id: u64, now: Duration) -> bool {
        self.expire_client(client_id, now);
        self.by_client.get(&client_id).is_some_and(|exports| {
            exports
                .values()
                .any(|obligation| matches!(obligation, MovedLeaseObligation::Pending { .. }))
        })
    }

    fn remove_client(&mut self, client_id: u64) {
        if let Some(exports) = self.by_client.remove(&client_id) {
            self.entries = self.entries.saturating_sub(exports.len());
        }
    }

    fn expire_client(&mut self, client_id: u64, now: Duration) {
        let Some(exports) = self.by_client.get_mut(&client_id) else {
            return;
        };
        let timeout = self.legacy_timeout;
        for obligation in exports.values_mut() {
            if let MovedLeaseObligation::Pending { first_notified } = obligation {
                if now.saturating_sub(*first_notified) >= timeout {
                    *obligation = MovedLeaseObligation::LegacyTimedOut;
                }
            }
        }
    }

    fn expire_all(&mut self, now: Duration) {
        let clients = self.by_client.keys().copied().collect::<Vec<_>>();
        for client_id in clients {
            self.expire_client(client_id, now);
        }
    }
}

#[derive(Clone, Debug)]
struct ClientSlot {
    confirmed: Option<ClientRecord>,
    unconfirmed: Option<ClientRecord>,
}

#[derive(Clone, Debug)]
struct ClientRecord {
    client_id: u64,
    owner: Vec<u8>,
    verifier: [u8; 8],
    confirmation: [u8; 8],
    setclientid_principal: Principal,
    callback: CallbackClient,
    callback_identifier: u32,
    created_at: Duration,
    reclaimable: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RecoveredClientIdentity {
    owner: Vec<u8>,
    verifier: [u8; 8],
    principal: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveredOpen {
    state_token: [u8; 16],
    previous_client_id: u64,
    owner: Vec<u8>,
    file: RuntimeFile,
    access: ShareAccess,
    deny: ShareDeny,
    contributions: ShareContributions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveredLock {
    state_token: [u8; 16],
    previous_open_state_token: [u8; 16],
    previous_client_id: u64,
    owner: Vec<u8>,
    file: RuntimeFile,
    ranges: Vec<RecoveredLockRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveredLockRange {
    access: LockAccess,
    range: LockRange,
}

type RecoveredReplay = (u32, OwnerRequestDigest, ResOp, ReplayEffect);

#[derive(Clone, Debug, Default)]
struct RecoveredRuntimeState {
    clients: HashMap<RecoveredClientIdentity, Vec<u64>>,
    opens: HashMap<[u8; 16], RecoveredOpen>,
    locks: HashMap<[u8; 16], RecoveredLock>,
    replays: HashMap<(u64, ReplayOwnerKind, Vec<u8>), RecoveredReplay>,
    cleanup_keys: HashSet<JournalKey>,
}

/// A fully validated recovery image that can be held while a migration import
/// remains staged, then atomically made visible to a quiesced runtime only
/// after the durable migration commit succeeds.
#[derive(Clone, Debug)]
pub(crate) struct PreparedRuntimeRecovery {
    previous_shutdown: PreviousShutdown,
    minimum_grace_duration: Duration,
    state: RecoveredRuntimeState,
}

#[derive(Clone, Debug)]
pub(crate) struct ConfirmedClientCallback {
    pub callback: CallbackClient,
    pub callback_identifier: u32,
    /// Exact flavor used by the confirmed SETCLIENTID request. Client
    /// identity matching is flavor-neutral for GSS, but callbacks must use
    /// the flavor the client selected during SETCLIENTID.
    pub setclientid_principal: Principal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SetClientIdPrincipalCollision {
    pub client_id: u64,
    pub previous_client_ids: Vec<u64>,
    pub client_using: ClientAddress,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OpenOwnerKey {
    client_id: u64,
    owner: Vec<u8>,
}

impl From<&OpenOwner> for OpenOwnerKey {
    fn from(owner: &OpenOwner) -> Self {
        Self {
            client_id: owner.client_id,
            owner: owner.owner.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LockOwnerKey {
    client_id: u64,
    owner: Vec<u8>,
}

impl From<&LockOwner> for LockOwnerKey {
    fn from(owner: &LockOwner) -> Self {
        Self {
            client_id: owner.client_id,
            owner: owner.owner.clone(),
        }
    }
}

/// Range ownership is narrower than protocol lock-owner sequencing.
///
/// One protocol lock owner has one seqid stream, but may derive distinct lock
/// state objects from distinct OPEN state objects for the same file. Keeping
/// the stable OPEN identity in the range owner prevents one such state object
/// from merging, unlocking, or excluding another one's ranges.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LockStateOwner {
    owner: LockOwnerKey,
    open: [u8; 12],
}

impl LockStateOwner {
    fn new(owner: LockOwnerKey, open: [u8; 12]) -> Self {
        Self { owner, open }
    }
}

#[derive(Clone, Debug)]
enum StatePayload {
    Open(OpenState),
    Lock(ByteRangeLockState),
}

#[derive(Clone, Debug)]
struct OpenState {
    owner: OpenOwnerKey,
    access: ShareAccess,
    deny: ShareDeny,
    contributions: ShareContributions,
    confirmed: bool,
    pin: [u8; 16],
}

#[derive(Clone, Debug)]
struct ByteRangeLockState {
    owner: LockOwnerKey,
    open_state_id: StateId,
}

struct OpenOwnerState {
    sequence: OwnerSequence<ResOp, ReplayEffect>,
    confirmed: bool,
    active_states: usize,
}

struct LockOwnerState {
    sequence: OwnerSequence<ResOp, ReplayEffect>,
    active_states: usize,
}

struct StateRegistry {
    open_owners: HashMap<OpenOwnerKey, OpenOwnerState>,
    lock_owners: HashMap<LockOwnerKey, LockOwnerState>,
    open_by_owner_file: HashMap<(OpenOwnerKey, RuntimeFile), StateId>,
    lock_by_state: HashMap<(LockStateOwner, RuntimeFile), StateId>,
    reclaimed_open_ancestry: HashMap<[u8; 12], [u8; 12]>,
    recovered_opens: HashMap<[u8; 16], RecoveredOpen>,
    recovered_locks: HashMap<[u8; 16], RecoveredLock>,
    recovered_replays: HashMap<(u64, ReplayOwnerKind, Vec<u8>), RecoveredReplay>,
    recovered_cleanup_keys: HashSet<JournalKey>,
    reserved_recovered_opens: HashSet<[u8; 16]>,
    stateids: StateIdTable<u64, RuntimeFile, StatePayload>,
    reserved_states: usize,
    next_reservation: u64,
    delegation_eligibility: HashMap<u64, PendingDelegationEligibility>,
    next_delegation_eligibility: u64,
    delegation_access: HashMap<u64, PendingDelegationAccess>,
    next_delegation_access: u64,
    pending_pin_releases: Vec<PendingPinRelease>,
    next_pin_release_id: u64,
}

#[derive(Default)]
struct FileShard {
    files: HashMap<RuntimeFile, FileState>,
}

#[derive(Default)]
struct FileState {
    shares: ShareTable<OpenOwnerKey>,
    locks: LockTable<LockStateOwner, [u8; 12]>,
    pending_opens: Vec<PendingOpen>,
}

#[derive(Clone)]
struct PendingOpen {
    reservation: u64,
    owner: OpenOwnerKey,
    access: ShareAccess,
    deny: ShareDeny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingDelegationEligibility {
    file: RuntimeFile,
    client_id: u64,
    kind: DelegationKind,
    open_reservation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingDelegationAccess {
    file: RuntimeFile,
    client_id: Option<u64>,
    access: DelegationKind,
    truncate: bool,
}

#[derive(Clone)]
pub(crate) struct DelegationEligibilityReservation {
    inner: Arc<DelegationEligibilityReservationInner>,
}

struct DelegationEligibilityReservationInner {
    core: Weak<RuntimeCore>,
    id: u64,
}

pub(crate) struct DelegationAccessReservation {
    core: Weak<RuntimeCore>,
    id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoAccess {
    Read,
    Write,
    SetSize,
}

pub(crate) struct IoPermit {
    pub client_id: Option<u64>,
    _gate: OwnedMutexGuard<()>,
    _delegation_access: Option<DelegationAccessReservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservedOwnerKind {
    Open,
    Lock,
}

struct OwnerReservation {
    core: Weak<RuntimeCore>,
    kind: ReservedOwnerKind,
    client_id: u64,
    owner: Vec<u8>,
    sequence_id: u32,
    digest: OwnerRequestDigest,
    reserved_state: bool,
    created_owner: bool,
    committed: bool,
}

pub(crate) struct OpenReservation {
    owner: Option<OwnerReservation>,
    key: OpenOwnerKey,
    access: ShareAccess,
    deny: ShareDeny,
    confirmation_required: bool,
    reservation: u64,
    provisional_pin: [u8; 16],
    reclaim_previous_ids: Vec<u64>,
    replay_effect: ReplayEffect,
}

impl OpenReservation {
    /// Stable operation identity available before a create OPEN has resolved
    /// its target object.
    pub(crate) fn operation_id(&self) -> u64 {
        self.reservation
    }

    /// Candidate pin for a newly allocated OPEN state. Upgrades replace this
    /// with the pin already attached to the existing state.
    pub(crate) fn provisional_pin(&self) -> [u8; 16] {
        self.provisional_pin
    }

    /// Records that this OPEN consumed a validated delegation stateid.
    /// Subsequent exact replays retain this source for §9.5 renewal.
    pub(crate) fn set_stateid_renewal_client(&mut self, client_id: u64) {
        self.replay_effect.stateid_renewal_client = Some(client_id);
    }
}

pub(crate) struct OpenTargetReservation {
    core: Weak<RuntimeCore>,
    owner: Option<OwnerReservation>,
    key: OpenOwnerKey,
    file: RuntimeFile,
    access: ShareAccess,
    deny: ShareDeny,
    contributions: ShareContributions,
    confirmation_required: bool,
    reservation: u64,
    existing_state: Option<StateId>,
    recovered_open_token: Option<[u8; 16]>,
    pin: [u8; 16],
    delegation_eligibility: Option<DelegationEligibilityReservation>,
    pending_removed: bool,
    replay_effect: ReplayEffect,
}

impl OpenTargetReservation {
    pub(crate) fn pin(&self) -> [u8; 16] {
        self.pin
    }

    pub(crate) fn needs_retain(&self) -> bool {
        self.existing_state.is_none()
    }
}

impl DelegationEligibilityReservation {
    fn id(&self) -> u64 {
        self.inner.id
    }
}

#[derive(Debug)]
pub(crate) struct OpenCompletion {
    pub result: ResOp,
    pub effect: ReplayEffect,
    pub newly_retained: bool,
}

#[derive(Debug)]
pub(crate) struct CloseCompletion {
    pub result: ResOp,
}

pub(crate) struct ClientTransition<T> {
    pub result: T,
}

impl<T> ClientTransition<T> {
    fn new(result: T) -> Self {
        Self { result }
    }
}

struct PendingOpenStateGuard {
    core: Weak<RuntimeCore>,
    state_id: Option<StateId>,
}

impl PendingOpenStateGuard {
    fn new(core: &Arc<RuntimeCore>, state_id: StateId) -> Self {
        Self {
            core: Arc::downgrade(core),
            state_id: Some(state_id),
        }
    }

    fn commit(&mut self) {
        self.state_id = None;
    }
}

impl Drop for PendingOpenStateGuard {
    fn drop(&mut self) {
        let (Some(core), Some(state_id)) = (self.core.upgrade(), self.state_id) else {
            return;
        };
        let mut state = core.state.lock().expect("NFSv4 state registry poisoned");
        let _ = state.stateids.set_disposition(state_id, StateDisposition::Closed);
    }
}

pub(crate) struct OpenStateReservation {
    owner: Option<OwnerReservation>,
    key: OpenOwnerKey,
    file: RuntimeFile,
    state_id: StateId,
    access: ShareAccess,
    deny: ShareDeny,
    contributions: ShareContributions,
    pin: [u8; 16],
}

impl OpenStateReservation {
    /// Client authenticated by `begin_open_state_operation`.
    pub(crate) fn client_id(&self) -> u64 {
        self.owner
            .as_ref()
            .expect("open state reservation owns its owner reservation")
            .client_id
    }
}

pub(crate) struct PreparedCloseReservation {
    reservation: OpenStateReservation,
    _gate: OwnedMutexGuard<()>,
}

impl PreparedCloseReservation {
    #[cfg(test)]
    pub(crate) fn pin(&self) -> [u8; 16] {
        self.reservation.pin
    }
}

impl Drop for OwnerReservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let mut state = core.state.lock().expect("NFSv4 state registry poisoned");
        match self.kind {
            ReservedOwnerKind::Open => {
                let key = OpenOwnerKey {
                    client_id: self.client_id,
                    owner: self.owner.clone(),
                };
                if let Some(owner) = state.open_owners.get_mut(&key) {
                    owner.sequence.cancel(self.sequence_id, self.digest);
                }
                if self.created_owner {
                    let remove = state.open_owners.get(&key).is_some_and(|owner| {
                        owner.active_states == 0 && owner.sequence.last().is_none() && !owner.sequence.has_pending()
                    });
                    if remove {
                        state.open_owners.remove(&key);
                    }
                }
            },
            ReservedOwnerKind::Lock => {
                let key = LockOwnerKey {
                    client_id: self.client_id,
                    owner: self.owner.clone(),
                };
                if let Some(owner) = state.lock_owners.get_mut(&key) {
                    owner.sequence.cancel(self.sequence_id, self.digest);
                }
                if self.created_owner {
                    let remove = state.lock_owners.get(&key).is_some_and(|owner| {
                        owner.active_states == 0 && owner.sequence.last().is_none() && !owner.sequence.has_pending()
                    });
                    if remove {
                        state.lock_owners.remove(&key);
                    }
                }
            },
        }
        if self.reserved_state {
            state.reserved_states = state.reserved_states.saturating_sub(1);
        }
    }
}

impl Drop for OpenTargetReservation {
    fn drop(&mut self) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        if let Some(token) = self.recovered_open_token {
            core.state
                .lock()
                .expect("NFSv4 state registry poisoned")
                .reserved_recovered_opens
                .remove(&token);
        }
        if !self.pending_removed {
            let shard_index = shard_for(&self.file, core.files.len());
            let mut shard = core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
            if let Some(file) = shard.files.get_mut(&self.file) {
                file.pending_opens.retain(|pending| pending.reservation != self.reservation);
                if file.is_empty() {
                    shard.files.remove(&self.file);
                }
            }
        }
    }
}

impl Drop for DelegationEligibilityReservationInner {
    fn drop(&mut self) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        core.state
            .lock()
            .expect("NFSv4 state registry poisoned")
            .delegation_eligibility
            .remove(&self.id);
    }
}

impl Drop for DelegationAccessReservation {
    fn drop(&mut self) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        core.state
            .lock()
            .expect("NFSv4 state registry poisoned")
            .delegation_access
            .remove(&self.id);
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RuntimeConfigError {
    #[error("invalid NFSv4 lease configuration")]
    Lease,
    #[error("invalid NFSv4 recovery configuration")]
    Recovery,
    #[error("invalid NFSv4 stateid configuration")]
    StateId,
}

impl Nfs4Runtime {
    pub(crate) fn new(config: RuntimeConfig) -> Result<Self, RuntimeConfigError> {
        Self::with_clock(config, Arc::new(SystemLeaseClock::new()))
    }

    pub(crate) fn with_clock(config: RuntimeConfig, clock: Arc<dyn LeaseClock>) -> Result<Self, RuntimeConfigError> {
        let leases = LeaseTable::new(config.lease_duration, clock.clone()).map_err(|_| RuntimeConfigError::Lease)?;
        let recovered = config.recovered.unwrap_or(RecoveredStableState {
            previous_shutdown: PreviousShutdown::FirstBoot,
            previous_boot: None,
            records: Vec::new(),
        });
        let prepared = prepare_runtime_recovery(&recovered, &config.limits, config.grace_duration)?;
        let recovery_had_grace = prepared.previous_shutdown != PreviousShutdown::FirstBoot;
        let recovery = if !recovery_had_grace {
            RecoveryState::reject_reclaims(clock.clone())
        } else {
            RecoveryState::from_recovered(clock.clone(), config.grace_duration, [])
                .map_err(|_| RuntimeConfigError::Recovery)?
        };
        let stateids = StateIdTable::with_boot_tag(config.limits.max_state_objects, config.boot_tag)
            .map_err(|_| RuntimeConfigError::StateId)?;
        let files = (0..STATE_SHARDS)
            .map(|_| Mutex::new(FileShard::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let operation_gates = (0..STATE_SHARDS)
            .map(|_| Arc::new(AsyncMutex::new(())))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            core: Arc::new(RuntimeCore {
                clients: AsyncMutex::new(ClientRegistry {
                    slots: HashMap::new(),
                    client_owners: HashMap::new(),
                    expired: HashSet::new(),
                    pending_expiry: HashSet::new(),
                    moved_leases: MovedLeaseTracker::new(
                        config.limits.max_state_objects.saturating_add(config.limits.max_clients),
                        config.lease_duration,
                    ),
                    leases,
                    recovery,
                    recovered_clients: prepared.state.clients,
                    current_to_previous: HashMap::new(),
                    recovery_had_grace,
                    grace_cleanup_complete: !recovery_had_grace,
                    clock,
                    lease_duration: config.lease_duration,
                    grace_duration: config.grace_duration,
                    boot_tag: config.boot_tag,
                    next_client: 1,
                    next_confirmation: 1,
                }),
                state: Mutex::new(StateRegistry {
                    open_owners: HashMap::new(),
                    lock_owners: HashMap::new(),
                    open_by_owner_file: HashMap::new(),
                    lock_by_state: HashMap::new(),
                    reclaimed_open_ancestry: HashMap::new(),
                    recovered_opens: prepared.state.opens,
                    recovered_locks: prepared.state.locks,
                    recovered_replays: prepared.state.replays,
                    recovered_cleanup_keys: prepared.state.cleanup_keys,
                    reserved_recovered_opens: HashSet::new(),
                    stateids,
                    reserved_states: 0,
                    next_reservation: 1,
                    delegation_eligibility: HashMap::new(),
                    next_delegation_eligibility: 1,
                    delegation_access: HashMap::new(),
                    next_delegation_access: 1,
                    pending_pin_releases: Vec::new(),
                    next_pin_release_id: 1,
                }),
                files,
                operation_gates,
                client_state_transition_gate: Arc::new(AsyncMutex::new(())),
                limits: config.limits,
                lease_duration: config.lease_duration,
                grace_duration: config.grace_duration,
                write_verifier: config.write_verifier,
                stable_journal: config.stable_journal,
                critical_tasks: Arc::new(CriticalTaskTracker::default()),
            }),
        })
    }

    pub(crate) fn prepare_recovery_import(
        &self,
        recovered: &RecoveredStableState,
        minimum_grace_duration: Duration,
    ) -> Result<PreparedRuntimeRecovery, RuntimeConfigError> {
        prepare_runtime_recovery(recovered, &self.core.limits, minimum_grace_duration)
    }

    /// Revalidates a prepared migration image against the current live
    /// registries without making any of the imported state visible.
    ///
    /// Migration control calls this after quiescing the affected exports and
    /// immediately before committing the imported stable records. Activation
    /// repeats the same validation so a concurrent change fails closed.
    pub(crate) async fn validate_recovery_import(
        &self,
        prepared: &PreparedRuntimeRecovery,
    ) -> Result<(), RuntimeConfigError> {
        let clients = self.core.clients.lock().await;
        let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        validate_recovery_import_locked(&clients, &state, prepared, &self.core.limits)
    }

    /// Makes a previously validated import visible. Migration control must
    /// call this only after its durable commit while the destination runtime
    /// remains quiesced. Validation is deliberately separate so a staged or
    /// aborted bundle can never leak protocol state into live dispatch.
    pub(crate) async fn activate_recovery_import(
        &self,
        prepared: PreparedRuntimeRecovery,
    ) -> Result<(), RuntimeConfigError> {
        let mut clients = self.core.clients.lock().await;
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        validate_recovery_import_locked(&clients, &state, &prepared, &self.core.limits)?;
        let already_active = prepared.state.clients.iter().all(|(identity, previous_ids)| {
            clients
                .recovered_clients
                .get(identity)
                .is_some_and(|existing| previous_ids.iter().all(|previous_id| existing.contains(previous_id)))
        }) && prepared
            .state
            .opens
            .iter()
            .all(|(token, recovered)| state.recovered_opens.get(token) == Some(recovered))
            && prepared
                .state
                .locks
                .iter()
                .all(|(token, recovered)| state.recovered_locks.get(token) == Some(recovered))
            && prepared
                .state
                .replays
                .iter()
                .all(|(key, recovered)| state.recovered_replays.get(key) == Some(recovered))
            && prepared.state.cleanup_keys.is_subset(&state.recovered_cleanup_keys);
        if already_active {
            return Ok(());
        }
        let PreparedRuntimeRecovery {
            previous_shutdown: _,
            minimum_grace_duration,
            state: imported,
        } = prepared;
        for (identity, previous_ids) in imported.clients {
            let existing = clients.recovered_clients.entry(identity).or_default();
            existing.extend(previous_ids);
            existing.sort_unstable();
            existing.dedup();
        }
        let confirmed_identities = clients
            .slots
            .values()
            .filter_map(|slot| slot.confirmed.as_ref())
            .map(|record| {
                (
                    record.client_id,
                    RecoveredClientIdentity {
                        owner: record.owner.clone(),
                        verifier: record.verifier,
                        principal: canonical_client_identity(&record.setclientid_principal),
                    },
                )
            })
            .collect::<Vec<_>>();
        for (client_id, identity) in confirmed_identities {
            if let Some(previous_ids) = clients.recovered_clients.get(&identity).cloned() {
                clients.current_to_previous.insert(client_id, previous_ids);
            }
        }
        clients.recovery_had_grace = true;
        clients.grace_cleanup_complete = false;
        let grace_duration = clients.grace_duration.max(minimum_grace_duration);
        let reclaimable_clients = clients.current_to_previous.keys().copied().collect::<Vec<_>>();
        clients
            .recovery
            .begin_grace(grace_duration, reclaimable_clients)
            .map_err(|_| RuntimeConfigError::Recovery)?;
        for (token, recovered) in imported.opens {
            state.recovered_opens.entry(token).or_insert(recovered);
        }
        for (token, recovered) in imported.locks {
            state.recovered_locks.entry(token).or_insert(recovered);
        }
        for (key, recovered) in imported.replays {
            state.recovered_replays.entry(key).or_insert(recovered);
        }
        state.recovered_cleanup_keys.extend(imported.cleanup_keys);
        Ok(())
    }

    pub(crate) fn write_verifier(&self) -> [u8; 8] {
        self.core.write_verifier
    }

    pub(crate) fn lease_duration(&self) -> Duration {
        self.core.lease_duration
    }

    pub(crate) fn grace_duration(&self) -> Duration {
        self.core.grace_duration
    }

    pub(crate) async fn operation_gate(&self, key: impl Hash) -> OwnedMutexGuard<()> {
        let index = shard_for(&key, self.core.operation_gates.len());
        self.core.operation_gates[index].clone().lock_owned().await
    }

    /// Serializes SETCLIENTID replacement checks with migration recovery
    /// activation, whose client and delegation records span separate
    /// registries.
    pub(crate) async fn client_state_transition_guard(&self) -> OwnedMutexGuard<()> {
        self.core.client_state_transition_gate.clone().lock_owned().await
    }

    pub(crate) async fn operation_gates(
        &self,
        first: impl Hash,
        second: impl Hash,
    ) -> (OwnedMutexGuard<()>, Option<OwnedMutexGuard<()>>) {
        let first_index = shard_for(&first, self.core.operation_gates.len());
        let second_index = shard_for(&second, self.core.operation_gates.len());
        let (low, high) = if first_index <= second_index {
            (first_index, second_index)
        } else {
            (second_index, first_index)
        };
        let low_guard = self.core.operation_gates[low].clone().lock_owned().await;
        let high_guard = if low == high {
            None
        } else {
            Some(self.core.operation_gates[high].clone().lock_owned().await)
        };
        (low_guard, high_guard)
    }

    /// Waits until every cancellation-shielded protocol transition has
    /// resolved its stable-store outcome and synchronized in-memory state.
    pub(crate) async fn wait_critical(&self) {
        self.core.critical_tasks.wait().await;
    }

    /// Returns a repeatable snapshot of retired backend pins. Entries remain
    /// in the bounded outbox until acknowledged, so cancellation between this
    /// read and transfer into the pin manager cannot lose cleanup work.
    pub(crate) fn pending_pin_releases(&self) -> Vec<PendingPinRelease> {
        self.core
            .state
            .lock()
            .expect("NFSv4 state registry poisoned")
            .pending_pin_releases
            .clone()
    }

    pub(crate) fn acknowledge_pin_release(&self, release_id: u64) -> bool {
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let previous = state.pending_pin_releases.len();
        state.pending_pin_releases.retain(|release| release.release_id != release_id);
        previous != state.pending_pin_releases.len()
    }

    /// Reconciles an OPEN pin after its caller was cancelled while a critical
    /// completion task continued in the background.
    pub(crate) fn is_open_pin_active(&self, file: RuntimeFile, pin: [u8; 16]) -> bool {
        let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        state.open_by_owner_file.iter().any(|((_, candidate_file), state_id)| {
            if *candidate_file != file {
                return false;
            }
            state
                .stateids
                .identify(*state_id)
                .is_ok_and(|record| matches!(&record.payload, StatePayload::Open(open) if open.pin == pin))
        })
    }

    pub(crate) async fn set_client_id(
        &self,
        arguments: &SetClientIdArgs,
        principal: &Principal,
    ) -> ClientTransition<SetClientIdResult> {
        if arguments.client.id.len() > self.core.limits.max_client_owner_size {
            return ClientTransition::new(SetClientIdResult::Err(NfsStatus::Resource));
        }
        let mut clients = self.core.clients.lock().await;
        let now = clients.clock.now();
        let stale = purge_unconfirmed(&mut clients, now);
        let existing = clients
            .slots
            .get(&arguments.client.id)
            .and_then(|slot| slot.confirmed.as_ref())
            .cloned();
        let same_identity = existing
            .as_ref()
            .is_none_or(|record| same_client_identity(&record.setclientid_principal, principal));
        let releasing_confirmed = if let Some(existing) = existing.as_ref().filter(|_| !same_identity) {
            let previous_client_ids = clients
                .current_to_previous
                .get(&existing.client_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if self.client_has_open_or_lock_state(existing.client_id, previous_client_ids) {
                return ClientTransition::new(SetClientIdResult::ClientIdInUse(existing.callback.location.clone()));
            }
            Some(existing.client_id)
        } else {
            None
        };

        let replacing_unconfirmed = clients
            .slots
            .get(&arguments.client.id)
            .and_then(|slot| slot.unconfirmed.as_ref())
            .map(|record| record.client_id);
        let same_incarnation = existing
            .as_ref()
            .filter(|record| same_identity && record.verifier == arguments.client.verifier)
            .map(|record| record.client_id);
        let live_records = clients.client_owners.len();
        let needs_new_id = same_incarnation.is_none();
        let replaced_ids = [replacing_unconfirmed, releasing_confirmed]
            .into_iter()
            .flatten()
            .filter(|id| Some(*id) != same_incarnation)
            .collect::<HashSet<_>>();
        if needs_new_id && live_records.saturating_sub(replaced_ids.len()) >= self.core.limits.max_clients {
            return ClientTransition::new(SetClientIdResult::Err(NfsStatus::Resource));
        }

        let client_id = match same_incarnation {
            Some(client_id) => client_id,
            None => match allocate_client_id(&mut clients) {
                Some(client_id) => client_id,
                None => return ClientTransition::new(SetClientIdResult::Err(NfsStatus::Resource)),
            },
        };
        let confirmation = allocate_confirmation(&mut clients, client_id, &arguments.client.verifier);
        let identity = RecoveredClientIdentity {
            owner: arguments.client.id.clone(),
            verifier: arguments.client.verifier,
            principal: canonical_client_identity(principal),
        };
        let record = ClientRecord {
            client_id,
            owner: arguments.client.id.clone(),
            verifier: arguments.client.verifier,
            confirmation,
            setclientid_principal: principal.clone(),
            callback: arguments.callback.clone(),
            callback_identifier: arguments.callback_identifier,
            created_at: now,
            reclaimable: clients.recovered_clients.contains_key(&identity),
        };

        let mut batch = PersistBatch::default();
        for stale_id in stale {
            batch = batch.delete(JournalKey::Client { client_id: stale_id });
        }
        if let Some(old) = replacing_unconfirmed {
            if old != client_id {
                batch = batch.delete(JournalKey::Client { client_id: old });
            }
        }
        if let Some(old) = releasing_confirmed {
            batch = self.append_client_revocation(batch, old);
        }
        if same_incarnation.is_none() {
            batch = batch
                .put(JournalKey::Client { client_id }, JournalRecord::Client(stable_client_record(&record, false)));
        }
        if self.persist_if_needed(batch).await.is_err() {
            return ClientTransition::new(SetClientIdResult::Err(NfsStatus::Resource));
        }

        if let Some(old) = releasing_confirmed {
            remove_client_registration(&mut clients, old);
            let _queued = self.revoke_client(old, StateDisposition::LeaseExpired);
        }
        if let Some(old) = replacing_unconfirmed {
            if old != client_id && Some(old) != releasing_confirmed {
                clients.client_owners.remove(&old);
            }
        }
        clients.client_owners.insert(client_id, arguments.client.id.clone());
        clients
            .slots
            .entry(arguments.client.id.clone())
            .or_insert_with(|| ClientSlot {
                confirmed: None,
                unconfirmed: None,
            })
            .unconfirmed = Some(record);
        ClientTransition::new(SetClientIdResult::Ok(SetClientIdOk {
            client_id,
            confirmation,
        }))
    }

    /// Reports a confirmed SETCLIENTID owner collision before a replacement
    /// can revoke that client's protocol state.
    ///
    /// OPEN and LOCK state live in this runtime and are rechecked atomically
    /// by [`Self::set_client_id`]. Delegations are managed per export, so the
    /// compound executor uses this snapshot to check every delegation manager
    /// before asking the runtime to perform the replacement. The caller must
    /// hold [`Self::client_state_transition_guard`] across that entire
    /// sequence.
    pub(crate) async fn setclientid_principal_collision(
        &self,
        arguments: &SetClientIdArgs,
        principal: &Principal,
    ) -> Option<SetClientIdPrincipalCollision> {
        let clients = self.core.clients.lock().await;
        let confirmed = clients.slots.get(&arguments.client.id)?.confirmed.as_ref()?;
        if same_client_identity(&confirmed.setclientid_principal, principal) {
            return None;
        }
        Some(SetClientIdPrincipalCollision {
            client_id: confirmed.client_id,
            previous_client_ids: clients
                .current_to_previous
                .get(&confirmed.client_id)
                .cloned()
                .unwrap_or_default(),
            client_using: confirmed.callback.location.clone(),
        })
    }

    pub(crate) async fn confirm_client(
        &self,
        client_id: u64,
        confirmation: [u8; 8],
        principal: &Principal,
    ) -> ClientTransition<NfsStatus> {
        // Serialize the client-registry decision with stateful reservation
        // creation. A previous incarnation may be replaced only when none of
        // its owner seqids is currently executing.
        let _transition_guard = self.client_state_transition_guard().await;
        let mut clients = self.core.clients.lock().await;
        let Some(owner) = clients.client_owners.get(&client_id).cloned() else {
            return ClientTransition::new(NfsStatus::StaleClientId);
        };
        let Some(slot) = clients.slots.get(&owner) else {
            return ClientTransition::new(NfsStatus::StaleClientId);
        };

        if let Some(confirmed) = slot.confirmed.as_ref() {
            if confirmed.client_id == client_id && confirmed.confirmation == confirmation {
                return ClientTransition::new(if same_client_identity(&confirmed.setclientid_principal, principal) {
                    NfsStatus::Ok
                } else {
                    NfsStatus::ClientIdInUse
                });
            }
        }
        let Some(unconfirmed) = slot
            .unconfirmed
            .as_ref()
            .filter(|record| record.client_id == client_id && record.confirmation == confirmation)
            .cloned()
        else {
            return ClientTransition::new(NfsStatus::StaleClientId);
        };
        if !same_client_identity(&unconfirmed.setclientid_principal, principal) {
            return ClientTransition::new(NfsStatus::ClientIdInUse);
        }
        let previous = slot.confirmed.clone();
        let callback_update = previous
            .as_ref()
            .is_some_and(|record| record.client_id == client_id && record.verifier == unconfirmed.verifier);
        if previous.as_ref().is_some_and(|record| {
            record.client_id != client_id && self.client_has_live_owner_reservation(record.client_id)
        }) {
            return ClientTransition::new(NfsStatus::Delay);
        }

        let mut batch = PersistBatch::default()
            .put(JournalKey::Client { client_id }, JournalRecord::Client(stable_client_record(&unconfirmed, true)));
        if let Some(previous) = &previous {
            if previous.client_id != client_id {
                batch = self.append_client_revocation(batch, previous.client_id);
            }
        }
        if self.persist_if_needed(batch).await.is_err() {
            return ClientTransition::new(NfsStatus::Resource);
        }

        let recovered_identity = RecoveredClientIdentity {
            owner: unconfirmed.owner.clone(),
            verifier: unconfirmed.verifier,
            principal: canonical_client_identity(&unconfirmed.setclientid_principal),
        };
        let previous_ids = clients.recovered_clients.get(&recovered_identity).cloned().unwrap_or_default();
        let slot = clients.slots.get_mut(&owner).expect("client slot remains while locked");
        slot.confirmed = Some(unconfirmed.clone());
        slot.unconfirmed = None;
        if unconfirmed.reclaimable && !previous_ids.is_empty() {
            clients.recovery.add_reclaimable(client_id);
            clients.current_to_previous.insert(client_id, previous_ids);
        }
        if let Some(previous) = previous {
            if !callback_update && previous.client_id != client_id {
                clients.client_owners.remove(&previous.client_id);
                clients.expired.insert(previous.client_id);
                clients.current_to_previous.remove(&previous.client_id);
                clients.moved_leases.remove_client(previous.client_id);
                drop(clients);
                let _queued = self.revoke_client(previous.client_id, StateDisposition::LeaseExpired);
            }
        }
        ClientTransition::new(NfsStatus::Ok)
    }

    pub(crate) async fn renew(&self, client_id: u64, principal: &Principal) -> NfsStatus {
        match self.touch_client(client_id, principal).await {
            Ok(()) => NfsStatus::Ok,
            Err(status) => status,
        }
    }

    pub(crate) async fn validate_client(&self, client_id: u64, principal: &Principal) -> NfsStatus {
        match self.touch_client(client_id, principal).await {
            Ok(()) => NfsStatus::Ok,
            Err(status) => status,
        }
    }

    /// Records that a confirmed client was told an export has moved.
    ///
    /// RFC 7931 requires subsequent explicit and implicit lease renewals to
    /// report `NFS4ERR_LEASE_MOVED` until that client probes `fs_locations`
    /// for every moved filesystem. Repeated notifications retain the first
    /// timestamp so legacy clients are released after two lease periods.
    pub(crate) async fn note_moved_export(
        &self,
        client_id: u64,
        export_id: ExportId,
        principal: &Principal,
    ) -> Result<(), NfsStatus> {
        let mut clients = self.core.clients.lock().await;
        confirmed_client_record(&clients, client_id, principal)?;
        let now = clients.clock.now();
        clients.moved_leases.note(client_id, export_id, now)
    }

    /// Completes successful `GETATTR(fs_locations)` probes for one client.
    ///
    /// This intentionally does not renew the lease. The identifying
    /// stateful operation in the COMPOUND (normally RENEW) performs renewal
    /// after the matching moved-export obligations have been removed.
    pub(crate) async fn complete_moved_export_probes(
        &self,
        client_id: u64,
        export_ids: &HashSet<ExportId>,
        principal: &Principal,
    ) -> Result<(), NfsStatus> {
        let mut clients = self.core.clients.lock().await;
        confirmed_client_record(&clients, client_id, principal)?;
        for export_id in export_ids {
            clients.moved_leases.clear(client_id, *export_id);
        }
        Ok(())
    }

    /// Identifies the confirmed client behind a non-special open/lock
    /// stateid without renewing its lease.
    pub(crate) async fn identify_stateid_client(
        &self,
        state_id: StateId,
        file: RuntimeFile,
        principal: &Principal,
    ) -> Result<Option<u64>, NfsStatus> {
        let _transition_guard = self.client_state_transition_guard().await;
        if state_id.other == [0; 12] {
            return if state_id.sequence_id == 0 {
                Ok(None)
            } else {
                Err(NfsStatus::BadStateId)
            };
        }
        if state_id.other == [u8::MAX; 12] {
            return if state_id.sequence_id == u32::MAX {
                Ok(None)
            } else {
                Err(NfsStatus::BadStateId)
            };
        }
        let client_id = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = state.stateids.identify(state_id).map_err(map_stateid_error)?;
            if record.file != file || !matches!(record.kind, StateKind::Open | StateKind::ByteRangeLock) {
                return Err(NfsStatus::BadStateId);
            }
            record.client
        };
        let clients = self.core.clients.lock().await;
        confirmed_client_record(&clients, client_id, principal)?;
        Ok(Some(client_id))
    }

    /// Returns whether a non-special stateid belongs to this runtime's
    /// OPEN/LOCK stateid namespace.
    ///
    /// Protocol operations that accept only delegation stateids use this to
    /// avoid reclassifying an old or otherwise invalid OPEN/LOCK stateid as
    /// a delegation lookup failure.
    pub(crate) fn owns_open_or_lock_stateid_namespace(&self, state_id: StateId) -> bool {
        state_id.other[..4]
            == self
                .core
                .state
                .lock()
                .expect("NFSv4 state registry poisoned")
                .stateids
                .boot_tag()
                .to_be_bytes()
    }

    pub(crate) async fn confirmed_client_callback(
        &self,
        client_id: u64,
        principal: &Principal,
    ) -> Result<ConfirmedClientCallback, NfsStatus> {
        let clients = self.core.clients.lock().await;
        let record = confirmed_client_record(&clients, client_id, principal)?;
        Ok(ConfirmedClientCallback {
            callback: record.callback.clone(),
            callback_identifier: record.callback_identifier,
            setclientid_principal: record.setclientid_principal.clone(),
        })
    }

    /// Returns the stable client IDs from the previous boot that are
    /// cryptographically bound to this confirmed current client identity.
    pub(crate) async fn previous_client_ids(
        &self,
        client_id: u64,
        principal: &Principal,
    ) -> Result<Vec<u64>, NfsStatus> {
        let clients = self.core.clients.lock().await;
        confirmed_client_record(&clients, client_id, principal)?;
        Ok(clients.current_to_previous.get(&client_id).cloned().unwrap_or_default())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn begin_open_with_identity(
        &self,
        owner: &OpenOwner,
        sequence_id: u32,
        share_access: u32,
        share_deny: u32,
        reclaim: bool,
        authenticate_clientid: bool,
        digest: OwnerRequestDigest,
        principal: &Principal,
    ) -> OpenDecision {
        let Some(access) = ShareAccess::from_wire(share_access) else {
            return OpenDecision::Error {
                status: NfsStatus::Invalid,
                client_id: None,
            };
        };
        let Some(deny) = ShareDeny::from_wire(share_deny) else {
            return OpenDecision::Error {
                status: NfsStatus::Invalid,
                client_id: None,
            };
        };
        if owner.owner.len() > self.core.limits.max_client_owner_size {
            return OpenDecision::Error {
                status: NfsStatus::Resource,
                client_id: None,
            };
        }
        // A client's first pending OPEN is the handoff point from stateless
        // identity to stateful identity. Serialize validation through pending
        // owner registration so SETCLIENTID cannot replace the client in
        // between those two registry updates.
        let _transition_guard = self.client_state_transition_guard().await;
        let reclaim_previous_ids = match self.gate_state_client_with_identity(owner.client_id, principal, reclaim).await
        {
            Ok(previous_ids) => previous_ids,
            Err(error) => {
                return OpenDecision::Error {
                    status: error.status,
                    client_id: error.client_id,
                }
            },
        };
        let authenticated_client = if authenticate_clientid {
            if let Err(error) = self.touch_client_authenticated(owner.client_id, principal).await {
                return OpenDecision::Error {
                    status: error.status,
                    client_id: error.client_id,
                };
            }
            Some(owner.client_id)
        } else {
            None
        };

        let key = OpenOwnerKey::from(owner);
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let created = !state.open_owners.contains_key(&key);
        if created {
            let owners_for_client = state
                .open_owners
                .keys()
                .filter(|candidate| candidate.client_id == key.client_id)
                .count();
            if owners_for_client >= self.core.limits.max_open_owners_per_client {
                return OpenDecision::Error {
                    status: NfsStatus::Resource,
                    client_id: authenticated_client,
                };
            }
            state.open_owners.insert(
                key.clone(),
                OpenOwnerState {
                    sequence: OwnerSequence::new(sequence_id),
                    confirmed: reclaim,
                    active_states: 0,
                },
            );
        }

        let decision = state
            .open_owners
            .get_mut(&key)
            .expect("open owner was inserted")
            .sequence
            .reserve(sequence_id, digest);
        match decision {
            SequenceDecision::Replay { result, context_effect } => {
                return OpenDecision::Replay {
                    result,
                    effect: context_effect,
                    client_id: authenticated_client,
                }
            },
            SequenceDecision::InProgress => {
                return OpenDecision::Error {
                    status: NfsStatus::Delay,
                    client_id: authenticated_client,
                }
            },
            SequenceDecision::BadSequence => {
                return OpenDecision::Error {
                    status: NfsStatus::BadSequenceId,
                    client_id: authenticated_client,
                }
            },
            SequenceDecision::Execute => {},
        }

        if state
            .stateids
            .len()
            .saturating_add(state.reserved_states)
            .saturating_add(state.pending_pin_releases.len())
            >= state.stateids.capacity()
        {
            if let Some(owner) = state.open_owners.get_mut(&key) {
                owner.sequence.cancel(sequence_id, digest);
            }
            if created {
                state.open_owners.remove(&key);
            }
            return OpenDecision::Error {
                status: NfsStatus::Resource,
                client_id: authenticated_client,
            };
        }
        state.reserved_states += 1;
        let reservation = state.next_reservation;
        state.next_reservation = state.next_reservation.wrapping_add(1).max(1);
        let provisional_pin = open_pin(state.stateids.boot_tag(), reservation);
        let confirmation_required = !state.open_owners.get(&key).expect("open owner exists").confirmed && !reclaim;
        OpenDecision::Execute(OpenReservation {
            owner: Some(OwnerReservation {
                core: Arc::downgrade(&self.core),
                kind: ReservedOwnerKind::Open,
                client_id: key.client_id,
                owner: key.owner.clone(),
                sequence_id,
                digest,
                reserved_state: true,
                created_owner: created,
                committed: false,
            }),
            key,
            access,
            deny,
            confirmation_required,
            reservation,
            provisional_pin,
            reclaim_previous_ids,
            replay_effect: ReplayEffect::default(),
        })
    }

    /// Runtime-only compatibility view for tests that do not need the
    /// authenticated OPEN client identity.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn begin_open(
        &self,
        owner: &OpenOwner,
        sequence_id: u32,
        share_access: u32,
        share_deny: u32,
        reclaim: bool,
        digest: OwnerRequestDigest,
        principal: &Principal,
    ) -> StatefulDecision<OpenReservation> {
        match self
            .begin_open_with_identity(owner, sequence_id, share_access, share_deny, reclaim, true, digest, principal)
            .await
        {
            OpenDecision::Execute(reservation) => StatefulDecision::Execute(reservation),
            OpenDecision::Replay { result, effect, .. } => StatefulDecision::Replay { result, effect },
            OpenDecision::Error { status, .. } => StatefulDecision::Error(status),
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn reserve_open_target(
        &self,
        mut reservation: OpenReservation,
        file: RuntimeFile,
    ) -> Result<OpenTargetReservation, (OpenReservation, NfsStatus)> {
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let requested_kind = if reservation.access.bits() & ShareAccess::WRITE.bits() != 0 {
            DelegationKind::Write
        } else {
            DelegationKind::Read
        };
        if state.delegation_eligibility.values().any(|candidate| {
            candidate.file == file
                && candidate.client_id != reservation.key.client_id
                && delegation_kinds_conflict(candidate.kind, requested_kind)
        }) {
            return Err((reservation, NfsStatus::Delay));
        }
        let existing_state = state.open_by_owner_file.get(&(reservation.key.clone(), file)).copied();
        let shard_index = shard_for(&file, self.core.files.len());
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        let file_state = shard.files.entry(file).or_default();
        let recovered_open = if reservation.reclaim_previous_ids.is_empty() {
            None
        } else {
            state
                .recovered_opens
                .values()
                .find(|recovered| {
                    reservation.reclaim_previous_ids.contains(&recovered.previous_client_id)
                        && recovered.owner == reservation.key.owner
                        && recovered.file == file
                        && recovered.access == reservation.access
                        && recovered.deny == reservation.deny
                        && !state.reserved_recovered_opens.contains(&recovered.state_token)
                })
                .cloned()
        };
        if !reservation.reclaim_previous_ids.is_empty() && recovered_open.is_none() {
            return Err((reservation, NfsStatus::ReclaimBad));
        }
        let mut candidate = file_state.shares.clone();
        let combined = match recovered_open.as_ref() {
            Some(recovered) => candidate.install(
                reservation.key.clone(),
                recovered.contributions,
                self.core.limits.max_open_contributions_per_state,
            ),
            None => candidate.open(
                reservation.key.clone(),
                reservation.access,
                reservation.deny,
                self.core.limits.max_open_contributions_per_state,
            ),
        };
        let combined = match combined {
            Ok(combined) => combined,
            Err(ShareOpenError::Conflict(_)) => return Err((reservation, NfsStatus::ShareDenied)),
            Err(ShareOpenError::ContributionLimit) => return Err((reservation, NfsStatus::Resource)),
        };
        if file_state.pending_opens.iter().any(|pending| {
            pending.owner != reservation.key
                && (combined.access.bits() & pending.deny.bits() != 0
                    || pending.access.bits() & combined.deny.bits() != 0)
        }) {
            return Err((reservation, NfsStatus::ShareDenied));
        }
        let recovered_open_token = recovered_open.map(|recovered| {
            let token = recovered.state_token;
            state.reserved_recovered_opens.insert(token);
            token
        });
        if existing_state.is_some() {
            state.reserved_states = state.reserved_states.saturating_sub(1);
            if let Some(owner) = reservation.owner.as_mut() {
                owner.reserved_state = false;
            }
        }
        file_state.pending_opens.push(PendingOpen {
            reservation: reservation.reservation,
            owner: reservation.key.clone(),
            access: combined.access,
            deny: combined.deny,
        });
        let pin = existing_state
            .and_then(|stateid| state.stateids.identify(stateid).ok())
            .and_then(|record| match &record.payload {
                StatePayload::Open(open) => Some(open.pin),
                StatePayload::Lock(_) => None,
            })
            .unwrap_or(reservation.provisional_pin);
        Ok(OpenTargetReservation {
            core: Arc::downgrade(&self.core),
            owner: reservation.owner.take(),
            key: reservation.key,
            file,
            access: combined.access,
            deny: combined.deny,
            contributions: combined.contributions(),
            confirmation_required: reservation.confirmation_required,
            reservation: reservation.reservation,
            existing_state,
            recovered_open_token,
            pin,
            delegation_eligibility: None,
            pending_removed: false,
            replay_effect: reservation.replay_effect,
        })
    }

    pub(crate) async fn complete_open_error(&self, mut reservation: OpenReservation, status: NfsStatus) -> ResOp {
        let effect = reservation.replay_effect;
        let owner = reservation.owner.take().expect("open reservation owns its owner reservation");
        self.complete_owner_error_with_effect(owner, status, ResOp::Open(NfsResult::Err(status)), effect)
            .await
    }

    pub(crate) async fn complete_open_target_error(
        &self,
        mut reservation: OpenTargetReservation,
        status: NfsStatus,
    ) -> ResOp {
        self.remove_pending_open(&mut reservation);
        let effect = reservation.replay_effect;
        let owner = reservation
            .owner
            .take()
            .expect("open target reservation owns its owner reservation");
        self.complete_owner_error_with_effect(owner, status, ResOp::Open(NfsResult::Err(status)), effect)
            .await
    }

    pub(crate) async fn complete_open(
        &self,
        reservation: OpenTargetReservation,
        change_info: ChangeInfo,
        attributes_set: Bitmap,
        delegation: OpenDelegation,
    ) -> Result<OpenCompletion, NfsStatus> {
        let runtime = self.clone();
        let critical = self.core.critical_tasks.start();
        match tokio::spawn(async move {
            let _critical = critical;
            runtime
                .complete_open_critical(reservation, change_info, attributes_set, delegation)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => panic!("critical OPEN completion task was cancelled"),
        }
    }

    /// Cancellation-shielded portion of OPEN completion.
    ///
    /// A stable-store CAS may have committed even when its future has not yet
    /// returned. Owning all rollback guards and the synchronous activation in
    /// this detached task ensures caller cancellation can never tear down an
    /// OPEN whose durable outcome is ambiguous.
    async fn complete_open_critical(
        &self,
        mut reservation: OpenTargetReservation,
        change_info: ChangeInfo,
        attributes_set: Bitmap,
        delegation: OpenDelegation,
    ) -> Result<OpenCompletion, NfsStatus> {
        let confirmation_required = reservation.confirmation_required && matches!(&delegation, OpenDelegation::None);
        let mut pending_state = None;
        let (state_id, previous_state, newly_allocated, recovered_open) = {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            validate_delegation_eligibility(&state, &reservation, &delegation)?;
            let owner_reservation = reservation
                .owner
                .as_ref()
                .expect("open target reservation owns its owner reservation");
            let owner = state.open_owners.get(&reservation.key).ok_or(NfsStatus::ServerFault)?;
            if !matches!(
                owner.sequence.decide(owner_reservation.sequence_id, owner_reservation.digest),
                SequenceDecision::InProgress
            ) {
                return Err(NfsStatus::ServerFault);
            }
            let recovered_open = reservation
                .recovered_open_token
                .map(|token| {
                    if !state.reserved_recovered_opens.contains(&token) {
                        return Err(NfsStatus::ReclaimBad);
                    }
                    state.recovered_opens.get(&token).cloned().ok_or(NfsStatus::ReclaimBad)
                })
                .transpose()?;
            match reservation.existing_state {
                Some(previous) => {
                    if owner_reservation.reserved_state
                        || state.open_by_owner_file.get(&(reservation.key.clone(), reservation.file)) != Some(&previous)
                    {
                        return Err(NfsStatus::ServerFault);
                    }
                    (
                        state.stateids.preview_transition(previous).map_err(map_stateid_error)?,
                        Some(previous),
                        false,
                        recovered_open,
                    )
                },
                None => {
                    if !owner_reservation.reserved_state || owner.active_states == usize::MAX {
                        return Err(NfsStatus::ServerFault);
                    }
                    let state_id = state
                        .stateids
                        .allocate_pending(
                            reservation.key.client_id,
                            reservation.file,
                            StateKind::Open,
                            StatePayload::Open(OpenState {
                                owner: reservation.key.clone(),
                                access: reservation.access,
                                deny: reservation.deny,
                                contributions: reservation.contributions,
                                confirmed: !confirmation_required,
                                pin: reservation.pin,
                            }),
                        )
                        .map_err(|_| NfsStatus::Resource)?;
                    state.reserved_states = state
                        .reserved_states
                        .checked_sub(1)
                        .expect("new OPEN consumes its reserved state capacity");
                    reservation
                        .owner
                        .as_mut()
                        .expect("open target reservation owns its owner reservation")
                        .reserved_state = false;
                    pending_state = Some(PendingOpenStateGuard::new(&self.core, state_id));
                    (state_id, None, true, recovered_open)
                },
            }
        };
        let result = ResOp::Open(NfsResult::Ok(OpenOk {
            state_id,
            change_info,
            result_flags: OPEN4_RESULT_LOCKTYPE_POSIX | if confirmation_required { OPEN4_RESULT_CONFIRM } else { 0 },
            attributes_set,
            delegation: delegation.clone(),
        }));
        let effect = ReplayEffect {
            current_file: Some(reservation.file),
            ..reservation.replay_effect
        };
        let reply = encode_replay(&result)?;
        let owner_reservation = reservation
            .owner
            .as_ref()
            .expect("open target reservation owns its owner reservation");
        let mut batch = PersistBatch::default();
        if let Some(previous) = previous_state {
            batch = batch.delete(JournalKey::Open {
                state_token: state_token(previous),
            });
        }
        if let Some(recovered) = &recovered_open {
            batch = batch
                .delete(JournalKey::Open {
                    state_token: recovered.state_token,
                })
                .delete(JournalKey::Replay {
                    client_id: recovered.previous_client_id,
                    owner_kind: ReplayOwnerKind::Open,
                    owner: Bytes::copy_from_slice(&recovered.owner),
                });
        }
        batch = batch
            .put(
                JournalKey::Open {
                    state_token: state_token(state_id),
                },
                JournalRecord::Open(StableOpenRecord {
                    state_token: state_token(state_id),
                    client_id: reservation.key.client_id,
                    owner: Bytes::copy_from_slice(&reservation.key.owner),
                    object: reservation.file.stable(),
                    share_access: reservation.access.bits(),
                    share_deny: reservation.deny.bits(),
                    contributions: stable_open_contributions(reservation.contributions),
                }),
            )
            .put(
                replay_key(owner_reservation),
                JournalRecord::Replay(replay_record(owner_reservation, &result, effect, reply)),
            );

        // Everything that can produce a recoverable protocol error is checked
        // before the durable record is written. Once persistence succeeds,
        // the synchronous commit below contains only prevalidated transitions;
        // an invariant violation is fail-stop rather than a reply that
        // contradicts the stable OPEN success.
        {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            validate_delegation_eligibility(&state, &reservation, &delegation)?;
            let owner = state.open_owners.get(&reservation.key).ok_or(NfsStatus::ServerFault)?;
            if !matches!(
                owner.sequence.decide(owner_reservation.sequence_id, owner_reservation.digest),
                SequenceDecision::InProgress
            ) {
                return Err(NfsStatus::ServerFault);
            }
            match previous_state {
                Some(previous) => {
                    if state.open_by_owner_file.get(&(reservation.key.clone(), reservation.file)) != Some(&previous)
                        || state.stateids.preview_transition(previous).map_err(map_stateid_error)? != state_id
                    {
                        return Err(NfsStatus::ServerFault);
                    }
                },
                None => {
                    if owner_reservation.reserved_state || owner.active_states == usize::MAX {
                        return Err(NfsStatus::ServerFault);
                    }
                },
            }
            if let Some(recovered) = &recovered_open {
                if !state.reserved_recovered_opens.contains(&recovered.state_token)
                    || state.recovered_opens.get(&recovered.state_token) != Some(recovered)
                {
                    return Err(NfsStatus::ReclaimBad);
                }
            }
            let shard_index = shard_for(&reservation.file, self.core.files.len());
            let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
            let file_state = shard.files.get(&reservation.file).ok_or(NfsStatus::ServerFault)?;
            if !file_state.pending_opens.iter().any(|pending| {
                pending.reservation == reservation.reservation
                    && pending.owner == reservation.key
                    && pending.access == reservation.access
                    && pending.deny == reservation.deny
            }) {
                return Err(NfsStatus::ServerFault);
            }
            let mut candidate = file_state.shares.clone();
            let combined = candidate
                .install(
                    reservation.key.clone(),
                    reservation.contributions,
                    self.core.limits.max_open_contributions_per_state,
                )
                .map_err(|_| NfsStatus::ServerFault)?;
            if combined.access != reservation.access
                || combined.deny != reservation.deny
                || combined.contributions() != reservation.contributions
            {
                return Err(NfsStatus::ServerFault);
            }
        }
        self.persist_if_needed(batch).await?;

        let mut owner_reservation = reservation
            .owner
            .take()
            .expect("open target reservation owns its owner reservation");
        {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let shard_index = shard_for(&reservation.file, self.core.files.len());
            let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
            let file_state = shard.files.entry(reservation.file).or_default();
            let combined = file_state
                .shares
                .install(
                    reservation.key.clone(),
                    reservation.contributions,
                    self.core.limits.max_open_contributions_per_state,
                )
                .expect("prevalidated OPEN share installation remains valid");
            assert_eq!(combined.access, reservation.access, "prevalidated OPEN access changed");
            assert_eq!(combined.deny, reservation.deny, "prevalidated OPEN deny changed");
            assert_eq!(combined.contributions(), reservation.contributions, "prevalidated OPEN contributions changed");
            if let Some(previous) = previous_state {
                let transitioned = state
                    .stateids
                    .transition(previous)
                    .expect("prevalidated OPEN stateid transition remains valid");
                assert_eq!(transitioned, state_id, "prevalidated OPEN stateid transition changed");
                let record = state
                    .stateids
                    .identify_mut(state_id)
                    .expect("transitioned OPEN stateid remains active");
                let StatePayload::Open(open) = &mut record.payload else {
                    panic!("prevalidated OPEN stateid changed kind");
                };
                open.access = combined.access;
                open.deny = combined.deny;
                open.contributions = combined.contributions();
                let indexed = state
                    .open_by_owner_file
                    .insert((reservation.key.clone(), reservation.file), state_id);
                assert_eq!(indexed, Some(previous), "prevalidated OPEN index changed");
            } else {
                state
                    .stateids
                    .activate(state_id)
                    .expect("reserved pending OPEN stateid remains valid");
                pending_state.as_mut().expect("new OPEN owns its pending-state guard").commit();
                let indexed = state
                    .open_by_owner_file
                    .insert((reservation.key.clone(), reservation.file), state_id);
                assert!(indexed.is_none(), "new OPEN unexpectedly replaced an indexed stateid");
                let active_states = &mut state
                    .open_owners
                    .get_mut(&reservation.key)
                    .expect("reserved open owner exists")
                    .active_states;
                *active_states = active_states
                    .checked_add(1)
                    .expect("prevalidated OPEN owner state count overflow");
            }
            let owner = state.open_owners.get_mut(&reservation.key).expect("reserved open owner exists");
            if !confirmation_required {
                owner.confirmed = true;
            }
            owner
                .sequence
                .commit(owner_reservation.sequence_id, owner_reservation.digest, result.clone(), effect)
                .expect("prevalidated OPEN owner reservation remains executable");
            if owner_reservation.reserved_state {
                state.reserved_states = state.reserved_states.saturating_sub(1);
                owner_reservation.reserved_state = false;
            }
            owner_reservation.committed = true;
            if let Some(recovered) = &recovered_open {
                state.recovered_opens.remove(&recovered.state_token);
                state.reserved_recovered_opens.remove(&recovered.state_token);
                state.recovered_cleanup_keys.remove(&JournalKey::Open {
                    state_token: recovered.state_token,
                });
                let replay_key = (recovered.previous_client_id, ReplayOwnerKind::Open, recovered.owner.clone());
                state.recovered_replays.remove(&replay_key);
                state.recovered_cleanup_keys.remove(&JournalKey::Replay {
                    client_id: recovered.previous_client_id,
                    owner_kind: ReplayOwnerKind::Open,
                    owner: Bytes::copy_from_slice(&recovered.owner),
                });
                state
                    .reclaimed_open_ancestry
                    .insert(state_id.other, state_other(recovered.state_token));
            }
            reservation.recovered_open_token = None;
            file_state
                .pending_opens
                .retain(|pending| pending.reservation != reservation.reservation);
            reservation.pending_removed = true;
        }
        Ok(OpenCompletion {
            result,
            effect,
            newly_retained: newly_allocated,
        })
    }

    pub(crate) async fn begin_open_state_operation_with_identity(
        &self,
        state_id: StateId,
        current_file: RuntimeFile,
        sequence_id: u32,
        digest: OwnerRequestDigest,
        principal: &Principal,
        require_unconfirmed: bool,
    ) -> OpenStateDecision {
        // Keep replacement, confirmation, and expiry out of the stateid
        // lookup, lease validation, and owner-reservation handoff window.
        let _transition_guard = self.client_state_transition_guard().await;
        // CLOSE retires its stateid, but an exact retransmission still has to
        // replay the open-owner result.  The operation digest includes the
        // stateid and operation discriminant, so a bounded scan cannot match
        // another owner's unrelated request.
        let retired_replay = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            state
                .open_owners
                .iter()
                .find_map(|(key, owner)| match owner.sequence.decide(sequence_id, digest) {
                    SequenceDecision::Replay { result, context_effect } => {
                        Some((key.client_id, result, context_effect))
                    },
                    SequenceDecision::Execute | SequenceDecision::InProgress | SequenceDecision::BadSequence => None,
                })
        };
        if let Some((client_id, result, effect)) = retired_replay {
            if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
                return OpenStateDecision::Error {
                    status: error.status,
                    client_id: error.client_id,
                };
            }
            return OpenStateDecision::Replay {
                result,
                effect,
                client_id,
            };
        }
        let (key, client_id) = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = match state.stateids.identify(state_id) {
                Ok(record) => record,
                Err(error) => {
                    return OpenStateDecision::Error {
                        status: map_stateid_error(error),
                        client_id: None,
                    }
                },
            };
            let StatePayload::Open(open) = &record.payload else {
                return OpenStateDecision::Error {
                    status: NfsStatus::BadStateId,
                    client_id: None,
                };
            };
            (open.owner.clone(), record.client)
        };
        let decision = {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            match state.open_owners.get_mut(&key) {
                Some(owner) => owner.sequence.reserve(sequence_id, digest),
                None => {
                    return OpenStateDecision::Error {
                        status: NfsStatus::BadStateId,
                        client_id: None,
                    }
                },
            }
        };
        match decision {
            SequenceDecision::Replay { result, context_effect } => {
                if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
                    return OpenStateDecision::Error {
                        status: error.status,
                        client_id: error.client_id,
                    };
                }
                return OpenStateDecision::Replay {
                    result,
                    effect: context_effect,
                    client_id,
                };
            },
            SequenceDecision::InProgress => {
                let stateid_is_valid = matches!(
                    self.core
                        .state
                        .lock()
                        .expect("NFSv4 state registry poisoned")
                        .stateids
                        .validate(state_id, &current_file, &[StateKind::Open]),
                    Ok(StateIdValidation::Active(_))
                );
                if !stateid_is_valid {
                    return OpenStateDecision::Error {
                        status: NfsStatus::Delay,
                        client_id: None,
                    };
                }
                if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
                    return OpenStateDecision::Error {
                        status: error.status,
                        client_id: error.client_id,
                    };
                }
                return OpenStateDecision::Error {
                    status: NfsStatus::Delay,
                    client_id: Some(client_id),
                };
            },
            SequenceDecision::BadSequence => {
                let stateid_is_valid = matches!(
                    self.core
                        .state
                        .lock()
                        .expect("NFSv4 state registry poisoned")
                        .stateids
                        .validate(state_id, &current_file, &[StateKind::Open]),
                    Ok(StateIdValidation::Active(_))
                );
                if !stateid_is_valid {
                    return OpenStateDecision::Error {
                        status: NfsStatus::BadSequenceId,
                        client_id: None,
                    };
                }
                if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
                    return OpenStateDecision::Error {
                        status: error.status,
                        client_id: error.client_id,
                    };
                }
                return OpenStateDecision::Error {
                    status: NfsStatus::BadSequenceId,
                    client_id: Some(client_id),
                };
            },
            SequenceDecision::Execute => {},
        }
        let open = {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let validated = match state.stateids.validate(state_id, &current_file, &[StateKind::Open]) {
                Ok(StateIdValidation::Active(record)) => record,
                Ok(StateIdValidation::Anonymous | StateIdValidation::ReadBypass) => {
                    if let Some(owner) = state.open_owners.get_mut(&key) {
                        owner.sequence.cancel(sequence_id, digest);
                    }
                    return OpenStateDecision::Error {
                        status: NfsStatus::BadStateId,
                        client_id: None,
                    };
                },
                Err(error) => {
                    if let Some(owner) = state.open_owners.get_mut(&key) {
                        owner.sequence.cancel(sequence_id, digest);
                    }
                    return OpenStateDecision::Error {
                        status: map_stateid_error(error),
                        client_id: None,
                    };
                },
            };
            let StatePayload::Open(open) = &validated.payload else {
                if let Some(owner) = state.open_owners.get_mut(&key) {
                    owner.sequence.cancel(sequence_id, digest);
                }
                return OpenStateDecision::Error {
                    status: NfsStatus::BadStateId,
                    client_id: None,
                };
            };
            open.clone()
        };
        if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            if let Some(owner) = state.open_owners.get_mut(&key) {
                owner.sequence.cancel(sequence_id, digest);
            }
            return OpenStateDecision::Error {
                status: error.status,
                client_id: error.client_id,
            };
        }
        if open.confirmed == require_unconfirmed {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            if let Some(owner) = state.open_owners.get_mut(&key) {
                owner.sequence.cancel(sequence_id, digest);
            }
            return OpenStateDecision::Error {
                status: NfsStatus::BadStateId,
                client_id: Some(client_id),
            };
        }
        OpenStateDecision::Execute(OpenStateReservation {
            owner: Some(OwnerReservation {
                core: Arc::downgrade(&self.core),
                kind: ReservedOwnerKind::Open,
                client_id,
                owner: key.owner.clone(),
                sequence_id,
                digest,
                reserved_state: false,
                created_owner: false,
                committed: false,
            }),
            key,
            file: current_file,
            state_id,
            access: open.access,
            deny: open.deny,
            contributions: open.contributions,
            pin: open.pin,
        })
    }

    /// Compatibility view for runtime-only callers that do not need the
    /// authenticated identity retained by the compound executor.
    #[cfg(test)]
    pub(crate) async fn begin_open_state_operation(
        &self,
        state_id: StateId,
        current_file: RuntimeFile,
        sequence_id: u32,
        digest: OwnerRequestDigest,
        principal: &Principal,
        require_unconfirmed: bool,
    ) -> StatefulDecision<OpenStateReservation> {
        match self
            .begin_open_state_operation_with_identity(
                state_id,
                current_file,
                sequence_id,
                digest,
                principal,
                require_unconfirmed,
            )
            .await
        {
            OpenStateDecision::Execute(reservation) => StatefulDecision::Execute(reservation),
            OpenStateDecision::Replay { result, effect, .. } => StatefulDecision::Replay { result, effect },
            OpenStateDecision::Error { status, .. } => StatefulDecision::Error(status),
        }
    }

    pub(crate) async fn complete_open_state_error(
        &self,
        mut reservation: OpenStateReservation,
        status: NfsStatus,
        result: ResOp,
    ) -> ResOp {
        let owner = reservation
            .owner
            .take()
            .expect("open state reservation owns its owner reservation");
        self.complete_owner_error(owner, status, result).await
    }

    pub(crate) async fn prepare_close(
        &self,
        reservation: OpenStateReservation,
    ) -> Result<PreparedCloseReservation, ResOp> {
        let gate = self.operation_gate(reservation.file).await;
        let shard_index = shard_for(&reservation.file, self.core.files.len());
        let locks_held = {
            let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
            shard
                .files
                .get(&reservation.file)
                .is_some_and(|file| file.locks.has_open(&reservation.state_id.other))
        };
        if locks_held {
            return Err(self
                .complete_open_state_error(
                    reservation,
                    NfsStatus::LocksHeld,
                    ResOp::Close(NfsResult::Err(NfsStatus::LocksHeld)),
                )
                .await);
        }
        Ok(PreparedCloseReservation {
            reservation,
            _gate: gate,
        })
    }

    pub(crate) async fn confirm_open(&self, mut reservation: OpenStateReservation) -> Result<ResOp, NfsStatus> {
        let mut owner_reservation = reservation
            .owner
            .take()
            .expect("open state reservation owns its owner reservation");
        let next = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            state
                .stateids
                .preview_transition(reservation.state_id)
                .map_err(map_stateid_error)?
        };
        let result = ResOp::OpenConfirm(NfsResult::Ok(next));
        self.persist_open_state_transition(
            &owner_reservation,
            &reservation,
            next,
            &result,
            reservation.access,
            reservation.deny,
            reservation.contributions,
        )
        .await?;
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let transitioned = state.stateids.transition(reservation.state_id).map_err(map_stateid_error)?;
        if transitioned != next {
            return Err(NfsStatus::ServerFault);
        }
        let record = state.stateids.identify_mut(next).map_err(map_stateid_error)?;
        let StatePayload::Open(open) = &mut record.payload else {
            return Err(NfsStatus::ServerFault);
        };
        open.confirmed = true;
        let owner = state.open_owners.get_mut(&reservation.key).ok_or(NfsStatus::ServerFault)?;
        owner.confirmed = true;
        owner
            .sequence
            .commit(owner_reservation.sequence_id, owner_reservation.digest, result.clone(), ReplayEffect::default())
            .map_err(|_| NfsStatus::ServerFault)?;
        state
            .open_by_owner_file
            .insert((reservation.key.clone(), reservation.file), next);
        owner_reservation.committed = true;
        Ok(result)
    }

    pub(crate) async fn downgrade_open(
        &self,
        mut reservation: OpenStateReservation,
        share_access: u32,
        share_deny: u32,
    ) -> Result<ResOp, NfsStatus> {
        let Some(access) = ShareAccess::from_wire(share_access) else {
            return Ok(self
                .complete_open_state_error(
                    reservation,
                    NfsStatus::Invalid,
                    ResOp::OpenDowngrade(NfsResult::Err(NfsStatus::Invalid)),
                )
                .await);
        };
        let Some(deny) = ShareDeny::from_wire(share_deny) else {
            return Ok(self
                .complete_open_state_error(
                    reservation,
                    NfsStatus::Invalid,
                    ResOp::OpenDowngrade(NfsResult::Err(NfsStatus::Invalid)),
                )
                .await);
        };
        let _gate = self.operation_gate(reservation.file).await;
        let shard_index = shard_for(&reservation.file, self.core.files.len());
        let planned_contributions = {
            let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
            let Some(file) = shard.files.get(&reservation.file) else {
                return Err(NfsStatus::ServerFault);
            };
            let mut candidate = file.shares.clone();
            match candidate.downgrade(&reservation.key, access, deny) {
                Err(_) => Err(NfsStatus::Invalid),
                Ok(downgraded) => {
                    let open = &reservation.state_id.other;
                    let permits_read = access.bits() & ShareAccess::READ.bits() != 0;
                    let permits_write = access.bits() & ShareAccess::WRITE.bits() != 0;
                    if (!permits_read && file.locks.open_requires(open, LockAccess::Read))
                        || (!permits_write && file.locks.open_requires(open, LockAccess::Write))
                    {
                        Err(NfsStatus::LocksHeld)
                    } else {
                        Ok(downgraded.contributions())
                    }
                },
            }
        };
        let planned_contributions = match planned_contributions {
            Ok(contributions) => contributions,
            Err(status) => {
                return Ok(self
                    .complete_open_state_error(reservation, status, ResOp::OpenDowngrade(NfsResult::Err(status)))
                    .await)
            },
        };
        let mut owner_reservation = reservation
            .owner
            .take()
            .expect("open state reservation owns its owner reservation");
        let next = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            state
                .stateids
                .preview_transition(reservation.state_id)
                .map_err(map_stateid_error)?
        };
        let result = ResOp::OpenDowngrade(NfsResult::Ok(next));
        self.persist_open_state_transition(
            &owner_reservation,
            &reservation,
            next,
            &result,
            access,
            deny,
            planned_contributions,
        )
        .await?;
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        let file = shard.files.get_mut(&reservation.file).ok_or(NfsStatus::ServerFault)?;
        let downgraded = file
            .shares
            .downgrade(&reservation.key, access, deny)
            .map_err(|_| NfsStatus::ServerFault)?;
        if downgraded.contributions() != planned_contributions {
            return Err(NfsStatus::ServerFault);
        }
        let transitioned = state.stateids.transition(reservation.state_id).map_err(map_stateid_error)?;
        if transitioned != next {
            return Err(NfsStatus::ServerFault);
        }
        let record = state.stateids.identify_mut(next).map_err(map_stateid_error)?;
        let StatePayload::Open(open) = &mut record.payload else {
            return Err(NfsStatus::ServerFault);
        };
        open.access = access;
        open.deny = deny;
        open.contributions = planned_contributions;
        state
            .open_by_owner_file
            .insert((reservation.key.clone(), reservation.file), next);
        let owner = state.open_owners.get_mut(&reservation.key).ok_or(NfsStatus::ServerFault)?;
        owner
            .sequence
            .commit(owner_reservation.sequence_id, owner_reservation.digest, result.clone(), ReplayEffect::default())
            .map_err(|_| NfsStatus::ServerFault)?;
        owner_reservation.committed = true;
        Ok(result)
    }

    pub(crate) async fn close_open(&self, prepared: PreparedCloseReservation) -> Result<CloseCompletion, NfsStatus> {
        let runtime = self.clone();
        let critical = self.core.critical_tasks.start();
        match tokio::spawn(async move {
            let _critical = critical;
            runtime.close_open_critical(prepared).await
        })
        .await
        {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => panic!("critical CLOSE completion task was cancelled"),
        }
    }

    /// Cancellation-shielded durable and in-memory CLOSE transition.
    async fn close_open_critical(&self, mut prepared: PreparedCloseReservation) -> Result<CloseCompletion, NfsStatus> {
        let reservation = &mut prepared.reservation;
        let shard_index = shard_for(&reservation.file, self.core.files.len());
        let owner_reservation = reservation
            .owner
            .as_ref()
            .expect("open state reservation owns its owner reservation");
        let (next, derived_lock_states) = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = state
                .stateids
                .validate(reservation.state_id, &reservation.file, &[StateKind::Open])
                .map_err(map_stateid_error)?;
            let StateIdValidation::Active(record) = record else {
                return Err(NfsStatus::BadStateId);
            };
            let StatePayload::Open(open) = &record.payload else {
                return Err(NfsStatus::BadStateId);
            };
            if open.owner != reservation.key
                || open.pin != reservation.pin
                || state.open_by_owner_file.get(&(reservation.key.clone(), reservation.file))
                    != Some(&reservation.state_id)
            {
                return Err(NfsStatus::ServerFault);
            }
            let owner = state.open_owners.get(&reservation.key).ok_or(NfsStatus::ServerFault)?;
            if owner.active_states == 0
                || !matches!(
                    owner.sequence.decide(owner_reservation.sequence_id, owner_reservation.digest),
                    SequenceDecision::InProgress
                )
            {
                return Err(NfsStatus::ServerFault);
            }
            if state.pending_pin_releases.len() >= self.core.limits.max_state_objects {
                return Err(NfsStatus::Resource);
            }
            let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
            let file = shard.files.get(&reservation.file).ok_or(NfsStatus::ServerFault)?;
            if file.locks.has_open(&reservation.state_id.other)
                || !file.shares.reservations().iter().any(|share| share.owner == reservation.key)
            {
                return Err(if file.locks.has_open(&reservation.state_id.other) {
                    NfsStatus::LocksHeld
                } else {
                    NfsStatus::ServerFault
                });
            }
            let derived_lock_states = state
                .lock_by_state
                .iter()
                .filter(|((lock_state_owner, file), _)| {
                    *file == reservation.file && lock_state_owner.open == reservation.state_id.other
                })
                .map(|(map_key, lock_state_id)| (map_key.clone(), *lock_state_id))
                .collect::<Vec<_>>();
            for ((lock_state_owner, file), lock_state_id) in &derived_lock_states {
                let record = state.stateids.identify(*lock_state_id).map_err(map_stateid_error)?;
                let StatePayload::Lock(lock) = &record.payload else {
                    return Err(NfsStatus::ServerFault);
                };
                if record.file != *file
                    || lock.owner != lock_state_owner.owner
                    || lock.open_state_id.other != reservation.state_id.other
                    || state
                        .lock_owners
                        .get(&lock_state_owner.owner)
                        .is_none_or(|owner| owner.active_states == 0)
                {
                    return Err(NfsStatus::ServerFault);
                }
            }
            let next = state
                .stateids
                .preview_transition(reservation.state_id)
                .map_err(map_stateid_error)?;
            (next, derived_lock_states)
        };
        let result = ResOp::Close(NfsResult::Ok(next));
        let reply = encode_replay(&result)?;
        let batch = PersistBatch::default()
            .delete(JournalKey::Open {
                state_token: state_token(reservation.state_id),
            })
            .put(
                replay_key(owner_reservation),
                JournalRecord::Replay(replay_record(owner_reservation, &result, ReplayEffect::default(), reply)),
            );
        self.persist_if_needed(batch).await?;

        // No await follows persistence: either every prevalidated transition
        // commits and the caller receives the backend pin to release, or an
        // impossible concurrent invariant violation terminates this task.
        let mut owner_reservation = reservation
            .owner
            .take()
            .expect("open state reservation owns its owner reservation");
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        let file = shard
            .files
            .get_mut(&reservation.file)
            .expect("prevalidated CLOSE file state remains present");
        assert!(file.shares.close(&reservation.key), "prevalidated CLOSE share reservation remains present");
        if file.is_empty() {
            shard.files.remove(&reservation.file);
        }
        let transitioned = state
            .stateids
            .transition(reservation.state_id)
            .expect("prevalidated CLOSE stateid transition remains valid");
        assert_eq!(transitioned, next, "prevalidated CLOSE stateid transition changed");
        state
            .stateids
            .set_disposition(next, StateDisposition::Closed)
            .expect("transitioned CLOSE stateid can be retired");
        let indexed = state.open_by_owner_file.remove(&(reservation.key.clone(), reservation.file));
        assert_eq!(indexed, Some(reservation.state_id), "prevalidated CLOSE state index changed");
        for (map_key, lock_state_id) in derived_lock_states {
            let lock_owner_key = map_key.0.owner.clone();
            assert_eq!(
                state.lock_by_state.remove(&map_key),
                Some(lock_state_id),
                "prevalidated CLOSE lock-state index changed"
            );
            state
                .stateids
                .set_disposition(lock_state_id, StateDisposition::Closed)
                .expect("prevalidated empty lock state can be retired with its OPEN");
            let lock_owner = state
                .lock_owners
                .get_mut(&lock_owner_key)
                .expect("prevalidated CLOSE lock owner remains present");
            lock_owner.active_states = lock_owner
                .active_states
                .checked_sub(1)
                .expect("prevalidated CLOSE lock owner has active state");
        }
        state.reclaimed_open_ancestry.remove(&reservation.state_id.other);
        let owner = state
            .open_owners
            .get_mut(&reservation.key)
            .expect("prevalidated CLOSE owner remains present");
        owner.active_states = owner
            .active_states
            .checked_sub(1)
            .expect("prevalidated CLOSE owner has active state");
        owner
            .sequence
            .commit(owner_reservation.sequence_id, owner_reservation.digest, result.clone(), ReplayEffect::default())
            .expect("prevalidated CLOSE owner reservation remains executable");
        owner_reservation.committed = true;
        state.queue_pin_release(
            ReleasedOpen {
                client_id: reservation.key.client_id,
                file: reservation.file,
                pin: reservation.pin,
            },
            self.core.limits.max_state_objects,
        );
        Ok(CloseCompletion { result })
    }

    #[allow(clippy::too_many_arguments)]
    async fn persist_open_state_transition(
        &self,
        owner: &OwnerReservation,
        reservation: &OpenStateReservation,
        next: StateId,
        result: &ResOp,
        access: ShareAccess,
        deny: ShareDeny,
        contributions: ShareContributions,
    ) -> Result<(), NfsStatus> {
        let reply = encode_replay(result)?;
        let batch = PersistBatch::default()
            .delete(JournalKey::Open {
                state_token: state_token(reservation.state_id),
            })
            .put(
                JournalKey::Open {
                    state_token: state_token(next),
                },
                JournalRecord::Open(StableOpenRecord {
                    state_token: state_token(next),
                    client_id: reservation.key.client_id,
                    owner: Bytes::copy_from_slice(&reservation.key.owner),
                    object: reservation.file.stable(),
                    share_access: access.bits(),
                    share_deny: deny.bits(),
                    contributions: stable_open_contributions(contributions),
                }),
            )
            .put(
                replay_key(owner),
                JournalRecord::Replay(replay_record(owner, result, ReplayEffect::default(), reply)),
            );
        self.persist_if_needed(batch).await
    }

    pub(crate) async fn expire_due(&self) -> Vec<PendingPinRelease> {
        // Stateful begin paths use the same gate through owner reservation.
        // Existing reservations are detected below and left pending for the
        // next maintenance pass.
        let _transition_guard = self.client_state_transition_guard().await;
        let pending = {
            let mut clients = self.core.clients.lock().await;
            let expired = clients.leases.expire_due();
            for client_id in &expired {
                clients.expired.insert(*client_id);
                clients.pending_expiry.insert(*client_id);
            }
            bound_expired_clientids(&mut clients, self.core.limits.max_clients);
            clients.pending_expiry.iter().copied().collect::<Vec<_>>()
        };
        let mut released = Vec::new();
        for client_id in pending {
            if self.client_has_live_owner_reservation(client_id) {
                continue;
            }
            let batch = self.client_revocation_batch(client_id);
            if self.persist_if_needed(batch).await.is_err() {
                continue;
            }
            released.extend(self.revoke_client(client_id, StateDisposition::LeaseExpired));
            let mut clients = self.core.clients.lock().await;
            remove_client_registration(&mut clients, client_id);
            clients.pending_expiry.remove(&client_id);
        }
        released
    }

    /// Reports that the bounded recovery window has elapsed but leaves all
    /// recovery records intact. COMPOUND uses this retryable phase to revoke
    /// unreclaimed delegations before calling [`Self::finish_grace_if_due`].
    pub(crate) async fn grace_cleanup_due(&self) -> bool {
        let clients = self.core.clients.lock().await;
        clients.recovery_had_grace && !clients.grace_cleanup_complete && clients.recovery.cleanup_due()
    }

    pub(crate) async fn ensure_not_in_grace(&self) -> Result<(), NfsStatus> {
        let clients = self.core.clients.lock().await;
        if clients.recovery.mode() == RecoveryMode::Grace {
            Err(NfsStatus::Grace)
        } else {
            Ok(())
        }
    }

    /// Durably removes runtime-owned recovery candidates exactly once after
    /// delegation managers have successfully completed their pre-cleanup.
    pub(crate) async fn finish_grace_if_due(&self) -> Result<bool, NfsStatus> {
        let mut clients = self.core.clients.lock().await;
        if !clients.recovery_had_grace || clients.grace_cleanup_complete {
            return Ok(false);
        }
        if !clients.recovery.cleanup_due() {
            return Ok(false);
        }
        let cleanup_keys = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            state.recovered_cleanup_keys.iter().cloned().collect::<Vec<_>>()
        };
        let mut batch = PersistBatch::default();
        for key in cleanup_keys {
            batch = batch.delete(key);
        }
        self.persist_if_needed(batch).await?;
        {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            state.recovered_opens.clear();
            state.recovered_locks.clear();
            state.recovered_replays.clear();
            state.recovered_cleanup_keys.clear();
            state.reserved_recovered_opens.clear();
        }
        clients.recovered_clients.clear();
        clients.current_to_previous.clear();
        clients.recovery.end_grace();
        clients.grace_cleanup_complete = true;
        Ok(true)
    }

    /// Compatibility view of I/O stateid validation for callers that only
    /// need an NFS status.  The compound executor uses
    /// [`Self::validate_io_with_identity`] to apply RFC 7530 section 9.5
    /// after a post-authentication error.
    pub(crate) async fn validate_io(
        &self,
        state_id: StateId,
        file: RuntimeFile,
        access: IoAccess,
        offset: u64,
        length: u64,
        principal: &Principal,
    ) -> Result<IoPermit, NfsStatus> {
        self.validate_io_with_identity(state_id, file, access, offset, length, principal)
            .await
            .map_err(|error| error.status)
    }

    /// Validates I/O while preserving the identity authenticated before a
    /// later operation-specific failure such as OPENMODE or an invalid range.
    pub(crate) async fn validate_io_with_identity(
        &self,
        state_id: StateId,
        file: RuntimeFile,
        access: IoAccess,
        offset: u64,
        length: u64,
        principal: &Principal,
    ) -> Result<IoPermit, IoValidationError> {
        let in_grace = {
            let clients = self.core.clients.lock().await;
            clients.recovery.mode() == RecoveryMode::Grace
        };
        // LOCK, LOCKU, CLOSE, and stateid-changing OPEN operations use this
        // same bounded per-file gate. Keeping it in the returned permit
        // closes the validation/backend-I/O race without holding a registry
        // mutex across a VFS await.
        let gate = self.operation_gate(file).await;

        #[derive(Clone)]
        enum Identity {
            Anonymous,
            ReadBypass,
            Open { client_id: u64, open: OpenState },
            Lock { client_id: u64, open: OpenState },
        }

        let identity = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let validated = match state
                .stateids
                .validate(state_id, &file, &[StateKind::Open, StateKind::ByteRangeLock])
            {
                Ok(validated) => validated,
                Err(error) => {
                    // RFC 7530 §9.5 renews only a *valid* non-special
                    // stateid. Matching its opaque `other` field is not
                    // enough: an old, bad, stale, or wrong-file stateid
                    // cannot authenticate a lease renewal.
                    return Err(IoValidationError::unauthenticated(if in_grace {
                        NfsStatus::Grace
                    } else {
                        map_stateid_error(error)
                    }));
                },
            };
            match validated {
                StateIdValidation::Anonymous => Identity::Anonymous,
                StateIdValidation::ReadBypass if access == IoAccess::Read => Identity::ReadBypass,
                // RFC 7530 gives the all-ones stateid special bypass meaning
                // only for READ. WRITE and size-changing SETATTR treat it as
                // the anonymous stateid and remain subject to share state.
                StateIdValidation::ReadBypass => Identity::Anonymous,
                StateIdValidation::Active(record) => match &record.payload {
                    StatePayload::Open(open) => Identity::Open {
                        client_id: record.client,
                        open: open.clone(),
                    },
                    StatePayload::Lock(lock) => {
                        let open_record = match state.stateids.identify(lock.open_state_id) {
                            Ok(record) => record,
                            Err(error) => {
                                return Err(if in_grace {
                                    IoValidationError::unauthenticated(NfsStatus::Grace)
                                } else {
                                    IoValidationError::authenticated(map_stateid_error(error), record.client)
                                });
                            },
                        };
                        if open_record.file != file
                            || open_record.client != record.client
                            || open_record.kind != StateKind::Open
                        {
                            return Err(if in_grace {
                                IoValidationError::unauthenticated(NfsStatus::Grace)
                            } else {
                                IoValidationError::authenticated(NfsStatus::BadStateId, record.client)
                            });
                        }
                        let StatePayload::Open(open) = &open_record.payload else {
                            return Err(if in_grace {
                                IoValidationError::unauthenticated(NfsStatus::Grace)
                            } else {
                                IoValidationError::authenticated(NfsStatus::BadStateId, record.client)
                            });
                        };
                        Identity::Lock {
                            client_id: record.client,
                            open: open.clone(),
                        }
                    },
                },
            }
        };

        let client_id = match &identity {
            Identity::Anonymous | Identity::ReadBypass => None,
            Identity::Open { client_id, .. } | Identity::Lock { client_id, .. } => {
                match self.touch_io_client_authenticated(*client_id, principal).await {
                    Ok(()) => {},
                    // GRACE retains precedence over a migrated lease, but
                    // the successful authentication and lease touch still
                    // prove this non-special stateid may renew every
                    // delegation manager (RFC 7530 §9.5).
                    Err(error) if in_grace && error.client_id == Some(*client_id) => {
                        return Err(IoValidationError::authenticated(NfsStatus::Grace, *client_id));
                    },
                    Err(error) => {
                        return Err(match error.client_id {
                            Some(client_id) => IoValidationError::authenticated(error.status, client_id),
                            None => IoValidationError::unauthenticated(error.status),
                        });
                    },
                }
                Some(*client_id)
            },
        };
        if in_grace {
            return Err(match client_id {
                Some(client_id) => IoValidationError::authenticated(NfsStatus::Grace, client_id),
                None => IoValidationError::unauthenticated(NfsStatus::Grace),
            });
        }
        let delegation_access = match access {
            IoAccess::Read => DelegationKind::Read,
            IoAccess::Write | IoAccess::SetSize => DelegationKind::Write,
        };
        let delegation_access = self
            .begin_delegation_access(file, client_id, delegation_access, matches!(access, IoAccess::SetSize))
            .map_err(|status| match client_id {
                Some(client_id) => IoValidationError::authenticated(status, client_id),
                None => IoValidationError::unauthenticated(status),
            })?;
        let required = match access {
            IoAccess::Read => ShareAccess::READ,
            IoAccess::Write | IoAccess::SetSize => ShareAccess::WRITE,
        };
        match &identity {
            Identity::Open { open, .. } | Identity::Lock { open, .. } => {
                if !open.confirmed || open.access.bits() & required.bits() == 0 {
                    return Err(IoValidationError::authenticated(
                        NfsStatus::OpenMode,
                        client_id.expect("runtime state identity has a client"),
                    ));
                }
            },
            Identity::Anonymous | Identity::ReadBypass => {},
        }

        let shard_index = shard_for(&file, self.core.files.len());
        let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        let Some(file_state) = shard.files.get(&file) else {
            return Ok(IoPermit {
                client_id,
                _gate: gate,
                _delegation_access: Some(delegation_access),
            });
        };
        if matches!(identity, Identity::Anonymous) && file_state.shares.conflicts_with_access(required) {
            return Err(IoValidationError::unauthenticated(NfsStatus::Locked));
        }
        if matches!(identity, Identity::ReadBypass) {
            return Ok(IoPermit {
                client_id,
                _gate: gate,
                _delegation_access: Some(delegation_access),
            });
        }
        if length != 0 {
            // This server implements RFC 7530 advisory byte-range locking:
            // LOCK and LOCKT reject conflicting lock requests, but established
            // byte-range locks do not make READ, WRITE, or size-changing
            // SETATTR mandatory-lock operations. In particular, an OPEN
            // stateid cannot identify which of several lock-owners derived
            // from that OPEN sent the I/O, so it must not be treated as one.
            // Still validate the 64-bit I/O range before reaching the backend.
            LockRange::from_offset_length(offset, length).map_err(|_| match client_id {
                Some(client_id) => IoValidationError::authenticated(NfsStatus::Invalid, client_id),
                None => IoValidationError::unauthenticated(NfsStatus::Invalid),
            })?;
        }
        Ok(IoPermit {
            client_id,
            _gate: gate,
            _delegation_access: Some(delegation_access),
        })
    }

    /// Reserves the same bounded I/O gate after a delegation stateid has been
    /// validated by the delegation manager.  The access reservation keeps a
    /// conflicting grant candidate out if DELEGRETURN races after validation.
    pub(crate) async fn reserve_delegation_io(
        &self,
        file: RuntimeFile,
        client_id: u64,
        access: IoAccess,
    ) -> Result<IoPermit, NfsStatus> {
        let kind = match access {
            IoAccess::Read => DelegationKind::Read,
            IoAccess::Write | IoAccess::SetSize => DelegationKind::Write,
        };
        let delegation_access =
            self.begin_delegation_access(file, Some(client_id), kind, matches!(access, IoAccess::SetSize))?;
        Ok(IoPermit {
            client_id: Some(client_id),
            _gate: self.operation_gate(file).await,
            _delegation_access: Some(delegation_access),
        })
    }

    pub(crate) fn reserve_delegation_eligibility(
        &self,
        target: &mut OpenTargetReservation,
        client_id: u64,
        kind: DelegationKind,
    ) -> Result<DelegationEligibilityReservation, NfsStatus> {
        if target.key.client_id != client_id || target.delegation_eligibility.is_some() {
            return Err(NfsStatus::ServerFault);
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        if state.delegation_eligibility.len() >= self.core.limits.max_state_objects {
            return Err(NfsStatus::Resource);
        }
        if state.delegation_access.values().any(|access| {
            access.file == target.file
                && access.client_id != Some(client_id)
                && (access.truncate || delegation_kinds_conflict(kind, access.access))
        }) {
            return Err(NfsStatus::Delay);
        }
        if state.delegation_eligibility.values().any(|candidate| {
            candidate.file == target.file
                && (candidate.client_id == client_id
                    || delegation_kinds_conflict(candidate.kind, kind)
                    || delegation_kinds_conflict(kind, candidate.kind))
        }) {
            return Err(NfsStatus::Delay);
        }
        let shard_index = shard_for(&target.file, self.core.files.len());
        let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        let Some(file_state) = shard.files.get(&target.file) else {
            return Err(NfsStatus::ServerFault);
        };
        if !file_state
            .pending_opens
            .iter()
            .any(|pending| pending.reservation == target.reservation && pending.owner == target.key)
        {
            return Err(NfsStatus::ServerFault);
        }
        if !delegation_share_eligible_locked(file_state, client_id, kind) {
            return Err(NfsStatus::Delay);
        }

        let id = (0..=self.core.limits.max_state_objects)
            .find_map(|_| {
                let candidate = state.next_delegation_eligibility;
                state.next_delegation_eligibility = state.next_delegation_eligibility.wrapping_add(1).max(1);
                (!state.delegation_eligibility.contains_key(&candidate)).then_some(candidate)
            })
            .ok_or(NfsStatus::Resource)?;
        state.delegation_eligibility.insert(
            id,
            PendingDelegationEligibility {
                file: target.file,
                client_id,
                kind,
                open_reservation: target.reservation,
            },
        );
        drop(shard);
        drop(state);
        let reservation = DelegationEligibilityReservation {
            inner: Arc::new(DelegationEligibilityReservationInner {
                core: Arc::downgrade(&self.core),
                id,
            }),
        };
        target.delegation_eligibility = Some(reservation.clone());
        Ok(reservation)
    }

    /// Atomically reserves access against a delegation candidate. The caller
    /// holds the returned token through held-delegation recall and the
    /// backend or runtime mutation.
    pub(crate) fn begin_delegation_access(
        &self,
        file: RuntimeFile,
        requesting_client: Option<u64>,
        access: DelegationKind,
        truncate: bool,
    ) -> Result<DelegationAccessReservation, NfsStatus> {
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        if state.delegation_eligibility.values().any(|candidate| {
            candidate.file == file
                && requesting_client != Some(candidate.client_id)
                && (truncate || delegation_kinds_conflict(candidate.kind, access))
        }) {
            return Err(NfsStatus::Delay);
        }
        if state.delegation_access.len() >= self.core.limits.max_state_objects {
            return Err(NfsStatus::Resource);
        }
        let id = (0..=self.core.limits.max_state_objects)
            .find_map(|_| {
                let candidate = state.next_delegation_access;
                state.next_delegation_access = state.next_delegation_access.wrapping_add(1).max(1);
                (!state.delegation_access.contains_key(&candidate)).then_some(candidate)
            })
            .ok_or(NfsStatus::Resource)?;
        state.delegation_access.insert(
            id,
            PendingDelegationAccess {
                file,
                client_id: requesting_client,
                access,
                truncate,
            },
        );
        Ok(DelegationAccessReservation {
            core: Arc::downgrade(&self.core),
            id,
        })
    }

    fn delegation_access_matches(
        &self,
        reservation: &DelegationAccessReservation,
        file: RuntimeFile,
        requesting_client: Option<u64>,
        access: DelegationKind,
        truncate: bool,
    ) -> bool {
        if !Weak::ptr_eq(&reservation.core, &Arc::downgrade(&self.core)) {
            return false;
        }
        self.core
            .state
            .lock()
            .expect("NFSv4 state registry poisoned")
            .delegation_access
            .get(&reservation.id)
            .is_some_and(|pending| {
                *pending
                    == PendingDelegationAccess {
                        file,
                        client_id: requesting_client,
                        access,
                        truncate,
                    }
            })
    }

    fn client_has_open_or_lock_state(&self, client_id: u64, previous_client_ids: &[u64]) -> bool {
        let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let has_active_state = state.stateids.active_records_for_client(&client_id).next().is_some();
        has_active_state
            || state.open_owners.iter().any(|(owner, state)| {
                owner.client_id == client_id && (state.active_states != 0 || state.sequence.has_pending())
            })
            || state.lock_owners.iter().any(|(owner, state)| {
                owner.client_id == client_id && (state.active_states != 0 || state.sequence.has_pending())
            })
            || state
                .recovered_opens
                .values()
                .any(|open| previous_client_ids.contains(&open.previous_client_id))
            || state
                .recovered_locks
                .values()
                .any(|lock| previous_client_ids.contains(&lock.previous_client_id))
    }

    fn client_has_live_owner_reservation(&self, client_id: u64) -> bool {
        let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        state
            .open_owners
            .iter()
            .any(|(owner, state)| owner.client_id == client_id && state.sequence.has_pending())
            || state
                .lock_owners
                .iter()
                .any(|(owner, state)| owner.client_id == client_id && state.sequence.has_pending())
    }

    pub(crate) async fn lock_test_with_identity(
        &self,
        arguments: &LockTestArgs,
        file: RuntimeFile,
        principal: &Principal,
    ) -> LockTestDecision {
        let _transition_guard = self.client_state_transition_guard().await;
        if arguments.owner.owner.len() > self.core.limits.max_client_owner_size {
            return LockTestDecision {
                result: LockTestResult::Err(NfsStatus::Resource),
                client_id: None,
            };
        }
        let range = match LockRange::from_offset_length(arguments.offset, arguments.length) {
            Ok(range) => range,
            Err(_) => {
                return LockTestDecision {
                    result: LockTestResult::Err(NfsStatus::Invalid),
                    client_id: None,
                }
            },
        };
        if let Err(error) = self
            .gate_state_client_with_identity(arguments.owner.client_id, principal, false)
            .await
        {
            return LockTestDecision {
                result: LockTestResult::Err(error.status),
                client_id: error.client_id,
            };
        }
        let owner = LockOwnerKey::from(&arguments.owner);
        let shard_index = shard_for(&file, self.core.files.len());
        let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        let result = match shard.files.get(&file).and_then(|file| {
            file.locks
                .conflict_excluding(|candidate| candidate.owner == owner, lock_access(arguments.lock_type), range)
        }) {
            Some(conflict) => LockTestResult::Denied(denied(conflict)),
            None => LockTestResult::Ok,
        };
        LockTestDecision {
            result,
            client_id: Some(arguments.owner.client_id),
        }
    }

    #[cfg(test)]
    pub(crate) async fn lock_test(
        &self,
        arguments: &LockTestArgs,
        file: RuntimeFile,
        principal: &Principal,
    ) -> LockTestResult {
        self.lock_test_with_identity(arguments, file, principal).await.result
    }

    /// Performs only the authenticated, in-memory preflight for
    /// RELEASE_LOCKOWNER.  The returned identity represents a valid clientid
    /// even when the owner subsequently fails with LOCKS_HELD.
    pub(crate) async fn prepare_release_lock_owner(
        &self,
        owner: &LockOwner,
        principal: &Principal,
    ) -> ReleaseLockOwnerDecision {
        let _transition_guard = self.client_state_transition_guard().await;
        if owner.owner.len() > self.core.limits.max_client_owner_size {
            return ReleaseLockOwnerDecision::Error {
                status: NfsStatus::Resource,
                client_id: None,
            };
        }
        if let Err(error) = self.touch_client_authenticated(owner.client_id, principal).await {
            return ReleaseLockOwnerDecision::Error {
                status: error.status,
                client_id: error.client_id,
            };
        }
        let key = LockOwnerKey::from(owner);
        for shard in &self.core.files {
            let shard = shard.lock().expect("NFSv4 file shard poisoned");
            if shard
                .files
                .values()
                .any(|file| file.locks.records().iter().any(|record| record.owner.owner == key))
            {
                return ReleaseLockOwnerDecision::Error {
                    status: NfsStatus::LocksHeld,
                    client_id: Some(owner.client_id),
                };
            }
        }
        ReleaseLockOwnerDecision::Execute {
            client_id: owner.client_id,
        }
    }

    /// Persists and retires a lock owner after its clientid has already been
    /// authenticated and delegation leases renewed.  This may await stable
    /// storage, so callers must not retain global delegation-renewal fences.
    pub(crate) async fn release_lock_owner_after_auth(&self, owner: &LockOwner) -> NfsStatus {
        let _transition_guard = self.client_state_transition_guard().await;
        let key = LockOwnerKey::from(owner);
        for shard in &self.core.files {
            let shard = shard.lock().expect("NFSv4 file shard poisoned");
            if shard
                .files
                .values()
                .any(|file| file.locks.records().iter().any(|record| record.owner.owner == key))
            {
                return NfsStatus::LocksHeld;
            }
        }
        let batch = PersistBatch::default().delete(JournalKey::Replay {
            client_id: key.client_id,
            owner_kind: ReplayOwnerKind::Lock,
            owner: Bytes::copy_from_slice(&key.owner),
        });
        if self.persist_if_needed(batch).await.is_err() {
            return NfsStatus::Resource;
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let retired = state
            .lock_by_state
            .iter()
            .filter_map(|((candidate, file), state_id)| {
                (candidate.owner == key).then_some(((candidate.clone(), *file), *state_id))
            })
            .collect::<Vec<_>>();
        for (map_key, state_id) in retired {
            state.lock_by_state.remove(&map_key);
            if state.stateids.set_disposition(state_id, StateDisposition::Closed).is_err() {
                return NfsStatus::ServerFault;
            }
        }
        state.lock_owners.remove(&key);
        NfsStatus::Ok
    }

    #[cfg(test)]
    pub(crate) async fn release_lock_owner(&self, owner: &LockOwner, principal: &Principal) -> NfsStatus {
        match self.prepare_release_lock_owner(owner, principal).await {
            ReleaseLockOwnerDecision::Execute { .. } => self.release_lock_owner_after_auth(owner).await,
            ReleaseLockOwnerDecision::Error { status, .. } => status,
        }
    }

    /// Validates an ordinary runtime stateid without touching the client
    /// lease.  Owner-seqid precedence can therefore select BAD_SEQID first
    /// while still withholding the renewal identity for an old, future,
    /// special, wrong-file, or wrong-kind stateid.
    fn validate_runtime_stateid_client(
        &self,
        state_id: StateId,
        file: RuntimeFile,
        kind: StateKind,
    ) -> Result<u64, NfsStatus> {
        let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        match state.stateids.validate(state_id, &file, &[kind]) {
            Ok(StateIdValidation::Active(record)) => Ok(record.client),
            Ok(StateIdValidation::Anonymous | StateIdValidation::ReadBypass) => Err(NfsStatus::BadStateId),
            Err(error) => Err(map_stateid_error(error)),
        }
    }

    /// Performs the owner-sequence portion of LOCK before validating the
    /// supplied stateid's sequence.  RFC 7530 sections 9.1.7 through 9.1.9
    /// require this ordering: a retransmission can carry the old stateid
    /// returned by the first request, and BAD_SEQID takes precedence over a
    /// later OLD_STATEID/BAD_STATEID determination.
    pub(crate) async fn preflight_lock(
        &self,
        arguments: &LockArgs,
        _file: RuntimeFile,
        digest: OwnerRequestDigest,
        principal: &Principal,
    ) -> LockPreflight {
        if LockRange::from_offset_length(arguments.offset, arguments.length).is_err() {
            return LockPreflight::Error {
                status: NfsStatus::Invalid,
                client_id: None,
            };
        }
        let (client_id, sequence, state_id, state_kind) = match &arguments.locker {
            Locker::New(locker) => {
                if locker.lock_owner.owner.len() > self.core.limits.max_client_owner_size {
                    return LockPreflight::Error {
                        status: NfsStatus::Resource,
                        client_id: None,
                    };
                }
                let (open_key, client_id) = {
                    let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
                    let record = match state.stateids.identify(locker.open_state_id) {
                        Ok(record) => record,
                        Err(error) => {
                            return LockPreflight::Error {
                                status: map_stateid_error(error),
                                client_id: None,
                            }
                        },
                    };
                    let StatePayload::Open(open) = &record.payload else {
                        return LockPreflight::Error {
                            status: NfsStatus::BadStateId,
                            client_id: None,
                        };
                    };
                    (open.owner.clone(), record.client)
                };
                if locker.lock_owner.client_id != client_id || open_key.client_id != client_id {
                    return LockPreflight::Error {
                        status: NfsStatus::BadStateId,
                        client_id: None,
                    };
                }
                let lock_key = LockOwnerKey::from(&locker.lock_owner);
                let sequence = {
                    let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
                    let Some(open_owner) = state.open_owners.get(&open_key) else {
                        return LockPreflight::Error {
                            status: NfsStatus::BadStateId,
                            client_id: None,
                        };
                    };
                    let open_decision = open_owner.sequence.decide(locker.open_sequence_id, digest);
                    let lock_decision = state
                        .lock_owners
                        .get(&lock_key)
                        .map(|owner| owner.sequence.decide(locker.lock_sequence_id, digest));
                    if matches!(&open_decision, SequenceDecision::BadSequence)
                        || matches!(lock_decision.as_ref(), Some(SequenceDecision::BadSequence))
                    {
                        Err(NfsStatus::BadSequenceId)
                    } else if matches!(&open_decision, SequenceDecision::InProgress)
                        || matches!(lock_decision.as_ref(), Some(SequenceDecision::InProgress))
                    {
                        Err(NfsStatus::Delay)
                    } else if let Some(result) = replayed_lock_result(&open_decision)
                        .or_else(|| lock_decision.as_ref().and_then(replayed_lock_result))
                    {
                        Ok(Some(ResOp::Lock(result)))
                    } else {
                        Ok(None)
                    }
                };
                (client_id, sequence, locker.open_state_id, StateKind::Open)
            },
            Locker::Existing(locker) => {
                let (lock_key, client_id) = {
                    let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
                    let record = match state.stateids.identify(locker.lock_state_id) {
                        Ok(record) => record,
                        Err(error) => {
                            return LockPreflight::Error {
                                status: map_stateid_error(error),
                                client_id: None,
                            }
                        },
                    };
                    let StatePayload::Lock(lock) = &record.payload else {
                        return LockPreflight::Error {
                            status: NfsStatus::BadStateId,
                            client_id: None,
                        };
                    };
                    (lock.owner.clone(), record.client)
                };
                let sequence = {
                    let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
                    let Some(owner) = state.lock_owners.get(&lock_key) else {
                        return LockPreflight::Error {
                            status: NfsStatus::BadStateId,
                            client_id: None,
                        };
                    };
                    match owner.sequence.decide(locker.lock_sequence_id, digest) {
                        SequenceDecision::Replay { result, .. } => Ok(Some(result)),
                        SequenceDecision::InProgress => Err(NfsStatus::Delay),
                        SequenceDecision::BadSequence => Err(NfsStatus::BadSequenceId),
                        SequenceDecision::Execute => Ok(None),
                    }
                };
                (client_id, sequence, locker.lock_state_id, StateKind::ByteRangeLock)
            },
        };
        if let Ok(Some(result)) = &sequence {
            if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
                return LockPreflight::Error {
                    status: error.status,
                    client_id: error.client_id,
                };
            }
            return LockPreflight::Replay {
                client_id,
                result: result.clone(),
            };
        }

        // Sequence precedence decides the returned status, but not whether a
        // lease may be renewed.  An opaque stateid match is insufficient:
        // RFC 7530 §9.5 requires a valid non-special stateid.  Exact replay
        // above is the deliberate exception because its cached owner result
        // authenticates the original request even when the reply advanced the
        // stateid sequence.
        let validated_client = match self.validate_runtime_stateid_client(state_id, _file, state_kind) {
            Ok(validated_client) if validated_client == client_id => validated_client,
            Ok(_) => {
                return LockPreflight::Error {
                    status: sequence.as_ref().err().copied().unwrap_or(NfsStatus::BadStateId),
                    client_id: None,
                }
            },
            Err(state_status) => {
                return LockPreflight::Error {
                    status: sequence.as_ref().err().copied().unwrap_or(state_status),
                    client_id: None,
                }
            },
        };
        if let Err(error) = self.touch_client_authenticated(validated_client, principal).await {
            return LockPreflight::Error {
                status: error.status,
                client_id: error.client_id,
            };
        }
        match sequence {
            Ok(Some(_)) => unreachable!("exact replay returned before stateid validation"),
            Ok(None) => LockPreflight::Execute {
                client_id: validated_client,
            },
            Err(status) => LockPreflight::Error {
                status,
                client_id: Some(validated_client),
            },
        }
    }

    /// Performs LOCKU owner sequencing with the same stateid-sequence
    /// priority as [`Self::preflight_lock`].
    pub(crate) async fn preflight_unlock(
        &self,
        arguments: &LockUnlockArgs,
        _file: RuntimeFile,
        digest: OwnerRequestDigest,
        principal: &Principal,
    ) -> LockPreflight {
        if LockRange::from_offset_length(arguments.offset, arguments.length).is_err() {
            return LockPreflight::Error {
                status: NfsStatus::Invalid,
                client_id: None,
            };
        }
        let (lock_key, client_id) = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = match state.stateids.identify(arguments.lock_state_id) {
                Ok(record) => record,
                Err(error) => {
                    return LockPreflight::Error {
                        status: map_stateid_error(error),
                        client_id: None,
                    }
                },
            };
            let StatePayload::Lock(lock) = &record.payload else {
                return LockPreflight::Error {
                    status: NfsStatus::BadStateId,
                    client_id: None,
                };
            };
            (lock.owner.clone(), record.client)
        };
        let sequence = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let Some(owner) = state.lock_owners.get(&lock_key) else {
                return LockPreflight::Error {
                    status: NfsStatus::BadStateId,
                    client_id: None,
                };
            };
            match owner.sequence.decide(arguments.sequence_id, digest) {
                SequenceDecision::Replay { result, .. } => Ok(Some(result)),
                SequenceDecision::InProgress => Err(NfsStatus::Delay),
                SequenceDecision::BadSequence => Err(NfsStatus::BadSequenceId),
                SequenceDecision::Execute => Ok(None),
            }
        };
        if let Ok(Some(result)) = &sequence {
            if let Err(error) = self.touch_client_authenticated(client_id, principal).await {
                return LockPreflight::Error {
                    status: error.status,
                    client_id: error.client_id,
                };
            }
            return LockPreflight::Replay {
                client_id,
                result: result.clone(),
            };
        }
        let validated_client =
            match self.validate_runtime_stateid_client(arguments.lock_state_id, _file, StateKind::ByteRangeLock) {
                Ok(validated_client) if validated_client == client_id => validated_client,
                Ok(_) => {
                    return LockPreflight::Error {
                        status: sequence.as_ref().err().copied().unwrap_or(NfsStatus::BadStateId),
                        client_id: None,
                    }
                },
                Err(state_status) => {
                    return LockPreflight::Error {
                        status: sequence.as_ref().err().copied().unwrap_or(state_status),
                        client_id: None,
                    }
                },
            };
        if let Err(error) = self.touch_client_authenticated(validated_client, principal).await {
            return LockPreflight::Error {
                status: error.status,
                client_id: error.client_id,
            };
        }
        match sequence {
            Ok(Some(_)) => unreachable!("exact replay returned before stateid validation"),
            Ok(None) => LockPreflight::Execute {
                client_id: validated_client,
            },
            Err(status) => LockPreflight::Error {
                status,
                client_id: Some(validated_client),
            },
        }
    }

    #[cfg(test)]
    pub(crate) async fn lock(
        &self,
        arguments: &LockArgs,
        file: RuntimeFile,
        digest: OwnerRequestDigest,
        principal: &Principal,
    ) -> LockResult {
        self.lock_with_optional_delegation_access(arguments, file, digest, principal, None)
            .await
    }

    /// Completes LOCK while retaining an access reservation acquired before
    /// delegation recall.  This prevents a conflicting delegation candidate
    /// from being admitted between recall and the state mutation.
    pub(crate) async fn lock_with_delegation_access(
        &self,
        arguments: &LockArgs,
        file: RuntimeFile,
        digest: OwnerRequestDigest,
        principal: &Principal,
        delegation_access: DelegationAccessReservation,
    ) -> LockResult {
        self.lock_with_optional_delegation_access(arguments, file, digest, principal, Some(delegation_access))
            .await
    }

    async fn lock_with_optional_delegation_access(
        &self,
        arguments: &LockArgs,
        file: RuntimeFile,
        digest: OwnerRequestDigest,
        principal: &Principal,
        delegation_access: Option<DelegationAccessReservation>,
    ) -> LockResult {
        let _transition_guard = self.client_state_transition_guard().await;
        let range = match LockRange::from_offset_length(arguments.offset, arguments.length) {
            Ok(range) => range,
            Err(_) => return LockResult::Err(NfsStatus::Invalid),
        };
        match &arguments.locker {
            Locker::New(locker) => {
                self.lock_new(
                    arguments.lock_type,
                    arguments.reclaim,
                    range,
                    file,
                    locker,
                    digest,
                    principal,
                    delegation_access.as_ref(),
                )
                .await
            },
            Locker::Existing(locker) => {
                self.lock_existing(
                    arguments.lock_type,
                    arguments.reclaim,
                    range,
                    file,
                    *locker,
                    digest,
                    principal,
                    delegation_access.as_ref(),
                )
                .await
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_new(
        &self,
        lock_type: LockType,
        reclaim: bool,
        range: LockRange,
        file: RuntimeFile,
        locker: &OpenToLockOwner,
        digest: OwnerRequestDigest,
        principal: &Principal,
        delegation_access: Option<&DelegationAccessReservation>,
    ) -> LockResult {
        if locker.lock_owner.owner.len() > self.core.limits.max_client_owner_size {
            return LockResult::Err(NfsStatus::Resource);
        }
        let (open_key, client_id, open_access, open_confirmed) = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = match state.stateids.identify(locker.open_state_id) {
                Ok(record) => record,
                Err(error) => return LockResult::Err(map_stateid_error(error)),
            };
            let StatePayload::Open(open) = &record.payload else {
                return LockResult::Err(NfsStatus::BadStateId);
            };
            (open.owner.clone(), record.client, open.access, open.confirmed)
        };
        if locker.lock_owner.client_id != client_id {
            return match self.touch_client(locker.lock_owner.client_id, principal).await {
                Err(status) => LockResult::Err(status),
                Ok(()) => LockResult::Err(NfsStatus::BadStateId),
            };
        }
        if open_key.client_id != client_id {
            return LockResult::Err(NfsStatus::BadStateId);
        }
        let reclaim_previous_ids = match self.gate_state_client(client_id, principal, reclaim).await {
            Ok(previous_ids) => previous_ids,
            Err(status) => return LockResult::Err(status),
        };
        let _owned_delegation_access = if let Some(reservation) = delegation_access {
            if !self.delegation_access_matches(
                reservation,
                file,
                Some(client_id),
                delegation_kind_for_lock(lock_type),
                false,
            ) {
                return LockResult::Err(NfsStatus::ServerFault);
            }
            None
        } else {
            match self.begin_delegation_access(file, Some(client_id), delegation_kind_for_lock(lock_type), false) {
                Ok(reservation) => Some(reservation),
                Err(status) => return LockResult::Err(status),
            }
        };
        let _gate = self.operation_gate(file).await;
        let lock_key = LockOwnerKey::from(&locker.lock_owner);
        let lock_state_owner = LockStateOwner::new(lock_key.clone(), locker.open_state_id.other);
        let shard_index = shard_for(&file, self.core.files.len());
        let prepared = {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let created_lock_owner = !state.lock_owners.contains_key(&lock_key);
            if created_lock_owner {
                let count = state.lock_owners.keys().filter(|owner| owner.client_id == client_id).count();
                if count >= self.core.limits.max_lock_owners_per_client {
                    return LockResult::Err(NfsStatus::Resource);
                }
                state.lock_owners.insert(
                    lock_key.clone(),
                    LockOwnerState {
                        sequence: OwnerSequence::new(locker.lock_sequence_id),
                        active_states: 0,
                    },
                );
            }
            let open_decision = match state.open_owners.get(&open_key) {
                Some(owner) => owner.sequence.decide(locker.open_sequence_id, digest),
                None => return LockResult::Err(NfsStatus::BadStateId),
            };
            let lock_decision = state
                .lock_owners
                .get(&lock_key)
                .expect("lock owner exists")
                .sequence
                .decide(locker.lock_sequence_id, digest);
            if matches!(open_decision, SequenceDecision::BadSequence)
                || matches!(lock_decision, SequenceDecision::BadSequence)
            {
                return LockResult::Err(NfsStatus::BadSequenceId);
            }
            if matches!(open_decision, SequenceDecision::InProgress)
                || matches!(lock_decision, SequenceDecision::InProgress)
            {
                return LockResult::Err(NfsStatus::Delay);
            }
            if let Some(result) = replayed_lock_result(&open_decision).or_else(|| replayed_lock_result(&lock_decision))
            {
                return result;
            }
            if !matches!(open_decision, SequenceDecision::Execute)
                || !matches!(lock_decision, SequenceDecision::Execute)
            {
                return LockResult::Err(NfsStatus::BadSequenceId);
            }
            let _ = state
                .open_owners
                .get_mut(&open_key)
                .expect("open owner exists")
                .sequence
                .reserve(locker.open_sequence_id, digest);
            let _ = state
                .lock_owners
                .get_mut(&lock_key)
                .expect("lock owner exists")
                .sequence
                .reserve(locker.lock_sequence_id, digest);
            let open_reservation = OwnerReservation {
                core: Arc::downgrade(&self.core),
                kind: ReservedOwnerKind::Open,
                client_id,
                owner: open_key.owner.clone(),
                sequence_id: locker.open_sequence_id,
                digest,
                reserved_state: false,
                created_owner: false,
                committed: false,
            };
            let mut lock_reservation = OwnerReservation {
                core: Arc::downgrade(&self.core),
                kind: ReservedOwnerKind::Lock,
                client_id,
                owner: lock_key.owner.clone(),
                sequence_id: locker.lock_sequence_id,
                digest,
                reserved_state: false,
                created_owner: created_lock_owner,
                committed: false,
            };
            if let Err(error) = state.stateids.validate(locker.open_state_id, &file, &[StateKind::Open]) {
                drop(state);
                return LockResult::Err(map_stateid_error(error));
            }
            if !open_confirmed {
                drop(state);
                return LockResult::Err(NfsStatus::BadStateId);
            }
            if state.lock_by_state.contains_key(&(lock_state_owner.clone(), file)) {
                drop(state);
                // RFC 7530 section 16.10 requires BAD_SEQID when a
                // client presents the new-lock-owner arm after state has
                // already been established for this lock-owner and open
                // file. Exact retransmissions were handled by the owner
                // replay decisions above.
                return LockResult::Err(NfsStatus::BadSequenceId);
            }
            let recovered_lock = if reclaim {
                state
                    .reclaimed_open_ancestry
                    .get(&locker.open_state_id.other)
                    .and_then(|previous_open_other| {
                        state.recovered_locks.values().find(|recovered| {
                            reclaim_previous_ids.contains(&recovered.previous_client_id)
                                && state_other(recovered.previous_open_state_token) == *previous_open_other
                                && recovered.owner == lock_key.owner
                                && recovered.file == file
                                && recovered.ranges.contains(&RecoveredLockRange {
                                    access: lock_access(lock_type),
                                    range,
                                })
                        })
                    })
                    .cloned()
            } else {
                None
            };
            if reclaim && recovered_lock.is_none() {
                Err((open_reservation, lock_reservation, LockResult::Err(NfsStatus::ReclaimBad)))
            } else {
                let requested_access = match lock_access(lock_type) {
                    LockAccess::Read => ShareAccess::READ,
                    LockAccess::Write => ShareAccess::WRITE,
                };
                let planned_locks = if open_access.bits() & requested_access.bits() == 0 {
                    Err(LockResult::Err(NfsStatus::OpenMode))
                } else {
                    let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
                    let mut locks = shard.files.get(&file).map(|state| state.locks.clone()).unwrap_or_default();
                    match locks.lock(
                        lock_state_owner.clone(),
                        locker.open_state_id.other,
                        lock_access(lock_type),
                        range,
                    ) {
                        Err(conflict) => Err(LockResult::Denied(denied(&conflict))),
                        Ok(())
                            if stable_lock_ranges(&locks, &lock_state_owner).len()
                                > self.core.limits.max_lock_ranges_per_state =>
                        {
                            Err(LockResult::Err(NfsStatus::Resource))
                        },
                        Ok(()) => Ok(locks),
                    }
                };
                match planned_locks {
                    Err(result) => Err((open_reservation, lock_reservation, result)),
                    Ok(planned_locks) => {
                        if state
                            .stateids
                            .len()
                            .saturating_add(state.reserved_states)
                            .saturating_add(state.pending_pin_releases.len())
                            >= state.stateids.capacity()
                        {
                            drop(state);
                            return LockResult::Err(NfsStatus::Resource);
                        }
                        state.reserved_states += 1;
                        lock_reservation.reserved_state = true;
                        let lock_state_id = match state.stateids.allocate_pending(
                            client_id,
                            file,
                            StateKind::ByteRangeLock,
                            StatePayload::Lock(ByteRangeLockState {
                                owner: lock_key.clone(),
                                open_state_id: locker.open_state_id,
                            }),
                        ) {
                            Ok(state_id) => state_id,
                            Err(_) => {
                                drop(state);
                                return LockResult::Err(NfsStatus::Resource);
                            },
                        };
                        let result = LockResult::Ok(lock_state_id);
                        let response = ResOp::Lock(result.clone());
                        let reply = match encode_replay(&response) {
                            Ok(reply) => reply,
                            Err(status) => {
                                let _ = state.stateids.set_disposition(lock_state_id, StateDisposition::Closed);
                                drop(state);
                                return LockResult::Err(status);
                            },
                        };
                        let mut batch = PersistBatch::default().put(
                            JournalKey::Lock {
                                state_token: state_token(lock_state_id),
                            },
                            JournalRecord::Lock(StableLockRecord {
                                state_token: state_token(lock_state_id),
                                open_state_token: state_token(locker.open_state_id),
                                client_id,
                                owner: Bytes::copy_from_slice(&lock_key.owner),
                                object: file.stable(),
                                ranges: stable_lock_ranges(&planned_locks, &lock_state_owner),
                            }),
                        );
                        let recovered_remainder = recovered_lock.as_ref().and_then(|recovered| {
                            recovered_lock_remainder(
                                recovered,
                                RecoveredLockRange {
                                    access: lock_access(lock_type),
                                    range,
                                },
                            )
                        });
                        if let Some(recovered) = &recovered_lock {
                            let recovered_key = JournalKey::Lock {
                                state_token: recovered.state_token,
                            };
                            batch = batch.delete(recovered_key.clone());
                            if let Some(remaining) = &recovered_remainder {
                                batch = batch.put(recovered_key, JournalRecord::Lock(stable_recovered_lock(remaining)));
                            }
                            batch = batch.delete(JournalKey::Replay {
                                client_id: recovered.previous_client_id,
                                owner_kind: ReplayOwnerKind::Lock,
                                owner: Bytes::copy_from_slice(&recovered.owner),
                            });
                        }
                        for reservation in [&open_reservation, &lock_reservation] {
                            batch = batch.put(
                                replay_key(reservation),
                                JournalRecord::Replay(replay_record(
                                    reservation,
                                    &response,
                                    ReplayEffect::default(),
                                    reply.clone(),
                                )),
                            );
                        }
                        Ok((
                            open_reservation,
                            lock_reservation,
                            lock_state_id,
                            result,
                            response,
                            batch,
                            planned_locks,
                            recovered_lock,
                            recovered_remainder,
                        ))
                    },
                }
            }
        };
        let (
            mut open_reservation,
            mut lock_reservation,
            lock_state_id,
            result,
            response,
            batch,
            planned_locks,
            recovered_lock,
            recovered_remainder,
        ) = match prepared {
            Ok(prepared) => prepared,
            Err((open_reservation, lock_reservation, result)) => {
                let mut reservations = [open_reservation, lock_reservation];
                return self.commit_lock_error(&mut reservations, result).await;
            },
        };
        if self.persist_if_needed(batch).await.is_err() {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let _ = state.stateids.set_disposition(lock_state_id, StateDisposition::Closed);
            return LockResult::Err(NfsStatus::Resource);
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        shard.files.entry(file).or_default().locks = planned_locks;
        if state.stateids.activate(lock_state_id).is_err() {
            return LockResult::Err(NfsStatus::ServerFault);
        }
        state.lock_by_state.insert((lock_state_owner, file), lock_state_id);
        state.lock_owners.get_mut(&lock_key).expect("lock owner exists").active_states += 1;
        if let Some(recovered) = recovered_lock {
            if let Some(remaining) = recovered_remainder {
                state.recovered_locks.insert(recovered.state_token, remaining);
            } else {
                state.recovered_locks.remove(&recovered.state_token);
                state.recovered_cleanup_keys.remove(&JournalKey::Lock {
                    state_token: recovered.state_token,
                });
            }
            let replay_key = (recovered.previous_client_id, ReplayOwnerKind::Lock, recovered.owner.clone());
            state.recovered_replays.remove(&replay_key);
            state.recovered_cleanup_keys.remove(&JournalKey::Replay {
                client_id: recovered.previous_client_id,
                owner_kind: ReplayOwnerKind::Lock,
                owner: Bytes::copy_from_slice(&recovered.owner),
            });
        }
        commit_reserved_owner(&mut state, &mut open_reservation, response.clone(), ReplayEffect::default())
            .expect("open owner reservation remains valid");
        commit_reserved_owner(&mut state, &mut lock_reservation, response, ReplayEffect::default())
            .expect("lock owner reservation remains valid");
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_existing(
        &self,
        lock_type: LockType,
        reclaim: bool,
        range: LockRange,
        file: RuntimeFile,
        locker: ExistingLockOwner,
        digest: OwnerRequestDigest,
        principal: &Principal,
        delegation_access: Option<&DelegationAccessReservation>,
    ) -> LockResult {
        let (lock_key, client_id, open_state_id) = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = match state.stateids.identify(locker.lock_state_id) {
                Ok(record) => record,
                Err(error) => return LockResult::Err(map_stateid_error(error)),
            };
            let StatePayload::Lock(lock) = &record.payload else {
                return LockResult::Err(NfsStatus::BadStateId);
            };
            (lock.owner.clone(), record.client, lock.open_state_id)
        };
        let reclaim_previous_ids = match self.gate_state_client(client_id, principal, reclaim).await {
            Ok(previous_ids) => previous_ids,
            Err(status) => return LockResult::Err(status),
        };
        let _owned_delegation_access = if let Some(reservation) = delegation_access {
            if !self.delegation_access_matches(
                reservation,
                file,
                Some(client_id),
                delegation_kind_for_lock(lock_type),
                false,
            ) {
                return LockResult::Err(NfsStatus::ServerFault);
            }
            None
        } else {
            match self.begin_delegation_access(file, Some(client_id), delegation_kind_for_lock(lock_type), false) {
                Ok(reservation) => Some(reservation),
                Err(status) => return LockResult::Err(status),
            }
        };
        let _gate = self.operation_gate(file).await;
        let lock_state_owner = LockStateOwner::new(lock_key.clone(), open_state_id.other);
        let shard_index = shard_for(&file, self.core.files.len());
        let prepared = {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let decision = match state.lock_owners.get_mut(&lock_key) {
                Some(owner) => owner.sequence.reserve(locker.lock_sequence_id, digest),
                None => return LockResult::Err(NfsStatus::BadStateId),
            };
            match decision {
                SequenceDecision::Replay { result, .. } => {
                    return match result {
                        ResOp::Lock(result) => result,
                        _ => LockResult::Err(NfsStatus::BadSequenceId),
                    }
                },
                SequenceDecision::InProgress => return LockResult::Err(NfsStatus::Delay),
                SequenceDecision::BadSequence => return LockResult::Err(NfsStatus::BadSequenceId),
                SequenceDecision::Execute => {},
            }
            let reservation = OwnerReservation {
                core: Arc::downgrade(&self.core),
                kind: ReservedOwnerKind::Lock,
                client_id,
                owner: lock_key.owner.clone(),
                sequence_id: locker.lock_sequence_id,
                digest,
                reserved_state: false,
                created_owner: false,
                committed: false,
            };
            if let Err(error) = state
                .stateids
                .validate(locker.lock_state_id, &file, &[StateKind::ByteRangeLock])
            {
                drop(state);
                return LockResult::Err(map_stateid_error(error));
            }
            // `open_state_id` is an internal association captured when the
            // lock state was created. OPEN upgrades and downgrades advance
            // the OPEN stateid sequence while preserving its 12-byte state
            // object identity, so resolving this link must not validate the
            // stale sequence snapshot. The client-supplied lock stateid was
            // validated exactly above.
            let (open_access, open_confirmed) = match state.stateids.identify(open_state_id) {
                Ok(record) if record.file == file && record.client == client_id && record.kind == StateKind::Open => {
                    match &record.payload {
                        StatePayload::Open(open) => (open.access, open.confirmed),
                        StatePayload::Lock(_) => {
                            drop(state);
                            return LockResult::Err(NfsStatus::BadStateId);
                        },
                    }
                },
                Ok(_) => {
                    drop(state);
                    return LockResult::Err(NfsStatus::BadStateId);
                },
                Err(error) => {
                    drop(state);
                    return LockResult::Err(map_stateid_error(error));
                },
            };
            if !open_confirmed {
                drop(state);
                return LockResult::Err(NfsStatus::BadStateId);
            }
            let requested_access = match lock_access(lock_type) {
                LockAccess::Read => ShareAccess::READ,
                LockAccess::Write => ShareAccess::WRITE,
            };
            let planned_locks = if open_access.bits() & requested_access.bits() == 0 {
                Err(LockResult::Err(NfsStatus::OpenMode))
            } else {
                let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
                let mut locks = shard.files.get(&file).map(|state| state.locks.clone()).unwrap_or_default();
                match locks.lock(lock_state_owner.clone(), open_state_id.other, lock_access(lock_type), range) {
                    Err(conflict) => Err(LockResult::Denied(denied(&conflict))),
                    Ok(())
                        if stable_lock_ranges(&locks, &lock_state_owner).len()
                            > self.core.limits.max_lock_ranges_per_state =>
                    {
                        Err(LockResult::Err(NfsStatus::Resource))
                    },
                    Ok(()) => Ok(locks),
                }
            };
            match planned_locks {
                Err(result) => Err((reservation, result)),
                Ok(planned_locks) => {
                    let recovered_lock = if reclaim {
                        let Some(previous_open_state_token) =
                            state.reclaimed_open_ancestry.get(&open_state_id.other).copied()
                        else {
                            drop(state);
                            return LockResult::Err(NfsStatus::ReclaimBad);
                        };
                        let candidate = state.recovered_locks.values().find(|recovered| {
                            reclaim_previous_ids.contains(&recovered.previous_client_id)
                                && state_other(recovered.previous_open_state_token) == previous_open_state_token
                                && recovered.owner == lock_key.owner
                                && recovered.file == file
                                && recovered.ranges.contains(&RecoveredLockRange {
                                    access: lock_access(lock_type),
                                    range,
                                })
                        });
                        let Some(candidate) = candidate.cloned() else {
                            drop(state);
                            return LockResult::Err(NfsStatus::ReclaimBad);
                        };
                        Some(candidate)
                    } else {
                        None
                    };
                    let next = match state.stateids.preview_transition(locker.lock_state_id) {
                        Ok(next) => next,
                        Err(error) => {
                            drop(state);
                            return LockResult::Err(map_stateid_error(error));
                        },
                    };
                    let result = LockResult::Ok(next);
                    let response = ResOp::Lock(result.clone());
                    let reply = match encode_replay(&response) {
                        Ok(reply) => reply,
                        Err(status) => {
                            drop(state);
                            return LockResult::Err(status);
                        },
                    };
                    let mut batch = PersistBatch::default()
                        .delete(JournalKey::Lock {
                            state_token: state_token(locker.lock_state_id),
                        })
                        .put(
                            JournalKey::Lock {
                                state_token: state_token(next),
                            },
                            JournalRecord::Lock(StableLockRecord {
                                state_token: state_token(next),
                                open_state_token: state_token(open_state_id),
                                client_id,
                                owner: Bytes::copy_from_slice(&lock_key.owner),
                                object: file.stable(),
                                ranges: stable_lock_ranges(&planned_locks, &lock_state_owner),
                            }),
                        )
                        .put(
                            replay_key(&reservation),
                            JournalRecord::Replay(replay_record(
                                &reservation,
                                &response,
                                ReplayEffect::default(),
                                reply,
                            )),
                        );
                    let recovered_remainder = recovered_lock.as_ref().and_then(|recovered| {
                        recovered_lock_remainder(
                            recovered,
                            RecoveredLockRange {
                                access: lock_access(lock_type),
                                range,
                            },
                        )
                    });
                    if let Some(recovered) = &recovered_lock {
                        let recovered_key = JournalKey::Lock {
                            state_token: recovered.state_token,
                        };
                        batch = batch.delete(recovered_key.clone());
                        if let Some(remaining) = &recovered_remainder {
                            batch = batch.put(recovered_key, JournalRecord::Lock(stable_recovered_lock(remaining)));
                        }
                        batch = batch.delete(JournalKey::Replay {
                            client_id: recovered.previous_client_id,
                            owner_kind: ReplayOwnerKind::Lock,
                            owner: Bytes::copy_from_slice(&recovered.owner),
                        });
                    }
                    Ok((reservation, next, result, response, batch, planned_locks, recovered_lock, recovered_remainder))
                },
            }
        };
        let (mut reservation, next, result, response, batch, planned_locks, recovered_lock, recovered_remainder) =
            match prepared {
                Ok(prepared) => prepared,
                Err((mut reservation, result)) => {
                    return self.commit_lock_error(std::slice::from_mut(&mut reservation), result).await;
                },
            };
        if self.persist_if_needed(batch).await.is_err() {
            return LockResult::Err(NfsStatus::Resource);
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        shard.files.entry(file).or_default().locks = planned_locks;
        let transitioned = match state.stateids.transition(locker.lock_state_id) {
            Ok(state_id) => state_id,
            Err(error) => return LockResult::Err(map_stateid_error(error)),
        };
        if transitioned != next {
            return LockResult::Err(NfsStatus::ServerFault);
        }
        state.lock_by_state.insert((lock_state_owner, file), next);
        if let Some(recovered) = recovered_lock {
            if let Some(remaining) = recovered_remainder {
                state.recovered_locks.insert(recovered.state_token, remaining);
            } else {
                state.recovered_locks.remove(&recovered.state_token);
                state.recovered_cleanup_keys.remove(&JournalKey::Lock {
                    state_token: recovered.state_token,
                });
            }
            let replay_key = (recovered.previous_client_id, ReplayOwnerKind::Lock, recovered.owner.clone());
            state.recovered_replays.remove(&replay_key);
            state.recovered_cleanup_keys.remove(&JournalKey::Replay {
                client_id: recovered.previous_client_id,
                owner_kind: ReplayOwnerKind::Lock,
                owner: Bytes::copy_from_slice(&recovered.owner),
            });
        }
        if commit_reserved_owner(&mut state, &mut reservation, response, ReplayEffect::default()).is_err() {
            return LockResult::Err(NfsStatus::ServerFault);
        }
        result
    }

    async fn commit_lock_error(&self, reservations: &mut [OwnerReservation], result: LockResult) -> LockResult {
        let status = result.status();
        if !sequence_status_consumed(status) {
            return result;
        }
        let response = ResOp::Lock(result.clone());
        let reply = match encode_replay(&response) {
            Ok(reply) => reply,
            Err(_) => return LockResult::Err(NfsStatus::Resource),
        };
        let mut batch = PersistBatch::default();
        for reservation in reservations.iter() {
            batch = batch.put(
                replay_key(reservation),
                JournalRecord::Replay(replay_record(reservation, &response, ReplayEffect::default(), reply.clone())),
            );
        }
        if self.persist_if_needed(batch).await.is_err() {
            return LockResult::Err(NfsStatus::Resource);
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        for reservation in reservations {
            if commit_reserved_owner(&mut state, reservation, response.clone(), ReplayEffect::default()).is_err() {
                return LockResult::Err(NfsStatus::ServerFault);
            }
        }
        result
    }

    pub(crate) async fn unlock(
        &self,
        arguments: &LockUnlockArgs,
        file: RuntimeFile,
        digest: OwnerRequestDigest,
        principal: &Principal,
    ) -> ResOp {
        let _transition_guard = self.client_state_transition_guard().await;
        let range = match LockRange::from_offset_length(arguments.offset, arguments.length) {
            Ok(range) => range,
            Err(_) => return ResOp::LockUnlock(NfsResult::Err(NfsStatus::Invalid)),
        };
        let (lock_key, client_id, open_state_id) = {
            let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let record = match state.stateids.identify(arguments.lock_state_id) {
                Ok(record) => record,
                Err(error) => return ResOp::LockUnlock(NfsResult::Err(map_stateid_error(error))),
            };
            let StatePayload::Lock(lock) = &record.payload else {
                return ResOp::LockUnlock(NfsResult::Err(NfsStatus::BadStateId));
            };
            (lock.owner.clone(), record.client, lock.open_state_id)
        };
        if let Err(status) = self.touch_client(client_id, principal).await {
            return ResOp::LockUnlock(NfsResult::Err(status));
        }
        let _gate = self.operation_gate(file).await;
        let lock_state_owner = LockStateOwner::new(lock_key.clone(), open_state_id.other);
        let shard_index = shard_for(&file, self.core.files.len());
        let prepared = {
            let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
            let decision = match state.lock_owners.get_mut(&lock_key) {
                Some(owner) => owner.sequence.reserve(arguments.sequence_id, digest),
                None => return ResOp::LockUnlock(NfsResult::Err(NfsStatus::BadStateId)),
            };
            match decision {
                SequenceDecision::Replay { result, .. } => return result,
                SequenceDecision::InProgress => return ResOp::LockUnlock(NfsResult::Err(NfsStatus::Delay)),
                SequenceDecision::BadSequence => return ResOp::LockUnlock(NfsResult::Err(NfsStatus::BadSequenceId)),
                SequenceDecision::Execute => {},
            }
            let reservation = OwnerReservation {
                core: Arc::downgrade(&self.core),
                kind: ReservedOwnerKind::Lock,
                client_id,
                owner: lock_key.owner.clone(),
                sequence_id: arguments.sequence_id,
                digest,
                reserved_state: false,
                created_owner: false,
                committed: false,
            };
            match state
                .stateids
                .validate(arguments.lock_state_id, &file, &[StateKind::ByteRangeLock])
            {
                Err(error) => Err((reservation, map_stateid_error(error))),
                Ok(_) => {
                    let planned_unlock = {
                        let shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
                        shard.files.get(&file).and_then(|file_state| {
                            let mut locks = file_state.locks.clone();
                            locks.unlock(&lock_state_owner, range).then_some(locks)
                        })
                    };
                    match planned_unlock {
                        Some(next_locks)
                            if stable_lock_ranges(&next_locks, &lock_state_owner).len()
                                > self.core.limits.max_lock_ranges_per_state =>
                        {
                            Err((reservation, NfsStatus::Resource))
                        },
                        Some(next_locks) => match state.stateids.preview_transition(arguments.lock_state_id) {
                            Ok(next) => Ok((reservation, next_locks, next)),
                            Err(error) => Err((reservation, map_stateid_error(error))),
                        },
                        None => Err((reservation, NfsStatus::LockRange)),
                    }
                },
            }
        };
        let (mut reservation, next_locks, next) = match prepared {
            Ok(prepared) => prepared,
            Err((reservation, status)) => {
                return self
                    .complete_owner_error(reservation, status, ResOp::LockUnlock(NfsResult::Err(status)))
                    .await;
            },
        };
        let result = ResOp::LockUnlock(NfsResult::Ok(next));
        let reply = match encode_replay(&result) {
            Ok(reply) => reply,
            Err(status) => return ResOp::LockUnlock(NfsResult::Err(status)),
        };
        let mut batch = PersistBatch::default().delete(JournalKey::Lock {
            state_token: state_token(arguments.lock_state_id),
        });
        let remaining_ranges = stable_lock_ranges(&next_locks, &lock_state_owner);
        if !remaining_ranges.is_empty() {
            batch = batch.put(
                JournalKey::Lock {
                    state_token: state_token(next),
                },
                JournalRecord::Lock(StableLockRecord {
                    state_token: state_token(next),
                    open_state_token: state_token(open_state_id),
                    client_id,
                    owner: Bytes::copy_from_slice(&lock_key.owner),
                    object: file.stable(),
                    ranges: remaining_ranges,
                }),
            );
        }
        batch = batch.put(
            replay_key(&reservation),
            JournalRecord::Replay(replay_record(&reservation, &result, ReplayEffect::default(), reply)),
        );
        if self.persist_if_needed(batch).await.is_err() {
            return ResOp::LockUnlock(NfsResult::Err(NfsStatus::Resource));
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        if let Some(file_state) = shard.files.get_mut(&file) {
            file_state.locks = next_locks;
        }
        let transitioned = match state.stateids.transition(arguments.lock_state_id) {
            Ok(state_id) => state_id,
            Err(error) => return ResOp::LockUnlock(NfsResult::Err(map_stateid_error(error))),
        };
        if transitioned != next {
            return ResOp::LockUnlock(NfsResult::Err(NfsStatus::ServerFault));
        }
        // The lock-owner stateid remains live after its final byte-range lock
        // is removed.  A later LOCK with the existing owner must be able to
        // reuse that stateid; RELEASE_LOCKOWNER or closing the originating
        // OPEN retires it.
        state.lock_by_state.insert((lock_state_owner, file), next);
        if commit_reserved_owner(&mut state, &mut reservation, result.clone(), ReplayEffect::default()).is_err() {
            return ResOp::LockUnlock(NfsResult::Err(NfsStatus::ServerFault));
        }
        result
    }

    async fn touch_client(&self, client_id: u64, principal: &Principal) -> Result<(), NfsStatus> {
        self.touch_client_authenticated(client_id, principal)
            .await
            .map_err(|error| error.status)
    }

    async fn touch_client_authenticated(
        &self,
        client_id: u64,
        principal: &Principal,
    ) -> Result<(), ClientAuthenticationError> {
        self.touch_client_with_identity_error(client_id, principal, NfsStatus::StaleClientId)
            .await
    }

    async fn touch_io_client_authenticated(
        &self,
        client_id: u64,
        principal: &Principal,
    ) -> Result<(), ClientAuthenticationError> {
        self.touch_client_with_identity_error(client_id, principal, NfsStatus::Access)
            .await
    }

    async fn touch_client_with_identity_error(
        &self,
        client_id: u64,
        principal: &Principal,
        identity_error: NfsStatus,
    ) -> Result<(), ClientAuthenticationError> {
        let mut clients = self.core.clients.lock().await;
        if clients.expired.contains(&client_id) {
            return Err(ClientAuthenticationError::unauthenticated(NfsStatus::Expired));
        }
        confirmed_client_record_with_identity_error(&clients, client_id, principal, identity_error)
            .map_err(ClientAuthenticationError::unauthenticated)?;
        clients.leases.touch(client_id).map_err(|error| {
            ClientAuthenticationError::unauthenticated(match error {
                LeaseError::UnknownClient => NfsStatus::StaleClientId,
                LeaseError::Expired => NfsStatus::Expired,
            })
        })?;
        let now = clients.clock.now();
        if clients.moved_leases.has_live(client_id, now) {
            return Err(ClientAuthenticationError::authenticated(NfsStatus::LeaseMoved, client_id));
        }
        Ok(())
    }

    async fn gate_state_client(
        &self,
        client_id: u64,
        principal: &Principal,
        reclaim: bool,
    ) -> Result<Vec<u64>, NfsStatus> {
        self.gate_state_client_with_identity(client_id, principal, reclaim)
            .await
            .map_err(|error| error.status)
    }

    async fn gate_state_client_with_identity(
        &self,
        client_id: u64,
        principal: &Principal,
        reclaim: bool,
    ) -> Result<Vec<u64>, ClientAuthenticationError> {
        let mut clients = self.core.clients.lock().await;
        if clients.expired.contains(&client_id) {
            return Err(ClientAuthenticationError::unauthenticated(NfsStatus::Expired));
        }
        confirmed_client_record(&clients, client_id, principal).map_err(ClientAuthenticationError::unauthenticated)?;
        clients.leases.touch(client_id).map_err(|error| {
            ClientAuthenticationError::unauthenticated(match error {
                LeaseError::UnknownClient => NfsStatus::StaleClientId,
                LeaseError::Expired => NfsStatus::Expired,
            })
        })?;
        let now = clients.clock.now();
        if clients.moved_leases.has_live(client_id, now) {
            return Err(ClientAuthenticationError::authenticated(NfsStatus::LeaseMoved, client_id));
        }
        let previous = clients.current_to_previous.get(&client_id).cloned().unwrap_or_default();
        clients
            .recovery
            .allow(&client_id, reclaim)
            .map_err(map_recovery_error)
            .map_err(|status| ClientAuthenticationError::authenticated(status, client_id))?;
        if reclaim && previous.is_empty() {
            return Err(ClientAuthenticationError::authenticated(NfsStatus::ReclaimBad, client_id));
        }
        Ok(if reclaim { previous } else { Vec::new() })
    }

    async fn complete_owner_error(&self, reservation: OwnerReservation, status: NfsStatus, result: ResOp) -> ResOp {
        self.complete_owner_error_with_effect(reservation, status, result, ReplayEffect::default())
            .await
    }

    async fn complete_owner_error_with_effect(
        &self,
        reservation: OwnerReservation,
        status: NfsStatus,
        result: ResOp,
        effect: ReplayEffect,
    ) -> ResOp {
        if !sequence_status_consumed(status) {
            return result;
        }
        let runtime = self.clone();
        let critical = self.core.critical_tasks.start();
        match tokio::spawn(async move {
            let _critical = critical;
            runtime.complete_owner_error_critical(reservation, result, effect).await
        })
        .await
        {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => panic!("critical owner-error completion task was cancelled"),
        }
    }

    /// Cancellation-shielded owner replay consumption for a definitive
    /// stateful-operation error.
    async fn complete_owner_error_critical(
        &self,
        mut reservation: OwnerReservation,
        result: ResOp,
        effect: ReplayEffect,
    ) -> ResOp {
        let reply = match encode_replay(&result) {
            Ok(reply) => reply,
            Err(_) => return owner_error_result(reservation.kind, NfsStatus::Resource),
        };
        let batch = PersistBatch::default()
            .put(replay_key(&reservation), JournalRecord::Replay(replay_record(&reservation, &result, effect, reply)));
        if self.persist_if_needed(batch).await.is_err() {
            return owner_error_result(reservation.kind, NfsStatus::Resource);
        }
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let committed = match reservation.kind {
            ReservedOwnerKind::Open => state
                .open_owners
                .get_mut(&OpenOwnerKey {
                    client_id: reservation.client_id,
                    owner: reservation.owner.clone(),
                })
                .and_then(|owner| {
                    owner
                        .sequence
                        .commit(reservation.sequence_id, reservation.digest, result.clone(), effect)
                        .ok()
                })
                .is_some(),
            ReservedOwnerKind::Lock => state
                .lock_owners
                .get_mut(&LockOwnerKey {
                    client_id: reservation.client_id,
                    owner: reservation.owner.clone(),
                })
                .and_then(|owner| {
                    owner
                        .sequence
                        .commit(reservation.sequence_id, reservation.digest, result.clone(), effect)
                        .ok()
                })
                .is_some(),
        };
        if !committed {
            return owner_error_result(reservation.kind, NfsStatus::ServerFault);
        }
        if reservation.reserved_state {
            state.reserved_states = state.reserved_states.saturating_sub(1);
            reservation.reserved_state = false;
        }
        reservation.committed = true;
        result
    }

    fn remove_pending_open(&self, reservation: &mut OpenTargetReservation) {
        if let Some(token) = reservation.recovered_open_token.take() {
            self.core
                .state
                .lock()
                .expect("NFSv4 state registry poisoned")
                .reserved_recovered_opens
                .remove(&token);
        }
        if reservation.pending_removed {
            return;
        }
        let shard_index = shard_for(&reservation.file, self.core.files.len());
        let mut shard = self.core.files[shard_index].lock().expect("NFSv4 file shard poisoned");
        if let Some(file) = shard.files.get_mut(&reservation.file) {
            file.pending_opens
                .retain(|pending| pending.reservation != reservation.reservation);
            if file.is_empty() {
                shard.files.remove(&reservation.file);
            }
        }
        reservation.pending_removed = true;
    }

    fn revoke_client(&self, client_id: u64, disposition: StateDisposition) -> Vec<PendingPinRelease> {
        let mut state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        let releases = state
            .stateids
            .active_records_for_client(&client_id)
            .filter_map(|(_, file, payload)| match payload {
                StatePayload::Open(open) => Some(ReleasedOpen {
                    client_id,
                    file: *file,
                    pin: open.pin,
                }),
                StatePayload::Lock(_) => None,
            })
            .collect::<Vec<_>>();
        assert!(
            state.stateids.len().saturating_add(state.pending_pin_releases.len()) <= state.stateids.capacity(),
            "state and pin-release reservations exceeded their shared bound"
        );
        let open_tokens = state
            .stateids
            .active_records_for_client(&client_id)
            .filter(|(_, _, payload)| matches!(payload, StatePayload::Open(_)))
            .map(|(state_id, _, _)| state_id.other)
            .collect::<Vec<_>>();
        state.stateids.set_client_disposition(&client_id, disposition);
        let releases = releases
            .into_iter()
            .map(|release| state.queue_pin_release(release, self.core.limits.max_state_objects))
            .collect::<Vec<_>>();
        for token in open_tokens {
            state.reclaimed_open_ancestry.remove(&token);
        }
        state.open_owners.retain(|owner, _| owner.client_id != client_id);
        state.lock_owners.retain(|owner, _| owner.client_id != client_id);
        state.open_by_owner_file.retain(|(owner, _), _| owner.client_id != client_id);
        state.lock_by_state.retain(|(owner, _), _| owner.owner.client_id != client_id);
        drop(state);
        for shard in &self.core.files {
            let mut shard = shard.lock().expect("NFSv4 file shard poisoned");
            for file in shard.files.values_mut() {
                file.shares.release_where(|owner| owner.client_id == client_id);
                file.locks.release_where(|owner| owner.owner.client_id == client_id);
                file.pending_opens.retain(|pending| pending.owner.client_id != client_id);
            }
            shard.files.retain(|_, file| !file.is_empty());
        }
        releases
    }

    fn client_revocation_batch(&self, client_id: u64) -> PersistBatch {
        self.append_client_revocation(PersistBatch::default(), client_id)
    }

    fn append_client_revocation(&self, mut batch: PersistBatch, client_id: u64) -> PersistBatch {
        batch = batch.delete(JournalKey::Client { client_id });
        let state = self.core.state.lock().expect("NFSv4 state registry poisoned");
        for (state_id, _, payload) in state.stateids.active_records_for_client(&client_id) {
            batch = match payload {
                StatePayload::Open(_) => batch.delete(JournalKey::Open {
                    state_token: state_token(state_id),
                }),
                StatePayload::Lock(_) => batch.delete(JournalKey::Lock {
                    state_token: state_token(state_id),
                }),
            };
        }
        for owner in state.open_owners.keys().filter(|owner| owner.client_id == client_id) {
            batch = batch.delete(JournalKey::Replay {
                client_id,
                owner_kind: ReplayOwnerKind::Open,
                owner: Bytes::copy_from_slice(&owner.owner),
            });
        }
        for owner in state.lock_owners.keys().filter(|owner| owner.client_id == client_id) {
            batch = batch.delete(JournalKey::Replay {
                client_id,
                owner_kind: ReplayOwnerKind::Lock,
                owner: Bytes::copy_from_slice(&owner.owner),
            });
        }
        batch
    }

    async fn persist_if_needed(&self, batch: PersistBatch) -> Result<(), NfsStatus> {
        if batch.is_empty() {
            return Ok(());
        }
        let Some(journal) = &self.core.stable_journal else {
            return Ok(());
        };
        journal
            .lock()
            .await
            .persist_before_ack(batch)
            .await
            .map(|_| ())
            .map_err(|_| NfsStatus::Resource)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleasedOpen {
    pub client_id: u64,
    pub file: RuntimeFile,
    pub pin: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingPinRelease {
    pub release_id: u64,
    pub open: ReleasedOpen,
}

impl StateRegistry {
    fn queue_pin_release(&mut self, open: ReleasedOpen, capacity: usize) -> PendingPinRelease {
        assert!(self.pending_pin_releases.len() < capacity, "pin-release outbox capacity invariant violated");
        let release_id = self.next_pin_release_id;
        self.next_pin_release_id = self.next_pin_release_id.wrapping_add(1).max(1);
        assert!(
            self.pending_pin_releases.iter().all(|pending| pending.release_id != release_id),
            "pin-release identifier wrapped while still pending"
        );
        let pending = PendingPinRelease { release_id, open };
        self.pending_pin_releases.push(pending);
        pending
    }
}

impl FileState {
    fn is_empty(&self) -> bool {
        self.shares.reservations().is_empty() && self.locks.records().is_empty() && self.pending_opens.is_empty()
    }
}

fn validate_recovery_import_locked(
    clients: &ClientRegistry,
    state: &StateRegistry,
    prepared: &PreparedRuntimeRecovery,
    limits: &Nfs4Limits,
) -> Result<(), RuntimeConfigError> {
    if prepared.previous_shutdown == PreviousShutdown::FirstBoot {
        return Err(RuntimeConfigError::Recovery);
    }
    let imported = &prepared.state;
    let mut previous_identities = HashMap::<u64, &RecoveredClientIdentity>::new();
    for (identity, previous_ids) in &clients.recovered_clients {
        for previous_id in previous_ids {
            if previous_identities
                .insert(*previous_id, identity)
                .is_some_and(|existing| existing != identity)
            {
                return Err(RuntimeConfigError::Recovery);
            }
        }
    }
    for (identity, previous_ids) in &imported.clients {
        for previous_id in previous_ids {
            if clients.client_owners.contains_key(previous_id)
                || previous_identities
                    .get(previous_id)
                    .is_some_and(|existing| *existing != identity)
            {
                return Err(RuntimeConfigError::Recovery);
            }
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum OccupiedStateKind {
        Live,
        Open,
        Lock,
    }
    let mut occupied_others = HashMap::<[u8; 12], (OccupiedStateKind, [u8; 16])>::new();
    let mut token_collision = false;
    for state_id in state.open_by_owner_file.values().chain(state.lock_by_state.values()) {
        if occupied_others
            .insert(state_id.other, (OccupiedStateKind::Live, state_token(*state_id)))
            .is_some()
        {
            token_collision = true;
        }
    }
    for token in state.recovered_opens.keys() {
        if occupied_others
            .insert(state_other(*token), (OccupiedStateKind::Open, *token))
            .is_some()
        {
            token_collision = true;
        }
    }
    for token in state.recovered_locks.keys() {
        if occupied_others
            .insert(state_other(*token), (OccupiedStateKind::Lock, *token))
            .is_some()
        {
            token_collision = true;
        }
    }
    for (token, recovered) in &imported.opens {
        match occupied_others.get(&state_other(*token)) {
            None => {
                occupied_others.insert(state_other(*token), (OccupiedStateKind::Open, *token));
            },
            Some((OccupiedStateKind::Open, existing_token))
                if existing_token == token && state.recovered_opens.get(token) == Some(recovered) => {},
            Some(_) => token_collision = true,
        }
    }
    for (token, recovered) in &imported.locks {
        match occupied_others.get(&state_other(*token)) {
            None => {
                occupied_others.insert(state_other(*token), (OccupiedStateKind::Lock, *token));
            },
            Some((OccupiedStateKind::Lock, existing_token))
                if existing_token == token && state.recovered_locks.get(token) == Some(recovered) => {},
            Some(_) => token_collision = true,
        }
    }

    let mut all_previous_ids = previous_identities.keys().copied().collect::<HashSet<_>>();
    all_previous_ids.extend(imported.clients.values().flatten().copied());
    let new_recovered_opens = imported
        .opens
        .iter()
        .filter(|(token, recovered)| state.recovered_opens.get(*token) != Some(*recovered))
        .count();
    let new_recovered_locks = imported
        .locks
        .iter()
        .filter(|(token, recovered)| state.recovered_locks.get(*token) != Some(*recovered))
        .count();
    let projected_state_candidates = state
        .stateids
        .len()
        .saturating_add(state.reserved_states)
        .saturating_add(state.recovered_opens.len())
        .saturating_add(state.recovered_locks.len())
        .saturating_add(new_recovered_opens)
        .saturating_add(new_recovered_locks);
    let mut projected_open_owners = HashMap::<u64, HashSet<&[u8]>>::new();
    for recovered in state.recovered_opens.values().chain(imported.opens.values()) {
        projected_open_owners
            .entry(recovered.previous_client_id)
            .or_default()
            .insert(&recovered.owner);
    }
    let mut projected_lock_owners = HashMap::<u64, HashSet<&[u8]>>::new();
    for recovered in state.recovered_locks.values().chain(imported.locks.values()) {
        projected_lock_owners
            .entry(recovered.previous_client_id)
            .or_default()
            .insert(&recovered.owner);
    }

    let replay_conflict = imported
        .replays
        .iter()
        .any(|(key, recovered)| state.recovered_replays.get(key).is_some_and(|existing| existing != recovered));

    if token_collision
        || replay_conflict
        || state.reserved_states != 0
        || all_previous_ids.len() > limits.max_clients
        || projected_state_candidates > limits.max_state_objects
        || projected_open_owners
            .values()
            .any(|owners| owners.len() > limits.max_open_owners_per_client)
        || projected_lock_owners
            .values()
            .any(|owners| owners.len() > limits.max_lock_owners_per_client)
        || state
            .recovered_locks
            .values()
            .chain(imported.locks.values())
            .any(|lock| lock.ranges.len() > limits.max_lock_ranges_per_state)
    {
        return Err(RuntimeConfigError::Recovery);
    }
    Ok(())
}

fn prepare_runtime_recovery(
    recovered: &RecoveredStableState,
    limits: &Nfs4Limits,
    minimum_grace_duration: Duration,
) -> Result<PreparedRuntimeRecovery, RuntimeConfigError> {
    if minimum_grace_duration.is_zero() {
        return Err(RuntimeConfigError::Recovery);
    }
    if recovered.previous_shutdown == PreviousShutdown::FirstBoot {
        if recovered.previous_boot.is_some() || !recovered.records.is_empty() {
            return Err(RuntimeConfigError::Recovery);
        }
        return Ok(PreparedRuntimeRecovery {
            previous_shutdown: PreviousShutdown::FirstBoot,
            minimum_grace_duration,
            state: RecoveredRuntimeState::default(),
        });
    }
    let _previous_boot = recovered.previous_boot.ok_or(RuntimeConfigError::Recovery)?;
    let mut state = RecoveredRuntimeState::default();
    let mut clients_by_id = HashMap::<u64, StableClientRecord>::new();
    let mut confirmed_client_count = 0usize;
    for (key, record) in &recovered.records {
        let JournalRecord::Client(client) = record else {
            continue;
        };
        let client_boot_tag = (client.client_id >> 32) as u32;
        if key
            != &(JournalKey::Client {
                client_id: client.client_id,
            })
            || client.owner.is_empty()
            || client.owner.len() > limits.max_client_owner_size
            || client.canonical_principal.is_empty()
            || matches!(client_boot_tag, 0 | u32::MAX)
            || clients_by_id.insert(client.client_id, client.clone()).is_some()
        {
            return Err(RuntimeConfigError::Recovery);
        }
        state.cleanup_keys.insert(key.clone());
        if client.confirmed {
            confirmed_client_count = confirmed_client_count.checked_add(1).ok_or(RuntimeConfigError::Recovery)?;
            if confirmed_client_count > limits.max_clients {
                return Err(RuntimeConfigError::Recovery);
            }
            let identity = RecoveredClientIdentity {
                owner: client.owner.to_vec(),
                verifier: client.verifier,
                principal: client.canonical_principal.to_vec(),
            };
            state.clients.entry(identity).or_default().push(client.client_id);
        }
    }
    for previous_ids in state.clients.values_mut() {
        previous_ids.sort_unstable();
        previous_ids.dedup();
    }

    let mut owner_counts = HashMap::<u64, HashSet<Vec<u8>>>::new();
    let mut recovered_state_others = HashSet::<[u8; 12]>::new();
    let mut recovered_opens_by_other = HashMap::<[u8; 12], [u8; 16]>::new();
    for (key, record) in &recovered.records {
        match record {
            JournalRecord::Open(open) => {
                if key
                    != &(JournalKey::Open {
                        state_token: open.state_token,
                    })
                    || !valid_recovered_state_token(open.state_token, (open.client_id >> 32) as u32)
                    || !clients_by_id.get(&open.client_id).is_some_and(|client| client.confirmed)
                    || open.owner.is_empty()
                    || open.owner.len() > limits.max_client_owner_size
                {
                    return Err(RuntimeConfigError::Recovery);
                }
                let access = ShareAccess::from_wire(open.share_access).ok_or(RuntimeConfigError::Recovery)?;
                let deny = ShareDeny::from_wire(open.share_deny).ok_or(RuntimeConfigError::Recovery)?;
                let mut contributions = ShareContributions::default();
                for contribution in &open.contributions {
                    let contribution_access =
                        ShareAccess::from_wire(contribution.share_access).ok_or(RuntimeConfigError::Recovery)?;
                    let contribution_deny =
                        ShareDeny::from_wire(contribution.share_deny).ok_or(RuntimeConfigError::Recovery)?;
                    contributions
                        .add(
                            contribution_access,
                            contribution_deny,
                            contribution.count,
                            limits.max_open_contributions_per_state,
                        )
                        .map_err(|_| RuntimeConfigError::Recovery)?;
                }
                if contributions.aggregate() != Some((access, deny)) {
                    return Err(RuntimeConfigError::Recovery);
                }
                let other = state_other(open.state_token);
                if !recovered_state_others.insert(other)
                    || recovered_opens_by_other.insert(other, open.state_token).is_some()
                {
                    return Err(RuntimeConfigError::Recovery);
                }
                let recovered_open = RecoveredOpen {
                    state_token: open.state_token,
                    previous_client_id: open.client_id,
                    owner: open.owner.to_vec(),
                    file: runtime_file(open.object),
                    access,
                    deny,
                    contributions,
                };
                if state.opens.insert(open.state_token, recovered_open).is_some() {
                    return Err(RuntimeConfigError::Recovery);
                }
                owner_counts.entry(open.client_id).or_default().insert(open.owner.to_vec());
                state.cleanup_keys.insert(key.clone());
            },
            JournalRecord::Replay(replay) => {
                if key
                    != &(JournalKey::Replay {
                        client_id: replay.client_id,
                        owner_kind: replay.owner_kind,
                        owner: replay.owner.clone(),
                    })
                    || !clients_by_id.get(&replay.client_id).is_some_and(|client| client.confirmed)
                    || replay.owner.is_empty()
                    || replay.owner.len() > limits.max_client_owner_size
                {
                    return Err(RuntimeConfigError::Recovery);
                }
                let result = decode_replay(&replay.reply).map_err(|_| RuntimeConfigError::Recovery)?;
                let effect = ReplayEffect {
                    current_file: replay.current_object.map(runtime_file),
                    stateid_renewal_client: match replay.renewal_source {
                        ReplayRenewalSource::None => None,
                        ReplayRenewalSource::StateId { client_id } if client_id == replay.client_id => Some(client_id),
                        ReplayRenewalSource::StateId { .. } => return Err(RuntimeConfigError::Recovery),
                    },
                };
                let recovered_replay = (replay.sequence_id, OwnerRequestDigest(replay.request_digest), result, effect);
                let replay_key = (replay.client_id, replay.owner_kind, replay.owner.to_vec());
                if state.replays.insert(replay_key, recovered_replay).is_some() {
                    return Err(RuntimeConfigError::Recovery);
                }
                state.cleanup_keys.insert(key.clone());
            },
            _ => {},
        }
    }
    if owner_counts
        .values()
        .any(|owners| owners.len() > limits.max_open_owners_per_client)
        || state.opens.len() > limits.max_state_objects
    {
        return Err(RuntimeConfigError::Recovery);
    }

    let mut lock_owner_counts = HashMap::<u64, HashSet<Vec<u8>>>::new();
    for (key, record) in &recovered.records {
        let JournalRecord::Lock(lock) = record else {
            continue;
        };
        // A lock refers to the OPEN state object, whose 12-byte `other`
        // identity is stable while the leading sequence advances on
        // OPEN_CONFIRM, upgrade, and downgrade. Older journal entries can
        // therefore legitimately contain an earlier OPEN sequence token.
        let stable_open_token = recovered_opens_by_other.get(&state_other(lock.open_state_token)).copied();
        let stable_open = stable_open_token.and_then(|token| state.opens.get(&token));
        if key
            != &(JournalKey::Lock {
                state_token: lock.state_token,
            })
            || !valid_recovered_state_token(lock.state_token, (lock.client_id >> 32) as u32)
            || !recovered_state_others.insert(state_other(lock.state_token))
            || !clients_by_id.get(&lock.client_id).is_some_and(|client| client.confirmed)
            || !stable_open
                .is_some_and(|open| open.previous_client_id == lock.client_id && open.file == runtime_file(lock.object))
            || lock.owner.is_empty()
            || lock.owner.len() > limits.max_client_owner_size
            || lock.ranges.len() > limits.max_lock_ranges_per_state
        {
            return Err(RuntimeConfigError::Recovery);
        }
        let ranges = lock
            .ranges
            .iter()
            .map(|range| {
                let wire_length = if range.length == 0 { u64::MAX } else { range.length };
                Ok(RecoveredLockRange {
                    access: if range.write {
                        LockAccess::Write
                    } else {
                        LockAccess::Read
                    },
                    range: LockRange::from_offset_length(range.offset, wire_length)
                        .map_err(|_| RuntimeConfigError::Recovery)?,
                })
            })
            .collect::<Result<Vec<_>, RuntimeConfigError>>()?;
        let recovered_lock = RecoveredLock {
            state_token: lock.state_token,
            previous_open_state_token: stable_open_token.expect("validated matching OPEN state identity"),
            previous_client_id: lock.client_id,
            owner: lock.owner.to_vec(),
            file: runtime_file(lock.object),
            ranges,
        };
        if state.locks.insert(lock.state_token, recovered_lock).is_some() {
            return Err(RuntimeConfigError::Recovery);
        }
        lock_owner_counts.entry(lock.client_id).or_default().insert(lock.owner.to_vec());
        state.cleanup_keys.insert(key.clone());
    }
    if lock_owner_counts
        .values()
        .any(|owners| owners.len() > limits.max_lock_owners_per_client)
        || state.opens.len().saturating_add(state.locks.len()) > limits.max_state_objects
    {
        return Err(RuntimeConfigError::Recovery);
    }

    Ok(PreparedRuntimeRecovery {
        previous_shutdown: recovered.previous_shutdown,
        minimum_grace_duration,
        state,
    })
}

fn runtime_file(object: StableObject) -> RuntimeFile {
    RuntimeFile {
        export_id: object.export_id,
        object: ObjectKey {
            file_id: object.file_id,
            generation: object.generation,
        },
    }
}

fn valid_recovered_state_token(token: [u8; 16], client_boot_tag: u32) -> bool {
    let sequence = u32::from_be_bytes(token[..4].try_into().expect("state token sequence"));
    let other: [u8; 12] = token[4..].try_into().expect("state token body");
    let boot_tag = u32::from_be_bytes(other[..4].try_into().expect("state token boot tag"));
    sequence != 0
        && other != [0; 12]
        && other != [u8::MAX; 12]
        && !matches!(client_boot_tag, 0 | u32::MAX)
        && boot_tag == client_boot_tag
}

fn confirmed_client_record<'a>(
    clients: &'a ClientRegistry,
    client_id: u64,
    principal: &Principal,
) -> Result<&'a ClientRecord, NfsStatus> {
    confirmed_client_record_with_identity_error(clients, client_id, principal, NfsStatus::StaleClientId)
}

fn confirmed_client_record_with_identity_error<'a>(
    clients: &'a ClientRegistry,
    client_id: u64,
    principal: &Principal,
    identity_error: NfsStatus,
) -> Result<&'a ClientRecord, NfsStatus> {
    let owner = clients.client_owners.get(&client_id).ok_or(NfsStatus::StaleClientId)?;
    let record = clients
        .slots
        .get(owner)
        .and_then(|slot| slot.confirmed.as_ref())
        .filter(|record| record.client_id == client_id)
        .ok_or(NfsStatus::StaleClientId)?;
    if !same_client_identity(&record.setclientid_principal, principal) {
        return Err(identity_error);
    }
    Ok(record)
}

fn stable_client_record(record: &ClientRecord, confirmed: bool) -> StableClientRecord {
    StableClientRecord {
        client_id: record.client_id,
        owner: Bytes::copy_from_slice(&record.owner),
        verifier: record.verifier,
        canonical_principal: Bytes::from(canonical_client_identity(&record.setclientid_principal)),
        confirmed,
    }
}

fn purge_unconfirmed(clients: &mut ClientRegistry, now: Duration) -> Vec<u64> {
    let mut stale = Vec::new();
    for slot in clients.slots.values_mut() {
        if slot
            .unconfirmed
            .as_ref()
            .is_some_and(|record| now.saturating_sub(record.created_at) >= clients.lease_duration)
        {
            if let Some(record) = slot.unconfirmed.take() {
                if slot
                    .confirmed
                    .as_ref()
                    .is_none_or(|confirmed| confirmed.client_id != record.client_id)
                {
                    clients.client_owners.remove(&record.client_id);
                    stale.push(record.client_id);
                }
            }
        }
    }
    clients
        .slots
        .retain(|_, slot| slot.confirmed.is_some() || slot.unconfirmed.is_some());
    stale
}

fn remove_client_registration(clients: &mut ClientRegistry, client_id: u64) {
    clients.moved_leases.remove_client(client_id);
    let Some(owner) = clients.client_owners.remove(&client_id) else {
        clients.current_to_previous.remove(&client_id);
        clients.recovery.complete_client_reclaim(&client_id);
        clients.leases.remove(&client_id);
        return;
    };
    if let Some(slot) = clients.slots.get_mut(&owner) {
        if slot.confirmed.as_ref().is_some_and(|record| record.client_id == client_id) {
            slot.confirmed = None;
        }
        if slot.unconfirmed.as_ref().is_some_and(|record| record.client_id == client_id) {
            slot.unconfirmed = None;
        }
    }
    clients
        .slots
        .retain(|_, slot| slot.confirmed.is_some() || slot.unconfirmed.is_some());
    clients.current_to_previous.remove(&client_id);
    clients.recovery.complete_client_reclaim(&client_id);
    clients.leases.remove(&client_id);
}

fn bound_expired_clientids(clients: &mut ClientRegistry, maximum: usize) {
    while clients.expired.len() > maximum.max(1) {
        let removable = clients
            .expired
            .iter()
            .copied()
            .find(|client_id| !clients.pending_expiry.contains(client_id));
        let Some(client_id) = removable else {
            break;
        };
        clients.expired.remove(&client_id);
    }
}

fn allocate_client_id(clients: &mut ClientRegistry) -> Option<u64> {
    for _ in 0..u32::MAX {
        let counter = clients.next_client;
        clients.next_client = clients.next_client.checked_add(1).unwrap_or(1);
        if counter == 0 {
            continue;
        }
        let client_id = (u64::from(clients.boot_tag) << 32) | u64::from(counter);
        if !clients.client_owners.contains_key(&client_id) {
            return Some(client_id);
        }
    }
    None
}

fn allocate_confirmation(clients: &mut ClientRegistry, client_id: u64, verifier: &[u8; 8]) -> [u8; 8] {
    let counter = clients.next_confirmation;
    clients.next_confirmation = clients.next_confirmation.wrapping_add(1).max(1);
    let mut hash = Sha256::new();
    hash.update(b"nfsembed/nfs4/setclientid-confirm");
    hash.update(clients.boot_tag.to_be_bytes());
    hash.update(client_id.to_be_bytes());
    hash.update(counter.to_be_bytes());
    hash.update(verifier);
    hash.finalize()[..8].try_into().expect("SHA-256 has eight bytes")
}

fn canonical_client_identity(principal: &Principal) -> Vec<u8> {
    let mut value = Vec::new();
    match principal {
        Principal::Anonymous => value.push(0),
        Principal::AuthSys {
            uid,
            gid,
            supplementary_gids,
            machine_name,
        } => {
            value.push(1);
            value.extend_from_slice(&uid.to_be_bytes());
            value.extend_from_slice(&gid.to_be_bytes());
            value.extend_from_slice(&(supplementary_gids.len() as u32).to_be_bytes());
            for group in supplementary_gids {
                value.extend_from_slice(&group.to_be_bytes());
            }
            value.extend_from_slice(&(machine_name.len() as u32).to_be_bytes());
            value.extend_from_slice(machine_name);
        },
        Principal::Gss {
            canonical_name,
            mechanism,
            ..
        } => {
            value.push(2);
            value.extend_from_slice(&(canonical_name.len() as u32).to_be_bytes());
            value.extend_from_slice(canonical_name.as_bytes());
            value.extend_from_slice(&(mechanism.len() as u32).to_be_bytes());
            value.extend_from_slice(mechanism);
        },
    }
    value
}

/// Compares the client identity bound by SETCLIENTID independently from the
/// exact RPC authentication flavor used for an individual operation.
///
/// A GSS canonical name and mechanism identify one Kerberos client across
/// RPCSEC_GSS versions and krb5/krb5i/krb5p service levels. AUTH_NONE and
/// AUTH_SYS remain exact to avoid broadening weaker identities.
fn same_client_identity(stored: &Principal, presented: &Principal) -> bool {
    match (stored, presented) {
        (
            Principal::Gss {
                canonical_name: stored_name,
                mechanism: stored_mechanism,
                ..
            },
            Principal::Gss {
                canonical_name: presented_name,
                mechanism: presented_mechanism,
                ..
            },
        ) => stored_name == presented_name && stored_mechanism == presented_mechanism,
        _ => stored == presented,
    }
}

fn shard_for(value: &impl Hash, shards: usize) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % shards
}

fn map_stateid_error(error: StateIdValidationError) -> NfsStatus {
    match error {
        StateIdValidationError::BadStateId => NfsStatus::BadStateId,
        StateIdValidationError::StaleStateId => NfsStatus::StaleStateId,
        StateIdValidationError::OldStateId => NfsStatus::OldStateId,
        StateIdValidationError::Expired => NfsStatus::Expired,
        StateIdValidationError::AdminRevoked => NfsStatus::AdminRevoked,
    }
}

fn map_recovery_error(error: RecoveryError) -> NfsStatus {
    match error {
        RecoveryError::Grace => NfsStatus::Grace,
        RecoveryError::NoGrace => NfsStatus::NoGrace,
        RecoveryError::ReclaimBad => NfsStatus::ReclaimBad,
    }
}

fn lock_access(lock_type: LockType) -> LockAccess {
    match lock_type {
        LockType::Read | LockType::BlockingRead => LockAccess::Read,
        LockType::Write | LockType::BlockingWrite => LockAccess::Write,
    }
}

fn delegation_kinds_conflict(held: DelegationKind, requested: DelegationKind) -> bool {
    matches!((held, requested), (DelegationKind::Write, _) | (DelegationKind::Read, DelegationKind::Write))
}

fn delegation_kind_for_lock(lock_type: LockType) -> DelegationKind {
    match lock_type {
        LockType::Read | LockType::BlockingRead => DelegationKind::Read,
        LockType::Write | LockType::BlockingWrite => DelegationKind::Write,
    }
}

fn validate_delegation_eligibility(
    state: &StateRegistry,
    target: &OpenTargetReservation,
    delegation: &OpenDelegation,
) -> Result<(), NfsStatus> {
    let granted_kind = match delegation {
        OpenDelegation::None => None,
        OpenDelegation::Read(_) => Some(DelegationKind::Read),
        OpenDelegation::Write(_) => Some(DelegationKind::Write),
    };
    let Some(reservation) = &target.delegation_eligibility else {
        return if granted_kind.is_none() {
            Ok(())
        } else {
            Err(NfsStatus::ServerFault)
        };
    };
    let pending = state
        .delegation_eligibility
        .get(&reservation.id())
        .ok_or(NfsStatus::ServerFault)?;
    if pending.file != target.file
        || pending.client_id != target.key.client_id
        || pending.open_reservation != target.reservation
        || granted_kind.is_some_and(|kind| kind != pending.kind)
    {
        return Err(NfsStatus::ServerFault);
    }
    Ok(())
}

fn delegation_share_eligible_locked(file_state: &FileState, client_id: u64, kind: DelegationKind) -> bool {
    let shares_are_safe = file_state.shares.reservations().iter().all(|reservation| {
        reservation.owner.client_id == client_id
            && (kind == DelegationKind::Write || reservation.access.bits() & ShareAccess::WRITE.bits() == 0)
    });
    let pending_are_safe = file_state.pending_opens.iter().all(|pending| {
        pending.owner.client_id == client_id
            && (kind == DelegationKind::Write || pending.access.bits() & ShareAccess::WRITE.bits() == 0)
    });
    let locks_are_safe = file_state.locks.records().iter().all(|lock| {
        lock.owner.owner.client_id == client_id && (kind == DelegationKind::Write || lock.access != LockAccess::Write)
    });
    shares_are_safe && pending_are_safe && locks_are_safe
}

fn denied(record: &LockRecord<LockStateOwner, [u8; 12]>) -> LockDenied {
    LockDenied {
        offset: record.range.start,
        length: record.range.end.map_or(u64::MAX, |end| end.saturating_sub(record.range.start)),
        lock_type: match record.access {
            LockAccess::Read => LockType::Read,
            LockAccess::Write => LockType::Write,
        },
        owner: LockOwner {
            client_id: record.owner.owner.client_id,
            owner: record.owner.owner.owner.clone(),
        },
    }
}

fn replayed_lock_result(decision: &SequenceDecision<ResOp, ReplayEffect>) -> Option<LockResult> {
    match decision {
        SequenceDecision::Replay {
            result: ResOp::Lock(result),
            ..
        } => Some(result.clone()),
        _ => None,
    }
}

fn commit_reserved_owner(
    state: &mut StateRegistry,
    reservation: &mut OwnerReservation,
    result: ResOp,
    effect: ReplayEffect,
) -> Result<(), ()> {
    let committed = match reservation.kind {
        ReservedOwnerKind::Open => state
            .open_owners
            .get_mut(&OpenOwnerKey {
                client_id: reservation.client_id,
                owner: reservation.owner.clone(),
            })
            .ok_or(())?
            .sequence
            .commit(reservation.sequence_id, reservation.digest, result, effect),
        ReservedOwnerKind::Lock => state
            .lock_owners
            .get_mut(&LockOwnerKey {
                client_id: reservation.client_id,
                owner: reservation.owner.clone(),
            })
            .ok_or(())?
            .sequence
            .commit(reservation.sequence_id, reservation.digest, result, effect),
    };
    committed.map_err(|_| ())?;
    if reservation.reserved_state {
        state.reserved_states = state.reserved_states.saturating_sub(1);
        reservation.reserved_state = false;
    }
    reservation.committed = true;
    Ok(())
}

fn stable_open_contributions(contributions: ShareContributions) -> Vec<StableOpenContributionRecord> {
    contributions
        .entries()
        .map(|(access, deny, count)| StableOpenContributionRecord {
            share_access: access.bits(),
            share_deny: deny.bits(),
            count,
        })
        .collect()
}

fn stable_lock_length(range: LockRange) -> u64 {
    range.end.map_or(0, |end| end.saturating_sub(range.start))
}

fn stable_lock_ranges(
    locks: &LockTable<LockStateOwner, [u8; 12]>,
    owner: &LockStateOwner,
) -> Vec<StableLockRangeRecord> {
    locks
        .records()
        .iter()
        .filter(|record| &record.owner == owner)
        .map(|record| StableLockRangeRecord {
            offset: record.range.start,
            length: stable_lock_length(record.range),
            write: record.access == LockAccess::Write,
        })
        .collect()
}

fn stable_recovered_lock(recovered: &RecoveredLock) -> StableLockRecord {
    StableLockRecord {
        state_token: recovered.state_token,
        open_state_token: recovered.previous_open_state_token,
        client_id: recovered.previous_client_id,
        owner: Bytes::copy_from_slice(&recovered.owner),
        object: recovered.file.stable(),
        ranges: recovered
            .ranges
            .iter()
            .map(|range| StableLockRangeRecord {
                offset: range.range.start,
                length: stable_lock_length(range.range),
                write: range.access == LockAccess::Write,
            })
            .collect(),
    }
}

fn recovered_lock_remainder(recovered: &RecoveredLock, consumed: RecoveredLockRange) -> Option<RecoveredLock> {
    let mut remaining = recovered.clone();
    let position = remaining
        .ranges
        .iter()
        .position(|candidate| *candidate == consumed)
        .expect("a selected recovered lock range remains present");
    remaining.ranges.remove(position);
    (!remaining.ranges.is_empty()).then_some(remaining)
}

fn state_token(stateid: StateId) -> [u8; 16] {
    let mut token = [0; 16];
    token[..4].copy_from_slice(&stateid.sequence_id.to_be_bytes());
    token[4..].copy_from_slice(&stateid.other);
    token
}

fn state_other(token: [u8; 16]) -> [u8; 12] {
    token[4..].try_into().expect("fixed-size state token")
}

fn replay_key(reservation: &OwnerReservation) -> JournalKey {
    JournalKey::Replay {
        client_id: reservation.client_id,
        owner_kind: match reservation.kind {
            ReservedOwnerKind::Open => ReplayOwnerKind::Open,
            ReservedOwnerKind::Lock => ReplayOwnerKind::Lock,
        },
        owner: Bytes::copy_from_slice(&reservation.owner),
    }
}

fn replay_record(reservation: &OwnerReservation, _result: &ResOp, effect: ReplayEffect, reply: Bytes) -> ReplayRecord {
    ReplayRecord {
        client_id: reservation.client_id,
        owner_kind: match reservation.kind {
            ReservedOwnerKind::Open => ReplayOwnerKind::Open,
            ReservedOwnerKind::Lock => ReplayOwnerKind::Lock,
        },
        owner: Bytes::copy_from_slice(&reservation.owner),
        sequence_id: reservation.sequence_id,
        request_digest: reservation.digest.0,
        reply,
        current_object: effect.current_file.map(RuntimeFile::stable),
        renewal_source: match effect.stateid_renewal_client {
            Some(client_id) => ReplayRenewalSource::StateId { client_id },
            None => ReplayRenewalSource::None,
        },
    }
}

fn owner_error_result(kind: ReservedOwnerKind, status: NfsStatus) -> ResOp {
    match kind {
        ReservedOwnerKind::Open => ResOp::Open(NfsResult::Err(status)),
        ReservedOwnerKind::Lock => ResOp::Lock(LockResult::Err(status)),
    }
}

fn sequence_status_consumed(status: NfsStatus) -> bool {
    !matches!(
        status,
        NfsStatus::StaleClientId
            | NfsStatus::StaleStateId
            | NfsStatus::BadStateId
            | NfsStatus::BadSequenceId
            | NfsStatus::BadXdr
            | NfsStatus::Resource
            | NfsStatus::NoFileHandle
            | NfsStatus::Moved
    )
}

fn open_pin(boot_tag: u32, reservation: u64) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"nfsembed/nfs4/open-pin");
    hash.update(boot_tag.to_be_bytes());
    hash.update(reservation.to_be_bytes());
    hash.finalize()[..16].try_into().expect("SHA-256 has sixteen bytes")
}

fn encode_replay(result: &ResOp) -> Result<Bytes, NfsStatus> {
    encode_compound_res(&CompoundRes::from_operations(Vec::new(), vec![result.clone()]))
        .map(Bytes::from)
        .map_err(|_| NfsStatus::ServerFault)
}

fn decode_replay(bytes: &[u8]) -> Result<ResOp, NfsStatus> {
    let response =
        decode_compound_res(bytes, super::codec::DecodeLimits::default()).map_err(|_| NfsStatus::ServerFault)?;
    response.operations.into_iter().next().ok_or(NfsStatus::ServerFault)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::nfs4::stable::tests::DurableFakeStore;
    use crate::nfs4::stable::{BootRecord, StableJournalLimits};
    use crate::nfs4::state::lease::ManualLeaseClock;
    use crate::nfs4::types::{ClientAddress, NfsClientId, ANONYMOUS_STATE_ID, READ_BYPASS_STATE_ID};
    use crate::vfs::{
        GssService, GssVersion, StableBatch, StableFenceToken, StableMutation, StableRecord, StableScope,
        StableSnapshot, StableStateError, StableStateSession, StableStateStore,
    };

    const KERBEROS_MECHANISM: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

    #[derive(Clone)]
    struct CommitAmbiguityStore {
        state: Arc<Mutex<CommitAmbiguityState>>,
        block_next: Arc<AtomicBool>,
        applied: Arc<Semaphore>,
        release: Arc<Semaphore>,
        fence: StableFenceToken,
    }

    #[derive(Default)]
    struct CommitAmbiguityState {
        generation: u64,
        records: HashMap<crate::vfs::StableKey, Bytes>,
    }

    impl Default for CommitAmbiguityStore {
        fn default() -> Self {
            Self {
                state: Arc::new(Mutex::new(CommitAmbiguityState::default())),
                block_next: Arc::new(AtomicBool::new(false)),
                applied: Arc::new(Semaphore::new(0)),
                release: Arc::new(Semaphore::new(0)),
                fence: StableFenceToken::new(Bytes::from_static(b"commit-ambiguity-fence")),
            }
        }
    }

    impl CommitAmbiguityStore {
        fn block_next_commit_after_apply(&self) {
            self.block_next.store(true, Ordering::Release);
        }

        async fn wait_until_commit_applied(&self) {
            self.applied
                .acquire()
                .await
                .expect("commit-applied semaphore remains open")
                .forget();
        }

        fn allow_commit_to_return(&self) {
            self.release.add_permits(1);
        }
    }

    #[async_trait]
    impl StableStateStore for CommitAmbiguityStore {
        async fn open_scope(&self, _scope: StableScope) -> Result<Arc<dyn StableStateSession>, StableStateError> {
            Ok(Arc::new(self.clone()))
        }
    }

    #[async_trait]
    impl StableStateSession for CommitAmbiguityStore {
        fn fence_token(&self) -> StableFenceToken {
            self.fence.clone()
        }

        fn generation(&self) -> u64 {
            self.state.lock().expect("ambiguity-store state poisoned").generation
        }

        async fn recover(&self) -> Result<StableSnapshot, StableStateError> {
            let state = self.state.lock().expect("ambiguity-store state poisoned");
            let mut records = state
                .records
                .iter()
                .map(|(key, payload)| StableRecord {
                    key: key.clone(),
                    payload: payload.clone(),
                })
                .collect::<Vec<_>>();
            records.sort_by(|left, right| left.key.key.as_ref().cmp(right.key.key.as_ref()));
            Ok(StableSnapshot {
                fence_token: self.fence.clone(),
                generation: state.generation,
                records,
            })
        }

        async fn commit(&self, expected_generation: u64, batch: StableBatch) -> Result<u64, StableStateError> {
            let next_generation = {
                let mut state = self.state.lock().expect("ambiguity-store state poisoned");
                if state.generation != expected_generation {
                    return Err(StableStateError::GenerationConflict {
                        expected: expected_generation,
                        actual: state.generation,
                    });
                }
                let next_generation = state
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| StableStateError::Other("ambiguity-store generation overflow".into()))?;
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
                state.generation = next_generation;
                next_generation
            };
            if self.block_next.swap(false, Ordering::AcqRel) {
                self.applied.add_permits(1);
                self.release
                    .acquire()
                    .await
                    .expect("commit-release semaphore remains open")
                    .forget();
            }
            Ok(next_generation)
        }
    }

    fn config() -> RuntimeConfig {
        RuntimeConfig {
            lease_duration: Duration::from_secs(10),
            grace_duration: Duration::from_secs(10),
            limits: Nfs4Limits {
                max_compound_operations: 16,
                max_clients: 8,
                max_open_owners_per_client: 8,
                max_open_contributions_per_state: 8,
                max_lock_owners_per_client: 8,
                max_lock_ranges_per_state: 8,
                max_state_objects: 32,
                max_client_owner_size: 64,
                max_state_payload_size: 4096,
            },
            boot_tag: 0x1234_5678,
            write_verifier: [0x5a; 8],
            stable_journal: None,
            recovered: None,
        }
    }

    fn recovered_state(previous_shutdown: PreviousShutdown) -> (RecoveredStableState, u64, RuntimeFile) {
        let previous_boot_tag: u32 = 0x1020_3040;
        let previous_client_id = (u64::from(previous_boot_tag) << 32) | 7;
        let file = test_file(700);
        let open_state_id = StateId {
            sequence_id: 1,
            other: {
                let mut other = [0; 12];
                other[..4].copy_from_slice(&previous_boot_tag.to_be_bytes());
                other[4..8].copy_from_slice(&3u32.to_be_bytes());
                other[8..].copy_from_slice(&1u32.to_be_bytes());
                other
            },
        };
        let lock_state_id = StateId {
            sequence_id: 1,
            other: {
                let mut other = [0; 12];
                other[..4].copy_from_slice(&previous_boot_tag.to_be_bytes());
                other[4..8].copy_from_slice(&4u32.to_be_bytes());
                other[8..].copy_from_slice(&1u32.to_be_bytes());
                other
            },
        };
        let open_token = state_token(open_state_id);
        let lock_token = state_token(lock_state_id);
        let stable_object = file.stable();
        let replay_result = ResOp::Open(NfsResult::Ok(OpenOk {
            state_id: open_state_id,
            change_info: ChangeInfo {
                atomic: true,
                before: 1,
                after: 2,
            },
            result_flags: OPEN4_RESULT_LOCKTYPE_POSIX,
            attributes_set: Vec::new(),
            delegation: OpenDelegation::None,
        }));
        let replay = ReplayRecord {
            client_id: previous_client_id,
            owner_kind: ReplayOwnerKind::Open,
            owner: Bytes::from_static(b"recovered-open-owner"),
            sequence_id: 3,
            request_digest: [0x33; 32],
            reply: encode_replay(&replay_result).unwrap(),
            current_object: Some(stable_object),
            renewal_source: ReplayRenewalSource::None,
        };
        let records = vec![
            (
                JournalKey::Client {
                    client_id: previous_client_id,
                },
                JournalRecord::Client(StableClientRecord {
                    client_id: previous_client_id,
                    owner: Bytes::from_static(b"recovered-client"),
                    verifier: [0x44; 8],
                    canonical_principal: Bytes::from(canonical_client_identity(&Principal::Anonymous)),
                    confirmed: true,
                }),
            ),
            (
                JournalKey::Open {
                    state_token: open_token,
                },
                JournalRecord::Open(StableOpenRecord {
                    state_token: open_token,
                    client_id: previous_client_id,
                    owner: Bytes::from_static(b"recovered-open-owner"),
                    object: stable_object,
                    share_access: ShareAccess::READ.bits(),
                    share_deny: ShareDeny::NONE.bits(),
                    contributions: vec![StableOpenContributionRecord {
                        share_access: ShareAccess::READ.bits(),
                        share_deny: ShareDeny::NONE.bits(),
                        count: 1,
                    }],
                }),
            ),
            (
                JournalKey::Lock {
                    state_token: lock_token,
                },
                JournalRecord::Lock(StableLockRecord {
                    state_token: lock_token,
                    open_state_token: open_token,
                    client_id: previous_client_id,
                    owner: Bytes::from_static(b"recovered-lock-owner"),
                    object: stable_object,
                    ranges: vec![StableLockRangeRecord {
                        offset: 10,
                        length: 20,
                        write: false,
                    }],
                }),
            ),
            (
                JournalKey::Replay {
                    client_id: previous_client_id,
                    owner_kind: ReplayOwnerKind::Open,
                    owner: Bytes::from_static(b"recovered-open-owner"),
                },
                JournalRecord::Replay(replay),
            ),
        ];
        (
            RecoveredStableState {
                previous_shutdown,
                previous_boot: Some(BootRecord {
                    verifier: [0x11; 8],
                    boot_tag: previous_boot_tag,
                    started_at_unix_seconds: 1,
                    clean_shutdown: previous_shutdown == PreviousShutdown::Clean,
                }),
                records,
            },
            previous_client_id,
            file,
        )
    }

    fn callback(address: &[u8]) -> CallbackClient {
        CallbackClient {
            program: 0x4000_0000,
            location: ClientAddress {
                netid: b"tcp".to_vec(),
                address: address.to_vec(),
            },
        }
    }

    fn set_client(owner: &[u8], verifier: [u8; 8], address: &[u8]) -> SetClientIdArgs {
        SetClientIdArgs {
            client: NfsClientId {
                verifier,
                id: owner.to_vec(),
            },
            callback: callback(address),
            callback_identifier: 7,
        }
    }

    fn gss_principal(canonical_name: &str, mechanism: &[u8], version: GssVersion, service: GssService) -> Principal {
        Principal::Gss {
            canonical_name: canonical_name.to_owned(),
            mechanism: mechanism.to_vec(),
            version,
            service,
        }
    }

    fn assert_no_releases<T>(transition: ClientTransition<T>) -> T {
        transition.result
    }

    async fn confirmed_client(runtime: &Nfs4Runtime, owner: &[u8], verifier: [u8; 8]) -> u64 {
        let SetClientIdResult::Ok(set) = assert_no_releases(
            runtime
                .set_client_id(&set_client(owner, verifier, b"127.0.0.1.8.1"), &Principal::Anonymous)
                .await,
        ) else {
            panic!("SETCLIENTID did not succeed");
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(set.client_id, set.confirmation, &Principal::Anonymous)
                    .await
            ),
            NfsStatus::Ok
        );
        set.client_id
    }

    fn test_file(file_id: u64) -> RuntimeFile {
        RuntimeFile {
            export_id: ExportId(7),
            object: ObjectKey { file_id, generation: 1 },
        }
    }

    async fn complete_open_request(
        runtime: &Nfs4Runtime,
        owner: &OpenOwner,
        file: RuntimeFile,
        sequence_id: u32,
        share_access: u32,
        share_deny: u32,
        digest_byte: u8,
    ) -> StateId {
        let reservation = match runtime
            .begin_open(
                owner,
                sequence_id,
                share_access,
                share_deny,
                false,
                OwnerRequestDigest([digest_byte; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected OPEN decision"),
        };
        let target = runtime
            .reserve_open_target(reservation, file)
            .unwrap_or_else(|_| panic!("target reservation failed"));
        let completion = runtime
            .complete_open(
                target,
                ChangeInfo {
                    atomic: true,
                    before: u64::from(sequence_id),
                    after: u64::from(sequence_id) + 1,
                },
                Vec::new(),
                OpenDelegation::None,
            )
            .await
            .expect("OPEN completion failed");
        let ResOp::Open(NfsResult::Ok(open)) = completion.result else {
            panic!("OPEN did not return a stateid");
        };
        open.state_id
    }

    async fn open_and_confirm(
        runtime: &Nfs4Runtime,
        owner: &OpenOwner,
        file: RuntimeFile,
        share_access: u32,
        share_deny: u32,
    ) -> StateId {
        let state_id = complete_open_request(runtime, owner, file, 1, share_access, share_deny, 0x11).await;
        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 2, OwnerRequestDigest([0x12; 32]), &Principal::Anonymous, true)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected OPEN_CONFIRM decision"),
        };
        let result = runtime.confirm_open(reservation).await.expect("OPEN_CONFIRM failed");
        let ResOp::OpenConfirm(NfsResult::Ok(state_id)) = result else {
            panic!("OPEN_CONFIRM did not return a stateid");
        };
        state_id
    }

    #[tokio::test]
    async fn setclientid_releases_a_stateless_principal_collision_without_reusing_the_incarnation() {
        let mut runtime_config = config();
        runtime_config.limits.max_clients = 1;
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let first = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"client", [1; 8], b"127.0.0.1.8.1"), &Principal::Anonymous)
                .await,
        );
        let SetClientIdResult::Ok(first) = first else {
            panic!("first SETCLIENTID did not succeed");
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(first.client_id, first.confirmation, &Principal::Anonymous)
                    .await
            ),
            NfsStatus::Ok
        );

        let update = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"client", [1; 8], b"127.0.0.1.9.9"), &Principal::Anonymous)
                .await,
        );
        let SetClientIdResult::Ok(update) = update else {
            panic!("callback update did not succeed");
        };
        assert_eq!(update.client_id, first.client_id);

        let other_principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"host".to_vec(),
        };
        let replacement = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"client", [1; 8], b"attacker"), &other_principal)
                .await,
        );
        let SetClientIdResult::Ok(replacement) = replacement else {
            panic!("stateless principal collision did not succeed");
        };
        assert_ne!(replacement.client_id, first.client_id);
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(replacement.client_id, replacement.confirmation, &other_principal)
                    .await
            ),
            NfsStatus::Ok
        );
        assert_eq!(runtime.validate_client(first.client_id, &Principal::Anonymous).await, NfsStatus::StaleClientId);
    }

    #[tokio::test]
    async fn setclientid_rejects_a_different_principal_while_open_state_is_active() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"stateful-client", [0x20; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"stateful-open-owner".to_vec(),
        };
        open_and_confirm(&runtime, &owner, test_file(200), ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let other_principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"other-host".to_vec(),
        };

        assert_eq!(
            assert_no_releases(
                runtime
                    .set_client_id(&set_client(b"stateful-client", [0x20; 8], b"attacker"), &other_principal)
                    .await
            ),
            SetClientIdResult::ClientIdInUse(callback(b"127.0.0.1.8.1").location)
        );
    }

    #[tokio::test]
    async fn confirming_new_incarnation_surfaces_every_retired_open_pin() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let old_client_id = confirmed_client(&runtime, b"restarting-client", [0x26; 8]).await;
        let owner = OpenOwner {
            client_id: old_client_id,
            owner: b"restarting-open-owner".to_vec(),
        };
        let file = test_file(202);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let pin = {
            let state = runtime.core.state.lock().unwrap();
            let record = state.stateids.identify(state_id).unwrap();
            let StatePayload::Open(open) = &record.payload else {
                panic!("OPEN state changed kind");
            };
            open.pin
        };

        let replacement = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"restarting-client", [0x27; 8], b"127.0.0.1.8.1"), &Principal::Anonymous)
                .await,
        );
        let SetClientIdResult::Ok(replacement) = replacement else {
            panic!("replacement SETCLIENTID did not succeed");
        };
        assert_ne!(replacement.client_id, old_client_id);
        let transition = runtime
            .confirm_client(replacement.client_id, replacement.confirmation, &Principal::Anonymous)
            .await;
        assert_eq!(transition.result, NfsStatus::Ok);
        let releases = runtime.pending_pin_releases();
        assert_eq!(releases.len(), 1);
        assert_eq!(
            releases[0].open,
            ReleasedOpen {
                client_id: old_client_id,
                file,
                pin,
            }
        );
        assert!(!runtime.is_open_pin_active(file, pin));
    }

    #[tokio::test]
    async fn setclientid_rejects_a_different_principal_while_recovered_state_is_reclaimable() {
        let (recovered, previous_client_id, _) = recovered_state(PreviousShutdown::Unclean);
        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let current = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"recovered-client", [0x44; 8], b"127.0.0.1.8.1"), &Principal::Anonymous)
                .await,
        );
        let SetClientIdResult::Ok(current) = current else {
            panic!("recovered SETCLIENTID did not succeed");
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(current.client_id, current.confirmation, &Principal::Anonymous)
                    .await
            ),
            NfsStatus::Ok
        );
        assert_eq!(
            runtime
                .previous_client_ids(current.client_id, &Principal::Anonymous)
                .await
                .unwrap(),
            vec![previous_client_id]
        );

        let other_principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"other-host".to_vec(),
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .set_client_id(&set_client(b"recovered-client", [0x44; 8], b"attacker"), &other_principal,)
                    .await
            ),
            SetClientIdResult::ClientIdInUse(callback(b"127.0.0.1.8.1").location)
        );
    }

    #[tokio::test]
    async fn first_open_registration_is_serialized_with_setclientid_replacement() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"opening-client", [0x22; 8]).await;
        let transition = runtime.client_state_transition_guard().await;
        let runtime_for_open = runtime.clone();
        let mut opening = tokio::spawn(async move {
            runtime_for_open
                .begin_open(
                    &OpenOwner {
                        client_id,
                        owner: b"opening-owner".to_vec(),
                    },
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    OwnerRequestDigest([0x22; 32]),
                    &Principal::Anonymous,
                )
                .await
        });

        assert!(tokio::time::timeout(Duration::from_millis(10), &mut opening).await.is_err());
        drop(transition);
        assert!(matches!(opening.await.unwrap(), StatefulDecision::Execute(_)));
    }

    #[tokio::test]
    async fn setclientid_replacement_rejects_a_client_with_a_live_open_reservation() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"reserved-open-client", [0x25; 8]).await;
        let reservation = match runtime
            .begin_open(
                &OpenOwner {
                    client_id,
                    owner: b"reserved-open-owner".to_vec(),
                },
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x26; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN reservation was not created"),
        };
        let other_principal = Principal::AuthSys {
            uid: 2,
            gid: 2,
            supplementary_gids: Vec::new(),
            machine_name: b"replacement-host".to_vec(),
        };

        let _transition_guard = runtime.client_state_transition_guard().await;
        assert_eq!(
            runtime
                .set_client_id(&set_client(b"reserved-open-client", [0x25; 8], b"attacker"), &other_principal,)
                .await
                .result,
            SetClientIdResult::ClientIdInUse(callback(b"127.0.0.1.8.1").location)
        );
        drop(reservation);
    }

    #[tokio::test]
    async fn lease_expiry_defers_revocation_while_an_open_owner_is_reserved() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"expiring-open-client", [0x23; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"expiring-open-owner".to_vec(),
        };
        let digest = OwnerRequestDigest([0x24; 32]);
        let reservation = match runtime
            .begin_open(
                &owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                digest,
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN reservation was not created"),
        };

        clock.advance(Duration::from_secs(10));
        assert!(runtime.expire_due().await.is_empty());
        {
            let clients = runtime.core.clients.lock().await;
            assert!(clients.pending_expiry.contains(&client_id));
            assert!(clients.client_owners.contains_key(&client_id));
        }
        assert!(runtime.client_has_live_owner_reservation(client_id));

        assert!(matches!(
            runtime.complete_open_error(reservation, NfsStatus::Access).await,
            ResOp::Open(NfsResult::Err(NfsStatus::Access))
        ));
        assert!(runtime.expire_due().await.is_empty());
        assert!(!runtime.client_has_live_owner_reservation(client_id));
        assert!(!runtime.core.clients.lock().await.client_owners.contains_key(&client_id));
    }

    #[tokio::test]
    async fn write_delegation_candidate_blocks_aliased_open_and_anonymous_io_until_last_guard_drops() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let first_client = confirmed_client(&runtime, b"candidate-write-client", [0x27; 8]).await;
        let second_client = confirmed_client(&runtime, b"aliased-open-client", [0x28; 8]).await;
        let file = test_file(203);
        let first_owner = OpenOwner {
            client_id: first_client,
            owner: b"candidate-write-owner".to_vec(),
        };
        let first = match runtime
            .begin_open(
                &first_owner,
                1,
                ShareAccess::BOTH.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x29; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("first OPEN reservation was not created"),
        };
        let mut first_target = runtime
            .reserve_open_target(first, file)
            .unwrap_or_else(|_| panic!("first target reservation failed"));
        let in_flight_read = runtime
            .validate_io(ANONYMOUS_STATE_ID, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
            .await
            .expect("anonymous read should be admitted before a candidate exists");
        assert!(matches!(
            runtime.reserve_delegation_eligibility(&mut first_target, first_client, DelegationKind::Write),
            Err(NfsStatus::Delay)
        ));
        drop(in_flight_read);
        let detached_guard = runtime
            .reserve_delegation_eligibility(&mut first_target, first_client, DelegationKind::Write)
            .expect("write delegation should initially be eligible");

        assert!(matches!(
            runtime
                .validate_io(ANONYMOUS_STATE_ID, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
                .await,
            Err(NfsStatus::Delay)
        ));
        assert!(runtime
            .begin_delegation_access(file, Some(first_client), DelegationKind::Write, true)
            .is_ok());
        drop(first_target);

        let aliased_owner = OpenOwner {
            client_id: second_client,
            owner: b"aliased-open-owner".to_vec(),
        };
        let aliased = match runtime
            .begin_open(
                &aliased_owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x2a; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("aliased OPEN reservation was not created"),
        };
        let (aliased, status) = match runtime.reserve_open_target(aliased, file) {
            Err(error) => error,
            Ok(_) => panic!("a second namespace edge to the same object must observe the candidate"),
        };
        assert_eq!(status, NfsStatus::Delay);
        drop(aliased);

        drop(detached_guard);
        let retry = match runtime
            .begin_open(
                &aliased_owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x2a; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("aliased OPEN retry was not admitted"),
        };
        drop(
            runtime
                .reserve_open_target(retry, file)
                .unwrap_or_else(|_| panic!("aliased target retry failed")),
        );
    }

    #[tokio::test]
    async fn read_delegation_candidate_allows_read_but_blocks_write_from_other_clients() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let first_client = confirmed_client(&runtime, b"candidate-read-client", [0x2b; 8]).await;
        let second_client = confirmed_client(&runtime, b"concurrent-read-client", [0x2c; 8]).await;
        let file = test_file(204);
        let first = match runtime
            .begin_open(
                &OpenOwner {
                    client_id: first_client,
                    owner: b"candidate-read-owner".to_vec(),
                },
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x2d; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("candidate OPEN reservation was not created"),
        };
        let mut first_target = runtime
            .reserve_open_target(first, file)
            .unwrap_or_else(|_| panic!("candidate target reservation failed"));
        let _guard = runtime
            .reserve_delegation_eligibility(&mut first_target, first_client, DelegationKind::Read)
            .expect("read delegation should initially be eligible");

        let read_permit = runtime
            .validate_io(ANONYMOUS_STATE_ID, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
            .await
            .expect("a read candidate permits concurrent reads");
        drop(read_permit);
        assert!(matches!(
            runtime
                .validate_io(ANONYMOUS_STATE_ID, file, IoAccess::Write, 0, 1, &Principal::Anonymous)
                .await,
            Err(NfsStatus::Delay)
        ));

        let read = match runtime
            .begin_open(
                &OpenOwner {
                    client_id: second_client,
                    owner: b"concurrent-read-owner".to_vec(),
                },
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x2e; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("concurrent read OPEN reservation was not created"),
        };
        drop(
            runtime
                .reserve_open_target(read, file)
                .unwrap_or_else(|_| panic!("concurrent read target should be admitted")),
        );

        let write = match runtime
            .begin_open(
                &OpenOwner {
                    client_id: second_client,
                    owner: b"concurrent-write-owner".to_vec(),
                },
                1,
                ShareAccess::WRITE.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x2f; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("concurrent write OPEN reservation was not created"),
        };
        let (write, status) = match runtime.reserve_open_target(write, file) {
            Err(error) => error,
            Ok(_) => panic!("a read delegation candidate must block another client's write"),
        };
        assert_eq!(status, NfsStatus::Delay);
        drop(write);
        drop(first_target);
    }

    #[tokio::test]
    async fn recall_before_lock_access_reservation_blocks_a_competing_delegation_candidate() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let candidate_client = confirmed_client(&runtime, b"lock-race-candidate", [0x30; 8]).await;
        let locking_client = confirmed_client(&runtime, b"lock-race-writer", [0x31; 8]).await;
        let file = test_file(205);
        let open = match runtime
            .begin_open(
                &OpenOwner {
                    client_id: candidate_client,
                    owner: b"lock-race-candidate-owner".to_vec(),
                },
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x32; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("candidate OPEN reservation was not created"),
        };
        let mut target = runtime
            .reserve_open_target(open, file)
            .unwrap_or_else(|_| panic!("candidate target reservation failed"));

        let lock_access = runtime
            .begin_delegation_access(file, Some(locking_client), DelegationKind::Write, false)
            .expect("recall-before-LOCK admission should be reserved");
        assert!(matches!(
            runtime.reserve_delegation_eligibility(&mut target, candidate_client, DelegationKind::Read),
            Err(NfsStatus::Delay)
        ));

        drop(lock_access);
        let eligibility = runtime
            .reserve_delegation_eligibility(&mut target, candidate_client, DelegationKind::Read)
            .expect("candidate may be admitted only after the LOCK reservation is released");
        drop(eligibility);
        drop(target);
    }

    #[tokio::test]
    async fn delegation_io_permit_excludes_a_conflicting_candidate_until_backend_io_finishes() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let delegated_client = confirmed_client(&runtime, b"delegated-io-client", [0x33; 8]).await;
        let candidate_client = confirmed_client(&runtime, b"delegated-io-candidate", [0x34; 8]).await;
        let file = test_file(206);
        let delegated_io = runtime
            .reserve_delegation_io(file, delegated_client, IoAccess::Write)
            .await
            .expect("validated delegated WRITE should reserve its backend-I/O window");
        let open = match runtime
            .begin_open(
                &OpenOwner {
                    client_id: candidate_client,
                    owner: b"delegated-io-candidate-owner".to_vec(),
                },
                1,
                ShareAccess::BOTH.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x35; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("candidate OPEN reservation was not created"),
        };
        let mut target = runtime
            .reserve_open_target(open, file)
            .unwrap_or_else(|_| panic!("candidate target reservation failed"));
        assert!(matches!(
            runtime.reserve_delegation_eligibility(&mut target, candidate_client, DelegationKind::Write),
            Err(NfsStatus::Delay)
        ));

        drop(delegated_io);
        let eligibility = runtime
            .reserve_delegation_eligibility(&mut target, candidate_client, DelegationKind::Write)
            .expect("candidate may be admitted after delegated backend I/O finishes");
        let same_client = runtime
            .reserve_delegation_io(file, candidate_client, IoAccess::Write)
            .await
            .expect("candidate client's own delegated I/O remains compatible");
        assert!(matches!(
            runtime.reserve_delegation_io(file, delegated_client, IoAccess::Write).await,
            Err(NfsStatus::Delay)
        ));

        drop(same_client);
        drop(eligibility);
        drop(target);
    }

    #[tokio::test]
    async fn setclientid_accepts_a_different_principal_after_expired_state_is_revoked() {
        let clock = Arc::new(ManualLeaseClock::default());
        let mut runtime_config = config();
        runtime_config.limits.max_clients = 1;
        let runtime = Nfs4Runtime::with_clock(runtime_config, clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"expired-client", [0x21; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"expired-open-owner".to_vec(),
        };
        open_and_confirm(&runtime, &owner, test_file(201), ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;

        clock.advance(Duration::from_secs(10));
        assert_eq!(runtime.expire_due().await.len(), 1);

        let other_principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"replacement-host".to_vec(),
        };
        let replacement = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"expired-client", [0x21; 8], b"replacement"), &other_principal)
                .await,
        );
        let SetClientIdResult::Ok(replacement) = replacement else {
            panic!("expired client identity was not reusable");
        };
        assert_ne!(replacement.client_id, client_id);
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(replacement.client_id, replacement.confirmation, &other_principal)
                    .await
            ),
            NfsStatus::Ok
        );
    }

    #[tokio::test]
    async fn active_stateid_io_rejects_a_different_principal_with_access() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"stateid-owner", [0x30; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"open-owner".to_vec(),
        };
        let file = test_file(300);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;
        let other_principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"other-host".to_vec(),
        };

        assert!(matches!(
            runtime
                .validate_io(state_id, file, IoAccess::Write, 0, 1, &other_principal)
                .await,
            Err(NfsStatus::Access)
        ));
        assert_eq!(runtime.validate_client(client_id, &other_principal).await, NfsStatus::StaleClientId);
    }

    #[tokio::test]
    async fn gss_client_identity_accepts_flavor_changes_but_distinguishes_name_or_mechanism() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let setclientid_principal =
            gss_principal("nfs/client@example.test", KERBEROS_MECHANISM, GssVersion::V1, GssService::Privacy);
        let operation_principal =
            gss_principal("nfs/client@example.test", KERBEROS_MECHANISM, GssVersion::V2, GssService::Integrity);
        let first = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"gss-client", [0x31; 8], b"127.0.0.1.8.1"), &setclientid_principal)
                .await,
        );
        let SetClientIdResult::Ok(first) = first else {
            panic!("GSS SETCLIENTID did not succeed");
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(first.client_id, first.confirmation, &operation_principal)
                    .await
            ),
            NfsStatus::Ok
        );
        assert_eq!(runtime.renew(first.client_id, &operation_principal).await, NfsStatus::Ok);

        let flavor_update = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"gss-client", [0x31; 8], b"127.0.0.1.9.9"), &operation_principal)
                .await,
        );
        let SetClientIdResult::Ok(flavor_update) = flavor_update else {
            panic!("same GSS identity was rejected after a flavor change");
        };
        assert_eq!(flavor_update.client_id, first.client_id);

        let different_name =
            gss_principal("nfs/other@example.test", KERBEROS_MECHANISM, GssVersion::V2, GssService::Integrity);
        assert_eq!(runtime.validate_client(first.client_id, &different_name).await, NfsStatus::StaleClientId);

        let different_mechanism =
            gss_principal("nfs/client@example.test", b"different-mechanism", GssVersion::V1, GssService::Privacy);
        assert_eq!(runtime.validate_client(first.client_id, &different_mechanism).await, NfsStatus::StaleClientId);

        let replacement = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"gss-client", [0x31; 8], b"attacker"), &different_name)
                .await,
        );
        let SetClientIdResult::Ok(replacement) = replacement else {
            panic!("stateless GSS identity collision did not succeed");
        };
        assert_ne!(replacement.client_id, first.client_id);
    }

    #[tokio::test]
    async fn recovered_gss_client_identity_is_flavor_neutral() {
        let recovered_principal =
            gss_principal("nfs/recovered@example.test", KERBEROS_MECHANISM, GssVersion::V1, GssService::Privacy);
        let current_principal =
            gss_principal("nfs/recovered@example.test", KERBEROS_MECHANISM, GssVersion::V2, GssService::Integrity);
        assert_eq!(canonical_client_identity(&recovered_principal), canonical_client_identity(&current_principal));

        let (mut recovered, previous_client_id, _file) = recovered_state(PreviousShutdown::Unclean);
        let client = recovered
            .records
            .iter_mut()
            .find_map(|(_, record)| match record {
                JournalRecord::Client(client) => Some(client),
                _ => None,
            })
            .expect("recovery fixture contains a client");
        client.canonical_principal = Bytes::from(canonical_client_identity(&recovered_principal));

        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let current = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"recovered-client", [0x44; 8], b"127.0.0.1.8.1"), &current_principal)
                .await,
        );
        let SetClientIdResult::Ok(current) = current else {
            panic!("recovered GSS SETCLIENTID did not succeed");
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(current.client_id, current.confirmation, &current_principal)
                    .await
            ),
            NfsStatus::Ok
        );
        assert_eq!(
            runtime
                .previous_client_ids(current.client_id, &current_principal)
                .await
                .unwrap(),
            vec![previous_client_id]
        );
    }

    #[tokio::test]
    async fn confirmed_callback_preserves_exact_setclientid_gss_flavor() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let setclientid_principal =
            gss_principal("nfs/callback@example.test", KERBEROS_MECHANISM, GssVersion::V1, GssService::Privacy);
        let confirm_principal =
            gss_principal("nfs/callback@example.test", KERBEROS_MECHANISM, GssVersion::V2, GssService::Integrity);
        let set = assert_no_releases(
            runtime
                .set_client_id(&set_client(b"callback-gss-client", [0x41; 8], b"127.0.0.1.8.1"), &setclientid_principal)
                .await,
        );
        let SetClientIdResult::Ok(set) = set else {
            panic!("callback GSS SETCLIENTID did not succeed");
        };
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(set.client_id, set.confirmation, &confirm_principal)
                    .await
            ),
            NfsStatus::Ok
        );

        let descriptor = runtime
            .confirmed_client_callback(set.client_id, &confirm_principal)
            .await
            .unwrap();
        assert_eq!(descriptor.setclientid_principal, setclientid_principal);
    }

    #[tokio::test]
    async fn confirmation_does_not_start_lease_and_first_renew_does() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"lease-client", [2; 8]).await;
        {
            let clients = runtime.core.clients.lock().await;
            assert!(!clients.leases.is_active(&client_id));
        }

        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        clock.advance(Duration::from_secs(10));
        assert!(runtime.expire_due().await.is_empty());
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Expired);
    }

    #[tokio::test]
    async fn moved_export_obligations_gate_renew_open_and_io_until_each_probe_completes() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock).unwrap();
        let client_id = confirmed_client(&runtime, b"moved-client", [0x21; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"existing-open".to_vec(),
        };
        let file = test_file(321);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;

        let first_export = file.export_id;
        let second_export = ExportId(8);
        runtime
            .note_moved_export(client_id, first_export, &Principal::Anonymous)
            .await
            .unwrap();
        runtime
            .note_moved_export(client_id, second_export, &Principal::Anonymous)
            .await
            .unwrap();

        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);
        assert!(matches!(
            runtime
                .validate_io(state_id, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
                .await,
            Err(NfsStatus::LeaseMoved)
        ));
        assert!(matches!(
            runtime
                .validate_io(state_id, file, IoAccess::Write, 0, 1, &Principal::Anonymous)
                .await,
            Err(NfsStatus::LeaseMoved)
        ));

        let new_owner = OpenOwner {
            client_id,
            owner: b"new-open".to_vec(),
        };
        assert!(matches!(
            runtime
                .begin_open(
                    &new_owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    OwnerRequestDigest([0x31; 32]),
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Error(NfsStatus::LeaseMoved)
        ));

        runtime
            .complete_moved_export_probes(client_id, &HashSet::from([ExportId(9)]), &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);

        runtime
            .complete_moved_export_probes(client_id, &HashSet::from([first_export]), &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);

        runtime
            .complete_moved_export_probes(client_id, &HashSet::from([second_export]), &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let permit = runtime
            .validate_io(state_id, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(permit.client_id, Some(client_id));
    }

    #[tokio::test]
    async fn moved_export_notification_times_out_after_two_lease_periods_without_refreshing() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"legacy-moved-client", [0x22; 8]).await;
        runtime
            .note_moved_export(client_id, ExportId(7), &Principal::Anonymous)
            .await
            .unwrap();

        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);
        clock.advance(Duration::from_secs(9));
        runtime
            .note_moved_export(client_id, ExportId(7), &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);
        clock.advance(Duration::from_secs(9));
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);
        clock.advance(Duration::from_secs(2));
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        runtime
            .note_moved_export(client_id, ExportId(7), &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn moved_export_obligations_are_removed_with_expired_and_replaced_clients() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let expired_client = confirmed_client(&runtime, b"expiring-moved-client", [0x23; 8]).await;
        runtime
            .note_moved_export(expired_client, ExportId(7), &Principal::Anonymous)
            .await
            .unwrap();
        assert_eq!(runtime.renew(expired_client, &Principal::Anonymous).await, NfsStatus::LeaseMoved);
        clock.advance(Duration::from_secs(10));
        assert!(runtime.expire_due().await.is_empty());
        {
            let clients = runtime.core.clients.lock().await;
            assert!(!clients.moved_leases.by_client.contains_key(&expired_client));
        }

        let replaced_client = confirmed_client(&runtime, b"replaced-moved-client", [0x24; 8]).await;
        runtime
            .note_moved_export(replaced_client, ExportId(8), &Principal::Anonymous)
            .await
            .unwrap();
        let SetClientIdResult::Ok(replacement) = assert_no_releases(
            runtime
                .set_client_id(
                    &set_client(b"replaced-moved-client", [0x25; 8], b"127.0.0.1.8.1"),
                    &Principal::Anonymous,
                )
                .await,
        ) else {
            panic!("replacement SETCLIENTID did not succeed");
        };
        assert_ne!(replacement.client_id, replaced_client);
        assert_eq!(
            assert_no_releases(
                runtime
                    .confirm_client(replacement.client_id, replacement.confirmation, &Principal::Anonymous)
                    .await
            ),
            NfsStatus::Ok
        );
        let clients = runtime.core.clients.lock().await;
        assert!(!clients.moved_leases.by_client.contains_key(&replaced_client));
    }

    #[test]
    fn moved_export_tracker_is_explicitly_bounded() {
        let mut tracker = MovedLeaseTracker::new(1, Duration::from_secs(10));
        tracker.note(1, ExportId(1), Duration::ZERO).unwrap();
        assert_eq!(tracker.note(1, ExportId(2), Duration::from_secs(1)), Err(NfsStatus::Resource));
        assert!(!tracker.has_live(1, Duration::from_secs(20)));
        tracker.note(1, ExportId(1), Duration::from_secs(20)).unwrap();
        assert!(!tracker.has_live(1, Duration::from_secs(20)));
        assert_eq!(tracker.note(1, ExportId(2), Duration::from_secs(20)), Err(NfsStatus::Resource));
        assert_eq!(tracker.entries, 1);
    }

    #[tokio::test]
    async fn open_owner_replay_is_xid_independent_and_restores_current_file() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"replay-client", [3; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"owner".to_vec(),
        };
        let digest = OwnerRequestDigest([0x44; 32]);
        let reservation = match runtime.begin_open(&owner, 9, 1, 0, false, digest, &Principal::Anonymous).await {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected initial decision"),
        };
        let file = RuntimeFile {
            export_id: ExportId(7),
            object: ObjectKey {
                file_id: 99,
                generation: 1,
            },
        };
        let target = match runtime.reserve_open_target(reservation, file) {
            Ok(target) => target,
            Err(_) => panic!("target reservation failed"),
        };
        let completion = runtime
            .complete_open(
                target,
                ChangeInfo {
                    atomic: true,
                    before: 10,
                    after: 11,
                },
                Vec::new(),
                OpenDelegation::None,
            )
            .await
            .unwrap();

        match runtime.begin_open(&owner, 9, 1, 0, false, digest, &Principal::Anonymous).await {
            StatefulDecision::Replay { result, effect } => {
                assert_eq!(result, completion.result);
                assert_eq!(effect.current_file, Some(file));
            },
            _ => panic!("unexpected replay decision"),
        }
        assert!(matches!(
            runtime
                .begin_open(&owner, 9, 1, 0, false, OwnerRequestDigest([0x45; 32]), &Principal::Anonymous,)
                .await,
            StatefulDecision::Error(NfsStatus::BadSequenceId)
        ));
    }

    #[tokio::test]
    async fn consecutive_open_upgrades_advance_the_indexed_stateid() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"upgrade-client", [0x31; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"upgrade-owner".to_vec(),
        };
        let file = test_file(97);
        let first = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let second =
            complete_open_request(&runtime, &owner, file, 3, ShareAccess::WRITE.bits(), ShareDeny::NONE.bits(), 0x32)
                .await;
        let third =
            complete_open_request(&runtime, &owner, file, 4, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits(), 0x33)
                .await;

        assert_eq!(first.other, second.other);
        assert_eq!(second.other, third.other);
        assert_ne!(first.sequence_id, second.sequence_id);
        assert_ne!(second.sequence_id, third.sequence_id);
        assert_eq!(
            runtime
                .core
                .state
                .lock()
                .unwrap()
                .open_by_owner_file
                .get(&(OpenOwnerKey::from(&owner), file)),
            Some(&third)
        );
    }

    #[tokio::test]
    async fn open_target_drop_cleans_pending_state_after_owner_extraction() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"target-drop-client", [0x36; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"target-drop-owner".to_vec(),
        };
        let file = test_file(970);
        let reservation = match runtime
            .begin_open(
                &owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x37; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN reservation was not created"),
        };
        let mut target = runtime
            .reserve_open_target(reservation, file)
            .unwrap_or_else(|_| panic!("target reservation failed"));
        let owner_guard = target.owner.take().expect("target owns the owner reservation");

        drop(target);
        {
            let shard = runtime.core.files[shard_for(&file, runtime.core.files.len())].lock().unwrap();
            assert!(
                shard.files.get(&file).is_none_or(|file| file.pending_opens.is_empty()),
                "target cleanup must not depend on retaining the owner guard"
            );
        }
        assert_eq!(runtime.core.state.lock().unwrap().reserved_states, 1);

        drop(owner_guard);
        assert_eq!(runtime.core.state.lock().unwrap().reserved_states, 0);
    }

    #[tokio::test]
    async fn failed_open_persistence_retires_pending_state_and_allows_retry() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"runtime-open-persist-failure"[..]);
        let journal = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"persist-failure-client", [0x38; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"persist-failure-owner".to_vec(),
        };
        let file = test_file(971);
        let digest = OwnerRequestDigest([0x39; 32]);
        let reservation = match runtime
            .begin_open(
                &owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                digest,
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN reservation was not created"),
        };
        let target = runtime
            .reserve_open_target(reservation, file)
            .unwrap_or_else(|_| panic!("target reservation failed"));

        store.fail_next_commit(&scope);
        assert!(matches!(
            runtime
                .complete_open(
                    target,
                    ChangeInfo {
                        atomic: true,
                        before: 1,
                        after: 2,
                    },
                    Vec::new(),
                    OpenDelegation::None,
                )
                .await,
            Err(NfsStatus::Resource)
        ));
        {
            let state = runtime.core.state.lock().unwrap();
            assert_eq!(state.stateids.len(), 0);
            assert_eq!(state.reserved_states, 0);
            assert!(!state.open_by_owner_file.contains_key(&(OpenOwnerKey::from(&owner), file)));
        }
        {
            let shard = runtime.core.files[shard_for(&file, runtime.core.files.len())].lock().unwrap();
            assert!(shard.files.get(&file).is_none_or(|file| file.pending_opens.is_empty()));
        }
        assert!(matches!(
            runtime
                .begin_open(
                    &owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    digest,
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Execute(_)
        ));
    }

    #[tokio::test]
    async fn cancelled_open_caller_drains_ambiguous_persistence_and_commits_state() {
        let store = Arc::new(CommitAmbiguityStore::default());
        let scope = StableScope::from(&b"runtime-open-persist-cancel"[..]);
        let journal = StableJournal::initialize(store.clone(), scope, 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        let journal = Arc::new(AsyncMutex::new(journal));
        runtime_config.stable_journal = Some(journal.clone());
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"persist-cancel-client", [0x3a; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"persist-cancel-owner".to_vec(),
        };
        let file = test_file(972);
        let digest = OwnerRequestDigest([0x3b; 32]);
        let reservation = match runtime
            .begin_open(
                &owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                digest,
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN reservation was not created"),
        };
        let target = runtime
            .reserve_open_target(reservation, file)
            .unwrap_or_else(|_| panic!("target reservation failed"));
        let pin = target.pin();

        store.block_next_commit_after_apply();
        let completing_runtime = runtime.clone();
        let completion = tokio::spawn(async move {
            completing_runtime
                .complete_open(
                    target,
                    ChangeInfo {
                        atomic: true,
                        before: 1,
                        after: 2,
                    },
                    Vec::new(),
                    OpenDelegation::None,
                )
                .await
        });
        store.wait_until_commit_applied().await;
        assert_eq!(
            runtime.core.state.lock().unwrap().stateids.len(),
            1,
            "OPEN remains pending after the CAS applies but before it returns"
        );

        completion.abort();
        assert!(completion.await.unwrap_err().is_cancelled());
        let draining_runtime = runtime.clone();
        let mut draining = tokio::spawn(async move {
            draining_runtime.wait_critical().await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut draining).await.is_err(),
            "critical drain must wait for the applied-but-not-returned CAS"
        );
        store.allow_commit_to_return();
        draining.await.unwrap();
        let state_id = {
            let mut committed = None;
            for _ in 0..128 {
                committed = runtime
                    .core
                    .state
                    .lock()
                    .unwrap()
                    .open_by_owner_file
                    .get(&(OpenOwnerKey::from(&owner), file))
                    .copied();
                if committed.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            committed.expect("detached OPEN completion must drain after caller cancellation")
        };
        {
            let state = runtime.core.state.lock().unwrap();
            assert_eq!(state.stateids.len(), 1);
            assert_eq!(state.reserved_states, 0);
            assert_eq!(state.open_by_owner_file.get(&(OpenOwnerKey::from(&owner), file)), Some(&state_id));
        }
        assert!(runtime.is_open_pin_active(file, pin));
        {
            let shard = runtime.core.files[shard_for(&file, runtime.core.files.len())].lock().unwrap();
            let file = shard.files.get(&file).expect("committed OPEN installs share state");
            assert!(file.pending_opens.is_empty());
            assert_eq!(file.shares.reservations().len(), 1);
        }
        assert!(matches!(
            runtime
                .begin_open(
                    &owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    digest,
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Replay {
                result: ResOp::Open(NfsResult::Ok(_)),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn cancelled_open_error_caller_drains_ambiguous_owner_replay_commit() {
        let store = Arc::new(CommitAmbiguityStore::default());
        let scope = StableScope::from(&b"runtime-open-error-persist-cancel"[..]);
        let journal = StableJournal::initialize(store.clone(), scope, 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"error-cancel-client", [0x3c; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"error-cancel-owner".to_vec(),
        };
        let digest = OwnerRequestDigest([0x3d; 32]);
        let reservation = match runtime
            .begin_open(
                &owner,
                1,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                digest,
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN reservation was not created"),
        };

        store.block_next_commit_after_apply();
        let completing_runtime = runtime.clone();
        let completion =
            tokio::spawn(async move { completing_runtime.complete_open_error(reservation, NfsStatus::Access).await });
        store.wait_until_commit_applied().await;

        completion.abort();
        assert!(completion.await.unwrap_err().is_cancelled());
        let draining_runtime = runtime.clone();
        let mut draining = tokio::spawn(async move {
            draining_runtime.wait_critical().await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut draining).await.is_err(),
            "critical owner-error drain must wait for the applied-but-not-returned CAS"
        );
        store.allow_commit_to_return();
        draining.await.unwrap();

        assert_eq!(runtime.core.state.lock().unwrap().reserved_states, 0);
        assert!(matches!(
            runtime
                .begin_open(
                    &owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    digest,
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Replay {
                result: ResOp::Open(NfsResult::Err(NfsStatus::Access)),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn cancelled_close_caller_drains_ambiguous_persistence_into_release_outbox() {
        let store = Arc::new(CommitAmbiguityStore::default());
        let scope = StableScope::from(&b"runtime-close-persist-cancel"[..]);
        let journal = StableJournal::initialize(store.clone(), scope, 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"close-cancel-client", [0x41; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"close-cancel-owner".to_vec(),
        };
        let file = test_file(975);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let digest = OwnerRequestDigest([0x42; 32]);
        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 3, digest, &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("CLOSE reservation was not created"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();
        let pin = prepared.pin();

        store.block_next_commit_after_apply();
        let closing_runtime = runtime.clone();
        let completion = tokio::spawn(async move { closing_runtime.close_open(prepared).await });
        store.wait_until_commit_applied().await;
        assert!(runtime.is_open_pin_active(file, pin));
        assert!(runtime.pending_pin_releases().is_empty());

        completion.abort();
        assert!(completion.await.unwrap_err().is_cancelled());
        let draining_runtime = runtime.clone();
        let mut draining = tokio::spawn(async move {
            draining_runtime.wait_critical().await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut draining).await.is_err(),
            "critical CLOSE drain must wait for the applied-but-not-returned CAS"
        );
        store.allow_commit_to_return();
        draining.await.unwrap();

        assert!(!runtime.is_open_pin_active(file, pin));
        let releases = runtime.pending_pin_releases();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].open, ReleasedOpen { client_id, file, pin });
        assert!(matches!(
            runtime
                .begin_open_state_operation(state_id, file, 3, digest, &Principal::Anonymous, false)
                .await,
            StatefulDecision::Replay {
                result: ResOp::Close(NfsResult::Ok(_)),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn setclientid_confirm_delays_while_critical_close_is_ambiguous() {
        let store = Arc::new(CommitAmbiguityStore::default());
        let scope = StableScope::from(&b"runtime-confirm-close-race"[..]);
        let journal = StableJournal::initialize(store.clone(), scope, 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"confirm-close-client", [0x43; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"confirm-close-owner".to_vec(),
        };
        let file = test_file(976);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let replacement = runtime
            .set_client_id(&set_client(b"confirm-close-client", [0x44; 8], b"127.0.0.1.8.1"), &Principal::Anonymous)
            .await
            .result;
        let SetClientIdResult::Ok(replacement) = replacement else {
            panic!("replacement SETCLIENTID did not succeed");
        };

        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 3, OwnerRequestDigest([0x45; 32]), &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("CLOSE reservation was not created"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();
        store.block_next_commit_after_apply();
        let closing_runtime = runtime.clone();
        let closing = tokio::spawn(async move { closing_runtime.close_open(prepared).await });
        store.wait_until_commit_applied().await;

        assert_eq!(
            runtime
                .confirm_client(replacement.client_id, replacement.confirmation, &Principal::Anonymous)
                .await
                .result,
            NfsStatus::Delay
        );
        assert!(runtime.is_open_pin_active(file, {
            let state = runtime.core.state.lock().unwrap();
            let record = state.stateids.identify(state_id).unwrap();
            let StatePayload::Open(open) = &record.payload else {
                panic!("OPEN state changed kind");
            };
            open.pin
        }));

        store.allow_commit_to_return();
        closing.await.unwrap().unwrap();
        assert_eq!(
            runtime
                .confirm_client(replacement.client_id, replacement.confirmation, &Principal::Anonymous)
                .await
                .result,
            NfsStatus::Ok
        );
        assert_eq!(runtime.pending_pin_releases().len(), 1);
    }

    #[tokio::test]
    async fn close_replays_after_the_stateid_is_retired() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"close-replay-client", [0x34; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"close-replay-owner".to_vec(),
        };
        let file = test_file(98);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;
        let digest = OwnerRequestDigest([0x35; 32]);
        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 3, digest, &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("initial CLOSE did not execute"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();
        let pin = prepared.pin();
        let completion = runtime.close_open(prepared).await.unwrap();
        let releases = runtime.pending_pin_releases();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].open, ReleasedOpen { client_id, file, pin });
        let result = completion.result;

        match runtime
            .begin_open_state_operation(state_id, file, 3, digest, &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Replay { result: replay, effect } => {
                assert_eq!(replay, result);
                assert_eq!(effect, ReplayEffect::default());
            },
            _ => panic!("unexpected CLOSE replay decision"),
        }
    }

    #[tokio::test]
    async fn failed_close_persistence_keeps_open_state_active_and_allows_retry() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"runtime-close-persist-failure"[..]);
        let journal = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"close-persist-client", [0x3c; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"close-persist-owner".to_vec(),
        };
        let file = test_file(973);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let digest = OwnerRequestDigest([0x3d; 32]);
        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 3, digest, &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("CLOSE reservation was not created"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();

        store.fail_next_commit(&scope);
        assert!(matches!(runtime.close_open(prepared).await, Err(NfsStatus::Resource)));
        drop(
            runtime
                .validate_io(state_id, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
                .await
                .expect("failed durable CLOSE must leave the OPEN active"),
        );
        assert!(matches!(
            runtime
                .begin_open_state_operation(state_id, file, 3, digest, &Principal::Anonymous, false)
                .await,
            StatefulDecision::Execute(_)
        ));
    }

    #[tokio::test]
    async fn pin_release_outbox_reserves_state_capacity_until_acknowledged() {
        let mut runtime_config = config();
        runtime_config.limits.max_state_objects = 1;
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"release-outbox-client", [0x3e; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"release-outbox-owner".to_vec(),
        };
        let file = test_file(974);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 3, OwnerRequestDigest([0x3f; 32]), &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("CLOSE reservation was not created"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();
        let pin = prepared.pin();
        runtime.close_open(prepared).await.unwrap();
        assert!(!runtime.is_open_pin_active(file, pin));
        let releases = runtime.pending_pin_releases();
        assert_eq!(releases.len(), 1);

        let next_owner = OpenOwner {
            client_id,
            owner: b"next-owner".to_vec(),
        };
        assert!(matches!(
            runtime
                .begin_open(
                    &next_owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    OwnerRequestDigest([0x40; 32]),
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Error(NfsStatus::Resource)
        ));

        assert!(runtime.acknowledge_pin_release(releases[0].release_id));
        assert!(runtime.pending_pin_releases().is_empty());
        assert!(matches!(
            runtime
                .begin_open(
                    &next_owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    OwnerRequestDigest([0x40; 32]),
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Execute(_)
        ));
    }

    #[tokio::test]
    async fn open_downgrade_requires_an_actual_open_subset() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"downgrade-client", [4; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"open-owner".to_vec(),
        };
        let file = test_file(100);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;

        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 3, OwnerRequestDigest([0x13; 32]), &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected OPEN_DOWNGRADE decision"),
        };
        assert_eq!(
            runtime
                .downgrade_open(reservation, ShareAccess::READ.bits(), ShareDeny::NONE.bits())
                .await
                .unwrap(),
            ResOp::OpenDowngrade(NfsResult::Err(NfsStatus::Invalid))
        );

        // Adding an actual READ contribution makes the same target a valid
        // union.  The failed downgrade consumed seqid 3 but did not alter
        // the contribution history or stateid.
        let state_id =
            complete_open_request(&runtime, &owner, file, 4, ShareAccess::READ.bits(), ShareDeny::NONE.bits(), 0x14)
                .await;
        let reservation = match runtime
            .begin_open_state_operation(state_id, file, 5, OwnerRequestDigest([0x15; 32]), &Principal::Anonymous, false)
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected OPEN_DOWNGRADE decision"),
        };
        assert!(matches!(
            runtime
                .downgrade_open(reservation, ShareAccess::READ.bits(), ShareDeny::NONE.bits())
                .await
                .unwrap(),
            ResOp::OpenDowngrade(NfsResult::Ok(_))
        ));
    }

    #[tokio::test]
    async fn repeated_open_contributions_fail_with_resource_before_completion() {
        let mut runtime_config = config();
        runtime_config.limits.max_open_contributions_per_state = 2;
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"bounded-open-client", [0x51; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"bounded-open-owner".to_vec(),
        };
        let file = test_file(105);
        open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        complete_open_request(&runtime, &owner, file, 3, ShareAccess::READ.bits(), ShareDeny::NONE.bits(), 0x52).await;

        let reservation = match runtime
            .begin_open(
                &owner,
                4,
                ShareAccess::READ.bits(),
                ShareDeny::NONE.bits(),
                false,
                OwnerRequestDigest([0x53; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("bounded repeated OPEN should reach target preflight"),
        };
        let (reservation, status) = match runtime.reserve_open_target(reservation, file) {
            Err(error) => error,
            Ok(_) => panic!("the contribution limit must reject a third repeated OPEN"),
        };
        assert_eq!(status, NfsStatus::Resource);
        assert_eq!(
            runtime.complete_open_error(reservation, status).await,
            ResOp::Open(NfsResult::Err(NfsStatus::Resource))
        );
        assert_eq!(runtime.core.state.lock().unwrap().reserved_states, 0);

        let shard = runtime.core.files[shard_for(&file, runtime.core.files.len())].lock().unwrap();
        let file_state = shard.files.get(&file).expect("the existing OPEN state remains");
        assert!(file_state.pending_opens.is_empty());
        assert_eq!(file_state.shares.reservations()[0].contributions().total(), 2);
    }

    #[tokio::test]
    async fn restart_reclaim_preserves_upgrade_contributions_for_downgrade() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"runtime-open-contribution-recovery"[..]);
        let journal = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut source_config = config();
        source_config.boot_tag = journal.boot().boot_tag;
        source_config.write_verifier = journal.boot().verifier;
        source_config.recovered = Some(journal.recovery().clone());
        let source_journal = Arc::new(AsyncMutex::new(journal));
        source_config.stable_journal = Some(source_journal.clone());
        let source = Nfs4Runtime::new(source_config).unwrap();
        let client_id = confirmed_client(&source, b"restart-open-client", [0x61; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"restart-open-owner".to_vec(),
        };
        let file = test_file(106);
        open_and_confirm(&source, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        complete_open_request(&source, &owner, file, 3, ShareAccess::WRITE.bits(), ShareDeny::NONE.bits(), 0x62).await;
        source_journal.lock().await.mark_clean_shutdown().await.unwrap();
        drop(source);
        drop(source_journal);

        let restarted_journal = StableJournal::initialize(store, scope, 200, StableJournalLimits::default())
            .await
            .unwrap();
        let recovered_open = restarted_journal
            .recovery()
            .records
            .iter()
            .find_map(|(_, record)| match record {
                JournalRecord::Open(open) => Some(open),
                _ => None,
            })
            .expect("the upgraded OPEN is durable");
        assert_eq!(recovered_open.share_access, ShareAccess::BOTH.bits());
        assert_eq!(
            recovered_open.contributions,
            vec![
                StableOpenContributionRecord {
                    share_access: ShareAccess::READ.bits(),
                    share_deny: ShareDeny::NONE.bits(),
                    count: 1,
                },
                StableOpenContributionRecord {
                    share_access: ShareAccess::WRITE.bits(),
                    share_deny: ShareDeny::NONE.bits(),
                    count: 1,
                },
            ]
        );

        let mut destination_config = config();
        destination_config.boot_tag = restarted_journal.boot().boot_tag;
        destination_config.write_verifier = restarted_journal.boot().verifier;
        destination_config.recovered = Some(restarted_journal.recovery().clone());
        destination_config.stable_journal = Some(Arc::new(AsyncMutex::new(restarted_journal)));
        let destination = Nfs4Runtime::new(destination_config).unwrap();
        let client_id = confirmed_client(&destination, b"restart-open-client", [0x61; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"restart-open-owner".to_vec(),
        };
        let reclaim = match destination
            .begin_open(
                &owner,
                1,
                ShareAccess::BOTH.bits(),
                ShareDeny::NONE.bits(),
                true,
                OwnerRequestDigest([0x63; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("the durable upgraded OPEN should be reclaimable"),
        };
        let target = destination
            .reserve_open_target(reclaim, file)
            .unwrap_or_else(|_| panic!("the durable OPEN contribution set should restore"));
        let completion = destination
            .complete_open(
                target,
                ChangeInfo {
                    atomic: true,
                    before: 3,
                    after: 4,
                },
                Vec::new(),
                OpenDelegation::None,
            )
            .await
            .unwrap();
        let ResOp::Open(NfsResult::Ok(open)) = completion.result else {
            panic!("OPEN reclaim did not return a stateid");
        };
        let downgrade = match destination
            .begin_open_state_operation(
                open.state_id,
                file,
                2,
                OwnerRequestDigest([0x64; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("OPEN_DOWNGRADE should execute after reclaim"),
        };
        assert!(matches!(
            destination
                .downgrade_open(downgrade, ShareAccess::READ.bits(), ShareDeny::NONE.bits())
                .await
                .unwrap(),
            ResOp::OpenDowngrade(NfsResult::Ok(_))
        ));
    }

    #[tokio::test]
    async fn close_returns_locks_held_until_originating_open_is_unlocked() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"close-lock-client", [5; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"lock-owner".to_vec(),
        };
        let file = test_file(101);
        let open_state_id =
            open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let lock_state_id = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 16,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner,
                    }),
                },
                file,
                OwnerRequestDigest([0x21; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("LOCK failed: {result:?}"),
        };

        let reservation = match runtime
            .begin_open_state_operation(
                open_state_id,
                file,
                4,
                OwnerRequestDigest([0x22; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected CLOSE decision"),
        };
        let result = match runtime.prepare_close(reservation).await {
            Err(result) => result,
            Ok(_) => panic!("CLOSE was prepared while byte-range locks remained"),
        };
        assert_eq!(result, ResOp::Close(NfsResult::Err(NfsStatus::LocksHeld)));

        assert!(matches!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Read,
                        sequence_id: 2,
                        lock_state_id,
                        offset: 0,
                        length: 16,
                    },
                    file,
                    OwnerRequestDigest([0x23; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Ok(_))
        ));

        let reservation = match runtime
            .begin_open_state_operation(
                open_state_id,
                file,
                5,
                OwnerRequestDigest([0x24; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected CLOSE retry decision"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();
        assert!(matches!(runtime.close_open(prepared).await.unwrap().result, ResOp::Close(NfsResult::Ok(_))));
    }

    #[tokio::test]
    async fn empty_lock_owner_stateid_remains_usable_until_open_close() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"empty-lock-client", [0x41; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"empty-lock-open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"empty-lock-owner".to_vec(),
        };
        let file = test_file(103);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let first_lock = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 16,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner: lock_owner.clone(),
                    }),
                },
                file,
                OwnerRequestDigest([0x42; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("initial LOCK failed: {result:?}"),
        };
        let upgraded_open_state = complete_open_request(
            &runtime,
            &open_owner,
            file,
            4,
            ShareAccess::WRITE.bits(),
            ShareDeny::NONE.bits(),
            0x45,
        )
        .await;
        assert_eq!(
            runtime
                .validate_io(upgraded_open_state, file, IoAccess::Write, 0, 16, &Principal::Anonymous,)
                .await
                .map(|permit| permit.client_id),
            Ok(Some(client_id)),
            "advisory byte-range locks must not block I/O"
        );
        let empty_state = match runtime
            .unlock(
                &LockUnlockArgs {
                    lock_type: LockType::Read,
                    sequence_id: 2,
                    lock_state_id: first_lock,
                    offset: 0,
                    length: 16,
                },
                file,
                OwnerRequestDigest([0x43; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            ResOp::LockUnlock(NfsResult::Ok(state_id)) => state_id,
            result => panic!("LOCKU failed: {result:?}"),
        };
        assert_eq!(
            runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Write,
                        reclaim: false,
                        offset: 0,
                        length: 16,
                        locker: Locker::New(OpenToLockOwner {
                            open_sequence_id: 5,
                            open_state_id: upgraded_open_state,
                            lock_sequence_id: 3,
                            lock_owner: lock_owner.clone(),
                        }),
                    },
                    file,
                    OwnerRequestDigest([0x46; 32]),
                    &Principal::Anonymous,
                )
                .await,
            LockResult::Err(NfsStatus::BadSequenceId)
        );
        assert!(matches!(
            runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Write,
                        reclaim: false,
                        offset: 0,
                        length: 16,
                        locker: Locker::Existing(ExistingLockOwner {
                            lock_state_id: empty_state,
                            lock_sequence_id: 3,
                        }),
                    },
                    file,
                    OwnerRequestDigest([0x44; 32]),
                    &Principal::Anonymous,
                )
                .await,
            LockResult::Ok(_)
        ));
    }

    #[tokio::test]
    async fn invalid_open_stateids_do_not_renew_a_bad_seqid_client() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"bad-seqid-open-client", [0x91; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"bad-seqid-open-owner".to_vec(),
        };
        let file = test_file(911);
        let state_id = open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;

        // OPEN_CONFIRM, OPEN_DOWNGRADE, and CLOSE all share this owner-seqid
        // preflight.  BAD_SEQID wins, but a stateid for a different file must
        // not authenticate a lease renewal.
        clock.advance(Duration::from_secs(9));
        for (digest, require_unconfirmed) in [([0x92; 32], true), ([0x93; 32], false), ([0x94; 32], false)] {
            assert!(matches!(
                runtime
                    .begin_open_state_operation_with_identity(
                        state_id,
                        test_file(912),
                        4,
                        OwnerRequestDigest(digest),
                        &Principal::Anonymous,
                        require_unconfirmed,
                    )
                    .await,
                OpenStateDecision::Error {
                    status: NfsStatus::BadSequenceId,
                    client_id: None,
                }
            ));
        }
        clock.advance(Duration::from_secs(2));
        assert_eq!(runtime.expire_due().await.len(), 1, "invalid OPEN stateids must not extend the lease");
    }

    #[tokio::test]
    async fn invalid_lock_stateids_do_not_renew_a_bad_seqid_client() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"bad-seqid-lock-client", [0xa1; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"bad-seqid-lock-open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"bad-seqid-lock-owner".to_vec(),
        };
        let file = test_file(921);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;

        clock.advance(Duration::from_secs(9));
        assert!(matches!(
            runtime
                .preflight_lock(
                    &LockArgs {
                        lock_type: LockType::Read,
                        reclaim: false,
                        offset: 0,
                        length: 1,
                        locker: Locker::New(OpenToLockOwner {
                            open_sequence_id: 4,
                            open_state_id,
                            lock_sequence_id: 1,
                            lock_owner: lock_owner.clone(),
                        }),
                    },
                    test_file(922),
                    OwnerRequestDigest([0xa2; 32]),
                    &Principal::Anonymous,
                )
                .await,
            LockPreflight::Error {
                status: NfsStatus::BadSequenceId,
                client_id: None,
            }
        ));
        clock.advance(Duration::from_secs(2));
        assert_eq!(runtime.expire_due().await.len(), 1, "invalid LOCK stateids must not extend the lease");
    }

    #[tokio::test]
    async fn invalid_locku_stateids_do_not_renew_a_bad_seqid_client() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"bad-seqid-locku-client", [0xb1; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"bad-seqid-locku-open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"bad-seqid-locku-owner".to_vec(),
        };
        let file = test_file(931);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let lock_state_id = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 1,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner,
                    }),
                },
                file,
                OwnerRequestDigest([0xb2; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("initial LOCK failed: {result:?}"),
        };

        clock.advance(Duration::from_secs(9));
        assert!(matches!(
            runtime
                .preflight_unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Read,
                        sequence_id: 3,
                        lock_state_id,
                        offset: 0,
                        length: 1,
                    },
                    test_file(932),
                    OwnerRequestDigest([0xb3; 32]),
                    &Principal::Anonymous,
                )
                .await,
            LockPreflight::Error {
                status: NfsStatus::BadSequenceId,
                client_id: None,
            }
        ));
        clock.advance(Duration::from_secs(2));
        assert_eq!(runtime.expire_due().await.len(), 1, "invalid LOCKU stateids must not extend the lease");
    }

    #[tokio::test]
    async fn same_lock_owner_has_independent_state_per_originating_open() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"composite-lock-client", [0x71; 8]).await;
        let file = test_file(108);
        let first_open_owner = OpenOwner {
            client_id,
            owner: b"first-composite-open".to_vec(),
        };
        let second_open_owner = OpenOwner {
            client_id,
            owner: b"second-composite-open".to_vec(),
        };
        let first_open =
            open_and_confirm(&runtime, &first_open_owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;
        let second_open = complete_open_request(
            &runtime,
            &second_open_owner,
            file,
            1,
            ShareAccess::BOTH.bits(),
            ShareDeny::NONE.bits(),
            0x70,
        )
        .await;
        let second_confirmation = match runtime
            .begin_open_state_operation(
                second_open,
                file,
                2,
                OwnerRequestDigest([0x79; 32]),
                &Principal::Anonymous,
                true,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            StatefulDecision::Error(status) => panic!("second OPEN_CONFIRM rejected: {status:?}"),
            StatefulDecision::Replay { .. } => panic!("second OPEN_CONFIRM unexpectedly replayed"),
        };
        let ResOp::OpenConfirm(NfsResult::Ok(second_open)) = runtime.confirm_open(second_confirmation).await.unwrap()
        else {
            panic!("second OPEN_CONFIRM failed");
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"shared-protocol-lock-owner".to_vec(),
        };
        let first_lock = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Write,
                    reclaim: false,
                    offset: 0,
                    length: 10,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id: first_open,
                        lock_sequence_id: 1,
                        lock_owner: lock_owner.clone(),
                    }),
                },
                file,
                OwnerRequestDigest([0x72; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("first LOCK failed: {result:?}"),
        };
        let second_lock = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Write,
                    reclaim: false,
                    offset: 20,
                    length: 10,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id: second_open,
                        lock_sequence_id: 2,
                        lock_owner: lock_owner.clone(),
                    }),
                },
                file,
                OwnerRequestDigest([0x73; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("second LOCK failed: {result:?}"),
        };
        assert_eq!(
            runtime
                .validate_io(first_open, file, IoAccess::Write, 0, 10, &Principal::Anonymous)
                .await
                .map(|permit| permit.client_id),
            Ok(Some(client_id)),
            "advisory byte-range locks do not block I/O"
        );
        assert_eq!(
            runtime
                .validate_io(second_open, file, IoAccess::Write, 0, 10, &Principal::Anonymous)
                .await
                .map(|permit| permit.client_id),
            Ok(Some(client_id)),
            "advisory byte-range locks do not become mandatory for another OPEN"
        );

        {
            let state = runtime.core.state.lock().unwrap();
            assert_eq!(
                state
                    .lock_by_state
                    .keys()
                    .filter(|(owner, candidate_file)| {
                        owner.owner == LockOwnerKey::from(&lock_owner) && *candidate_file == file
                    })
                    .count(),
                2
            );
        }

        assert!(matches!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Write,
                        sequence_id: 3,
                        lock_state_id: first_lock,
                        offset: 0,
                        length: 10,
                    },
                    file,
                    OwnerRequestDigest([0x74; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Ok(_))
        ));
        {
            let shard = runtime.core.files[shard_for(&file, runtime.core.files.len())].lock().unwrap();
            let records = shard.files[&file].locks.records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].owner.open, second_open.other);
            assert_eq!(records[0].range, LockRange::from_offset_length(20, 10).unwrap());
        }

        let first_close = match runtime
            .begin_open_state_operation(
                first_open,
                file,
                4,
                OwnerRequestDigest([0x75; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("first CLOSE should execute after its exact lock scope is empty"),
        };
        let first_close = runtime.prepare_close(first_close).await.unwrap();
        assert!(matches!(runtime.close_open(first_close).await.unwrap().result, ResOp::Close(NfsResult::Ok(_))));
        assert_eq!(
            runtime
                .core
                .state
                .lock()
                .unwrap()
                .lock_by_state
                .keys()
                .filter(|(owner, candidate_file)| {
                    owner.owner == LockOwnerKey::from(&lock_owner) && *candidate_file == file
                })
                .count(),
            1,
            "closing one OPEN must not retire another OPEN's composite lock state"
        );

        assert!(matches!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Write,
                        sequence_id: 4,
                        lock_state_id: second_lock,
                        offset: 20,
                        length: 10,
                    },
                    file,
                    OwnerRequestDigest([0x76; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Ok(_))
        ));
        assert_eq!(runtime.release_lock_owner(&lock_owner, &Principal::Anonymous).await, NfsStatus::Ok);
        assert!(
            runtime
                .core
                .state
                .lock()
                .unwrap()
                .lock_by_state
                .keys()
                .all(|(owner, _)| owner.owner != LockOwnerKey::from(&lock_owner)),
            "RELEASE_LOCKOWNER must retire every composite lock state"
        );
    }

    #[tokio::test]
    async fn io_permit_blocks_lock_installation_until_backend_work_finishes() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"io-lock-race-client", [0x75; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"io-lock-race-open".to_vec(),
        };
        let file = test_file(109);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;
        let permit = runtime
            .validate_io(open_state_id, file, IoAccess::Write, 0, 16, &Principal::Anonymous)
            .await
            .unwrap();

        let racing_runtime = runtime.clone();
        let racing_lock = tokio::spawn(async move {
            racing_runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Write,
                        reclaim: false,
                        offset: 0,
                        length: 16,
                        locker: Locker::New(OpenToLockOwner {
                            open_sequence_id: 3,
                            open_state_id,
                            lock_sequence_id: 1,
                            lock_owner: LockOwner {
                                client_id,
                                owner: b"io-lock-race-owner".to_vec(),
                            },
                        }),
                    },
                    file,
                    OwnerRequestDigest([0x76; 32]),
                    &Principal::Anonymous,
                )
                .await
        });
        tokio::task::yield_now().await;
        assert!(!racing_lock.is_finished());

        drop(permit);
        assert!(matches!(racing_lock.await.unwrap(), LockResult::Ok(_)));
    }

    #[tokio::test]
    async fn overflowing_io_range_is_invalid() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"io-overflow-client", [0x77; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"io-overflow-open".to_vec(),
        };
        let file = test_file(110);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        assert!(matches!(
            runtime
                .validate_io(open_state_id, file, IoAccess::Read, u64::MAX, 2, &Principal::Anonymous,)
                .await,
            Err(NfsStatus::Invalid)
        ));
    }

    #[tokio::test]
    async fn unlock_with_pre_transition_stateid_reports_old_stateid() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"old-lock-client", [0x45; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"old-lock-open-owner".to_vec(),
        };
        let file = test_file(104);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::BOTH.bits(), ShareDeny::NONE.bits()).await;
        let old_lock_state = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 16,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner: LockOwner {
                            client_id,
                            owner: b"old-lock-owner".to_vec(),
                        },
                    }),
                },
                file,
                OwnerRequestDigest([0x46; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("initial LOCK failed: {result:?}"),
        };
        assert!(matches!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Read,
                        sequence_id: 2,
                        lock_state_id: old_lock_state,
                        offset: 0,
                        length: 16,
                    },
                    file,
                    OwnerRequestDigest([0x47; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Ok(_))
        ));
        assert_eq!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Read,
                        sequence_id: 3,
                        lock_state_id: old_lock_state,
                        offset: 0,
                        length: 16,
                    },
                    file,
                    OwnerRequestDigest([0x48; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Err(NfsStatus::OldStateId))
        );
    }

    #[tokio::test]
    async fn lock_operations_reject_empty_and_overflowing_ranges_as_invalid() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let bogus_state_id = StateId {
            sequence_id: 1,
            other: [0x51; 12],
        };
        let owner = LockOwner {
            client_id: 7,
            owner: b"range-owner".to_vec(),
        };
        assert_eq!(
            runtime
                .lock_test(
                    &LockTestArgs {
                        lock_type: LockType::Read,
                        offset: 1,
                        length: 0,
                        owner,
                    },
                    test_file(107),
                    &Principal::Anonymous,
                )
                .await,
            LockTestResult::Err(NfsStatus::Invalid)
        );
        assert_eq!(
            runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Read,
                        reclaim: false,
                        offset: 1,
                        length: 0,
                        locker: Locker::Existing(ExistingLockOwner {
                            lock_state_id: bogus_state_id,
                            lock_sequence_id: 1,
                        }),
                    },
                    test_file(107),
                    OwnerRequestDigest([0x52; 32]),
                    &Principal::Anonymous,
                )
                .await,
            LockResult::Err(NfsStatus::Invalid)
        );
        assert_eq!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Read,
                        sequence_id: 1,
                        lock_state_id: bogus_state_id,
                        offset: 100,
                        length: u64::MAX - 1,
                    },
                    test_file(107),
                    OwnerRequestDigest([0x53; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Err(NfsStatus::Invalid))
        );
    }

    #[tokio::test]
    async fn prepared_close_excludes_a_concurrent_lock_until_the_open_is_closed() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"close-race-client", [6; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"close-race-open-owner".to_vec(),
        };
        let file = test_file(102);
        let open_state_id =
            open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let reservation = match runtime
            .begin_open_state_operation(
                open_state_id,
                file,
                3,
                OwnerRequestDigest([0x31; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected CLOSE decision"),
        };
        let prepared = runtime.prepare_close(reservation).await.unwrap();

        let racing_runtime = runtime.clone();
        let racing_lock = tokio::spawn(async move {
            racing_runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Read,
                        reclaim: false,
                        offset: 0,
                        length: 16,
                        locker: Locker::New(OpenToLockOwner {
                            open_sequence_id: 4,
                            open_state_id,
                            lock_sequence_id: 1,
                            lock_owner: LockOwner {
                                client_id,
                                owner: b"close-race-lock-owner".to_vec(),
                            },
                        }),
                    },
                    file,
                    OwnerRequestDigest([0x32; 32]),
                    &Principal::Anonymous,
                )
                .await
        });
        tokio::task::yield_now().await;
        assert!(!racing_lock.is_finished());

        assert!(matches!(runtime.close_open(prepared).await.unwrap().result, ResOp::Close(NfsResult::Ok(_))));
        assert!(matches!(racing_lock.await.unwrap(), LockResult::Err(NfsStatus::BadStateId | NfsStatus::OldStateId)));
    }

    #[tokio::test]
    async fn disjoint_lock_ranges_are_bounded_before_the_state_changes() {
        let mut runtime_config = config();
        runtime_config.limits.max_lock_ranges_per_state = 2;
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"bounded-lock-client", [0x51; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"bounded-open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"bounded-lock-owner".to_vec(),
        };
        let file = test_file(151);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::WRITE.bits(), ShareDeny::NONE.bits()).await;
        let mut lock_state_id = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Write,
                    reclaim: false,
                    offset: 0,
                    length: 10,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner: lock_owner.clone(),
                    }),
                },
                file,
                OwnerRequestDigest([0x52; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("initial LOCK failed: {result:?}"),
        };
        lock_state_id = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Write,
                    reclaim: false,
                    offset: 20,
                    length: 10,
                    locker: Locker::Existing(ExistingLockOwner {
                        lock_state_id,
                        lock_sequence_id: 2,
                    }),
                },
                file,
                OwnerRequestDigest([0x53; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("second LOCK failed: {result:?}"),
        };
        assert_eq!(
            runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Write,
                        reclaim: false,
                        offset: 40,
                        length: 10,
                        locker: Locker::Existing(ExistingLockOwner {
                            lock_state_id,
                            lock_sequence_id: 3,
                        }),
                    },
                    file,
                    OwnerRequestDigest([0x54; 32]),
                    &Principal::Anonymous,
                )
                .await,
            LockResult::Err(NfsStatus::Resource)
        );

        let lock_key = LockStateOwner::new(LockOwnerKey::from(&lock_owner), open_state_id.other);
        let shard = runtime.core.files[shard_for(&file, runtime.core.files.len())].lock().unwrap();
        let ranges = shard.files[&file]
            .locks
            .records()
            .iter()
            .filter(|record| record.owner == lock_key)
            .map(|record| record.range)
            .collect::<Vec<_>>();
        assert_eq!(
            ranges,
            vec![
                LockRange::from_offset_length(0, 10).unwrap(),
                LockRange::from_offset_length(20, 10).unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn split_unlock_persists_and_recovers_both_remaining_ranges() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"runtime-split-lock-recovery"[..]);
        let journal = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let client_id = confirmed_client(&runtime, b"split-lock-client", [0x61; 8]).await;
        let open_owner = OpenOwner {
            client_id,
            owner: b"split-open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"split-lock-owner".to_vec(),
        };
        let file = test_file(161);
        let open_state_id =
            open_and_confirm(&runtime, &open_owner, file, ShareAccess::WRITE.bits(), ShareDeny::NONE.bits()).await;
        let lock_state_id = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Write,
                    reclaim: false,
                    offset: 0,
                    length: 100,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner,
                    }),
                },
                file,
                OwnerRequestDigest([0x62; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("LOCK failed: {result:?}"),
        };
        assert!(matches!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Write,
                        sequence_id: 2,
                        lock_state_id,
                        offset: 40,
                        length: 20,
                    },
                    file,
                    OwnerRequestDigest([0x63; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Ok(_))
        ));

        let restarted = StableJournal::initialize(store, scope, 200, StableJournalLimits::default())
            .await
            .unwrap();
        let stable_lock = restarted
            .recovery()
            .records
            .iter()
            .find_map(|(_, record)| match record {
                JournalRecord::Lock(lock) => Some(lock.clone()),
                _ => None,
            })
            .expect("durable lock record");
        assert_eq!(
            stable_lock.ranges,
            vec![
                StableLockRangeRecord {
                    offset: 0,
                    length: 40,
                    write: true,
                },
                StableLockRangeRecord {
                    offset: 60,
                    length: 40,
                    write: true,
                },
            ]
        );

        let mut restarted_config = config();
        restarted_config.boot_tag = restarted.boot().boot_tag;
        restarted_config.write_verifier = restarted.boot().verifier;
        restarted_config.recovered = Some(restarted.recovery().clone());
        restarted_config.stable_journal = Some(Arc::new(AsyncMutex::new(restarted)));
        let restarted_runtime = Nfs4Runtime::new(restarted_config).unwrap();
        let recovered = restarted_runtime
            .core
            .state
            .lock()
            .unwrap()
            .recovered_locks
            .values()
            .next()
            .cloned()
            .expect("recovered lock");
        assert_eq!(
            recovered.ranges,
            vec![
                RecoveredLockRange {
                    access: LockAccess::Write,
                    range: LockRange::from_offset_length(0, 40).unwrap(),
                },
                RecoveredLockRange {
                    access: LockAccess::Write,
                    range: LockRange::from_offset_length(60, 40).unwrap(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn downgrade_rejects_access_incompatible_with_originating_locks() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let client_id = confirmed_client(&runtime, b"downgrade-lock-client", [6; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"open-owner".to_vec(),
        };
        let lock_owner = LockOwner {
            client_id,
            owner: b"lock-owner".to_vec(),
        };
        let file = test_file(102);
        let _read_state_id =
            open_and_confirm(&runtime, &owner, file, ShareAccess::READ.bits(), ShareDeny::NONE.bits()).await;
        let open_state_id =
            complete_open_request(&runtime, &owner, file, 3, ShareAccess::WRITE.bits(), ShareDeny::NONE.bits(), 0x31)
                .await;
        let lock_state_id = match runtime
            .lock(
                &LockArgs {
                    lock_type: LockType::Write,
                    reclaim: false,
                    offset: 8,
                    length: 8,
                    locker: Locker::New(OpenToLockOwner {
                        open_sequence_id: 4,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner,
                    }),
                },
                file,
                OwnerRequestDigest([0x32; 32]),
                &Principal::Anonymous,
            )
            .await
        {
            LockResult::Ok(state_id) => state_id,
            result => panic!("LOCK failed: {result:?}"),
        };

        let reservation = match runtime
            .begin_open_state_operation(
                open_state_id,
                file,
                5,
                OwnerRequestDigest([0x33; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected OPEN_DOWNGRADE decision"),
        };
        assert_eq!(
            runtime
                .downgrade_open(reservation, ShareAccess::READ.bits(), ShareDeny::NONE.bits())
                .await
                .unwrap(),
            ResOp::OpenDowngrade(NfsResult::Err(NfsStatus::LocksHeld))
        );

        assert!(matches!(
            runtime
                .unlock(
                    &LockUnlockArgs {
                        lock_type: LockType::Write,
                        sequence_id: 2,
                        lock_state_id,
                        offset: 8,
                        length: 8,
                    },
                    file,
                    OwnerRequestDigest([0x34; 32]),
                    &Principal::Anonymous,
                )
                .await,
            ResOp::LockUnlock(NfsResult::Ok(_))
        ));
        let reservation = match runtime
            .begin_open_state_operation(
                open_state_id,
                file,
                6,
                OwnerRequestDigest([0x35; 32]),
                &Principal::Anonymous,
                false,
            )
            .await
        {
            StatefulDecision::Execute(reservation) => reservation,
            _ => panic!("unexpected OPEN_DOWNGRADE retry decision"),
        };
        assert!(matches!(
            runtime
                .downgrade_open(reservation, ShareAccess::READ.bits(), ShareDeny::NONE.bits())
                .await
                .unwrap(),
            ResOp::OpenDowngrade(NfsResult::Ok(_))
        ));
    }

    #[tokio::test]
    async fn recovery_links_locks_to_open_identity_across_sequence_transitions() {
        let (mut recovered, _, _) = recovered_state(PreviousShutdown::Unclean);
        let mut transitioned_open_token = None;
        for (key, record) in &mut recovered.records {
            let JournalRecord::Open(open) = record else {
                continue;
            };
            let mut token = open.state_token;
            token[..4].copy_from_slice(&9_u32.to_be_bytes());
            open.state_token = token;
            *key = JournalKey::Open { state_token: token };
            transitioned_open_token = Some(token);
        }
        let transitioned_open_token = transitioned_open_token.expect("recovery fixture contains OPEN state");

        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let state = runtime.core.state.lock().unwrap();
        let recovered_lock = state.recovered_locks.values().next().expect("lock state recovered");
        assert_eq!(recovered_lock.previous_open_state_token, transitioned_open_token);
    }

    #[test]
    fn recovery_rejects_duplicate_state_object_identity_across_open_and_lock() {
        let (mut recovered, _, _) = recovered_state(PreviousShutdown::Unclean);
        let open_other = recovered
            .records
            .iter()
            .find_map(|(_, record)| match record {
                JournalRecord::Open(open) => Some(state_other(open.state_token)),
                _ => None,
            })
            .expect("recovery fixture contains OPEN state");
        for (key, record) in &mut recovered.records {
            let JournalRecord::Lock(lock) = record else {
                continue;
            };
            let mut duplicate_identity = lock.state_token;
            duplicate_identity[4..].copy_from_slice(&open_other);
            lock.state_token = duplicate_identity;
            *key = JournalKey::Lock {
                state_token: duplicate_identity,
            };
        }

        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        assert!(matches!(Nfs4Runtime::new(runtime_config), Err(RuntimeConfigError::Recovery)));
    }

    #[test]
    fn recovery_accepts_state_that_survived_more_than_one_restart() {
        let (mut recovered, _, _) = recovered_state(PreviousShutdown::Unclean);
        let immediate_previous_tag = {
            let boot = recovered.previous_boot.as_mut().expect("recovery fixture has a boot");
            boot.boot_tag ^= 0x00ff_00ff;
            boot.boot_tag
        };
        let client_tag = recovered
            .records
            .iter()
            .find_map(|(_, record)| match record {
                JournalRecord::Client(client) => Some((client.client_id >> 32) as u32),
                _ => None,
            })
            .expect("recovery fixture has a client");
        assert_ne!(immediate_previous_tag, client_tag);

        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        assert!(Nfs4Runtime::new(runtime_config).is_ok());
    }

    #[tokio::test]
    async fn recovery_gate_errors_preserve_authenticated_identity_for_open_and_lock_test() {
        let (recovered, _, file) = recovered_state(PreviousShutdown::Unclean);
        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        let runtime = Nfs4Runtime::new(runtime_config).unwrap();
        let recovered_client = confirmed_client(&runtime, b"recovered-client", [0x44; 8]).await;
        let recovered_owner = OpenOwner {
            client_id: recovered_client,
            owner: b"recovery-gate-open".to_vec(),
        };

        // A confirmed client is authenticated before the recovery gate
        // selects GRACE.  The executor needs that evidence to renew all
        // delegation managers while preserving the protocol error.
        assert!(matches!(
            runtime
                .begin_open_with_identity(
                    &recovered_owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    true,
                    OwnerRequestDigest([0x91; 32]),
                    &Principal::Anonymous,
                )
                .await,
            OpenDecision::Error {
                status: NfsStatus::Grace,
                client_id: Some(client_id),
            } if client_id == recovered_client
        ));
        assert_eq!(
            runtime
                .lock_test_with_identity(
                    &LockTestArgs {
                        lock_type: LockType::Read,
                        offset: 0,
                        length: 1,
                        owner: LockOwner {
                            client_id: recovered_client,
                            owner: b"recovery-gate-lockt".to_vec(),
                        },
                    },
                    file,
                    &Principal::Anonymous,
                )
                .await,
            LockTestDecision {
                result: LockTestResult::Err(NfsStatus::Grace),
                client_id: Some(recovered_client),
            }
        );

        // A different confirmed client has no previous-boot identity.  Its
        // reclaim error is still authenticated and must renew managers too.
        let unrecovered_client = confirmed_client(&runtime, b"unrecovered-client", [0x45; 8]).await;
        assert!(matches!(
            runtime
                .begin_open_with_identity(
                    &OpenOwner {
                        client_id: unrecovered_client,
                        owner: b"reclaim-bad-open".to_vec(),
                    },
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    true,
                    true,
                    OwnerRequestDigest([0x92; 32]),
                    &Principal::Anonymous,
                )
                .await,
            OpenDecision::Error {
                status: NfsStatus::ReclaimBad,
                client_id: Some(client_id),
            } if client_id == unrecovered_client
        ));

        let no_recovery_runtime = Nfs4Runtime::new(config()).unwrap();
        let no_grace_client = confirmed_client(&no_recovery_runtime, b"no-grace-client", [0x46; 8]).await;
        assert!(matches!(
            no_recovery_runtime
                .begin_open_with_identity(
                    &OpenOwner {
                        client_id: no_grace_client,
                        owner: b"no-grace-open".to_vec(),
                    },
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    true,
                    true,
                    OwnerRequestDigest([0x93; 32]),
                    &Principal::Anonymous,
                )
                .await,
            OpenDecision::Error {
                status: NfsStatus::NoGrace,
                client_id: Some(client_id),
            } if client_id == no_grace_client
        ));
    }

    #[tokio::test]
    async fn clean_and_unclean_restarts_hydrate_exact_reclaim_inventory() {
        for shutdown in [PreviousShutdown::Clean, PreviousShutdown::Unclean] {
            let (recovered, previous_client_id, file) = recovered_state(shutdown);
            let clock = Arc::new(ManualLeaseClock::default());
            let mut runtime_config = config();
            runtime_config.recovered = Some(recovered);
            let runtime = Nfs4Runtime::with_clock(runtime_config, clock.clone()).unwrap();
            {
                let state = runtime.core.state.lock().unwrap();
                assert_eq!(state.recovered_opens.len(), 1);
                assert_eq!(state.recovered_locks.len(), 1);
                assert_eq!(state.recovered_replays.len(), 1);
            }

            let client_id = confirmed_client(&runtime, b"recovered-client", [0x44; 8]).await;
            assert_eq!(
                runtime.previous_client_ids(client_id, &Principal::Anonymous).await.unwrap(),
                vec![previous_client_id]
            );
            let descriptor = runtime
                .confirmed_client_callback(client_id, &Principal::Anonymous)
                .await
                .unwrap();
            assert_eq!(descriptor.callback_identifier, 7);
            assert_eq!(descriptor.callback, callback(b"127.0.0.1.8.1"));

            let owner = OpenOwner {
                client_id,
                owner: b"recovered-open-owner".to_vec(),
            };
            assert!(matches!(
                runtime
                    .begin_open(
                        &owner,
                        1,
                        ShareAccess::READ.bits(),
                        ShareDeny::NONE.bits(),
                        false,
                        OwnerRequestDigest([1; 32]),
                        &Principal::Anonymous,
                    )
                    .await,
                StatefulDecision::Error(NfsStatus::Grace)
            ));

            let false_reclaim = match runtime
                .begin_open(
                    &owner,
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    true,
                    OwnerRequestDigest([2; 32]),
                    &Principal::Anonymous,
                )
                .await
            {
                StatefulDecision::Execute(reservation) => reservation,
                _ => panic!("known client reclaim should reach exact claim validation"),
            };
            let (false_reclaim, status) = match runtime.reserve_open_target(false_reclaim, test_file(701)) {
                Err(error) => error,
                Ok(_) => panic!("an unrecovered object must not be reclaimable"),
            };
            assert_eq!(status, NfsStatus::ReclaimBad);
            assert_eq!(
                runtime.complete_open_error(false_reclaim, status).await,
                ResOp::Open(NfsResult::Err(NfsStatus::ReclaimBad))
            );

            let exact_reclaim = match runtime
                .begin_open(
                    &owner,
                    2,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    true,
                    OwnerRequestDigest([3; 32]),
                    &Principal::Anonymous,
                )
                .await
            {
                StatefulDecision::Execute(reservation) => reservation,
                _ => panic!("exact reclaim should execute"),
            };
            let target = match runtime.reserve_open_target(exact_reclaim, file) {
                Ok(target) => target,
                Err(_) => panic!("the recovered OPEN must match exactly"),
            };
            let completion = runtime
                .complete_open(
                    target,
                    ChangeInfo {
                        atomic: true,
                        before: 2,
                        after: 3,
                    },
                    Vec::new(),
                    OpenDelegation::None,
                )
                .await
                .unwrap();
            let ResOp::Open(NfsResult::Ok(open)) = completion.result else {
                panic!("reclaim did not return OPEN success");
            };
            assert_eq!(open.result_flags & OPEN4_RESULT_CONFIRM, 0);
            // The reclaimed, non-special stateid remains a valid lease
            // renewal source even though the active grace period makes this
            // I/O request return GRACE.
            assert!(matches!(
                runtime
                    .validate_io_with_identity(open.state_id, file, IoAccess::Read, 0, 1, &Principal::Anonymous)
                    .await,
                Err(IoValidationError {
                    status: NfsStatus::Grace,
                    client_id: Some(id),
                }) if id == client_id
            ));
            assert!(runtime.core.state.lock().unwrap().recovered_opens.is_empty());

            let false_lock = runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Read,
                        reclaim: true,
                        offset: 10,
                        length: 20,
                        locker: Locker::New(OpenToLockOwner {
                            open_sequence_id: 3,
                            open_state_id: open.state_id,
                            lock_sequence_id: 1,
                            lock_owner: LockOwner {
                                client_id,
                                owner: b"false-lock-owner".to_vec(),
                            },
                        }),
                    },
                    file,
                    OwnerRequestDigest([4; 32]),
                    &Principal::Anonymous,
                )
                .await;
            assert_eq!(false_lock, LockResult::Err(NfsStatus::ReclaimBad));

            let exact_lock = runtime
                .lock(
                    &LockArgs {
                        lock_type: LockType::Read,
                        reclaim: true,
                        offset: 10,
                        length: 20,
                        locker: Locker::New(OpenToLockOwner {
                            open_sequence_id: 4,
                            open_state_id: open.state_id,
                            lock_sequence_id: 1,
                            lock_owner: LockOwner {
                                client_id,
                                owner: b"recovered-lock-owner".to_vec(),
                            },
                        }),
                    },
                    file,
                    OwnerRequestDigest([5; 32]),
                    &Principal::Anonymous,
                )
                .await;
            assert!(matches!(exact_lock, LockResult::Ok(_)));
            assert!(runtime.core.state.lock().unwrap().recovered_locks.is_empty());

            assert!(!runtime.grace_cleanup_due().await);
            assert!(!runtime.finish_grace_if_due().await.unwrap());
            clock.advance(Duration::from_secs(10));
            assert!(runtime.grace_cleanup_due().await);
            assert!(runtime.finish_grace_if_due().await.unwrap());
            assert!(!runtime.grace_cleanup_due().await);
            assert!(!runtime.finish_grace_if_due().await.unwrap());
            let state = runtime.core.state.lock().unwrap();
            assert!(state.recovered_locks.is_empty());
            assert!(state.recovered_replays.is_empty());
        }
    }

    #[test]
    fn recovery_preserves_stateid_replay_renewal_source() {
        let (mut recovered, previous_client_id, _) = recovered_state(PreviousShutdown::Unclean);
        for (_, record) in &mut recovered.records {
            if let JournalRecord::Replay(replay) = record {
                replay.renewal_source = ReplayRenewalSource::StateId {
                    client_id: previous_client_id,
                };
            }
        }
        let mut runtime_config = config();
        runtime_config.recovered = Some(recovered);
        let runtime = Nfs4Runtime::new(runtime_config).expect("replay source is valid recovered state");
        let state = runtime.core.state.lock().expect("NFSv4 state registry poisoned");
        let replay = state
            .recovered_replays
            .values()
            .next()
            .expect("recovery fixture contains one replay");
        assert_eq!(replay.3.stateid_renewal_client, Some(previous_client_id));
    }

    #[tokio::test]
    async fn grace_cleanup_retries_without_dropping_recovery_state_after_store_failure() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"runtime-grace-cleanup-retry"[..]);
        let journal = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let (recovered, _, _) = recovered_state(PreviousShutdown::Unclean);
        let clock = Arc::new(ManualLeaseClock::default());
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(recovered);
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::with_clock(runtime_config, clock.clone()).unwrap();

        clock.advance(Duration::from_secs(10));
        assert!(runtime.grace_cleanup_due().await);
        store.fail_next_commit(&scope);
        assert_eq!(runtime.finish_grace_if_due().await, Err(NfsStatus::Resource));
        assert!(runtime.grace_cleanup_due().await);
        {
            let state = runtime.core.state.lock().unwrap();
            assert_eq!(state.recovered_opens.len(), 1);
            assert_eq!(state.recovered_locks.len(), 1);
            assert_eq!(state.recovered_replays.len(), 1);
            assert!(!state.recovered_cleanup_keys.is_empty());
        }

        assert!(runtime.finish_grace_if_due().await.unwrap());
        assert!(!runtime.grace_cleanup_due().await);
        let state = runtime.core.state.lock().unwrap();
        assert!(state.recovered_opens.is_empty());
        assert!(state.recovered_locks.is_empty());
        assert!(state.recovered_replays.is_empty());
        assert!(state.recovered_cleanup_keys.is_empty());
    }

    #[tokio::test]
    async fn lease_expiry_releases_client_and_state_capacity_for_reuse() {
        let clock = Arc::new(ManualLeaseClock::default());
        let mut runtime_config = config();
        runtime_config.limits.max_clients = 1;
        runtime_config.limits.max_state_objects = 1;
        let runtime = Nfs4Runtime::with_clock(runtime_config, clock.clone()).unwrap();
        let first_client = confirmed_client(&runtime, b"first-client", [1; 8]).await;
        let first_owner = OpenOwner {
            client_id: first_client,
            owner: b"first-owner".to_vec(),
        };
        let first_state = complete_open_request(
            &runtime,
            &first_owner,
            test_file(801),
            1,
            ShareAccess::READ.bits(),
            ShareDeny::NONE.bits(),
            1,
        )
        .await;
        assert_eq!(runtime.core.state.lock().unwrap().stateids.len(), 1);

        clock.advance(Duration::from_secs(10));
        let releases = runtime.expire_due().await;
        assert_eq!(releases.len(), 1);
        assert_eq!(runtime.core.state.lock().unwrap().stateids.len(), 0);
        assert!(runtime.core.clients.lock().await.client_owners.is_empty());
        assert!(matches!(
            runtime
                .validate_io(first_state, test_file(801), IoAccess::Read, 0, 1, &Principal::Anonymous,)
                .await,
            Err(NfsStatus::Expired)
        ));
        assert!(runtime.acknowledge_pin_release(releases[0].release_id));

        let second_client = confirmed_client(&runtime, b"second-client", [2; 8]).await;
        let second_owner = OpenOwner {
            client_id: second_client,
            owner: b"second-owner".to_vec(),
        };
        let second_state = complete_open_request(
            &runtime,
            &second_owner,
            test_file(802),
            1,
            ShareAccess::READ.bits(),
            ShareDeny::NONE.bits(),
            2,
        )
        .await;
        assert_ne!(first_state.other, second_state.other);
        assert_eq!(&first_state.other[..8], &second_state.other[..8]);
    }

    #[tokio::test]
    async fn lease_expiry_deletes_durable_client_open_and_replay_records() {
        let store = Arc::new(DurableFakeStore::default());
        let scope = StableScope::from(&b"runtime-expiry-deletion"[..]);
        let journal = StableJournal::initialize(store.clone(), scope.clone(), 100, StableJournalLimits::default())
            .await
            .unwrap();
        let clock = Arc::new(ManualLeaseClock::default());
        let mut runtime_config = config();
        runtime_config.boot_tag = journal.boot().boot_tag;
        runtime_config.write_verifier = journal.boot().verifier;
        runtime_config.recovered = Some(journal.recovery().clone());
        runtime_config.stable_journal = Some(Arc::new(AsyncMutex::new(journal)));
        let runtime = Nfs4Runtime::with_clock(runtime_config, clock.clone()).unwrap();
        let client_id = confirmed_client(&runtime, b"durable-client", [9; 8]).await;
        let owner = OpenOwner {
            client_id,
            owner: b"durable-owner".to_vec(),
        };
        complete_open_request(&runtime, &owner, test_file(901), 1, ShareAccess::READ.bits(), ShareDeny::NONE.bits(), 9)
            .await;

        clock.advance(Duration::from_secs(10));
        assert_eq!(runtime.expire_due().await.len(), 1);
        let restarted = StableJournal::initialize(store, scope, 200, StableJournalLimits::default())
            .await
            .unwrap();
        assert!(restarted.recovery().records.iter().all(|(_, record)| !matches!(
            record,
            JournalRecord::Client(_) | JournalRecord::Open(_) | JournalRecord::Lock(_) | JournalRecord::Replay(_)
        )));
    }

    #[tokio::test]
    async fn migration_recovery_prepare_is_invisible_and_activation_merges_with_live_clients() {
        let clock = Arc::new(ManualLeaseClock::default());
        let runtime = Nfs4Runtime::with_clock(config(), clock.clone()).unwrap();
        let live_client = confirmed_client(&runtime, b"unrelated-live-client", [1; 8]).await;
        let (recovered, previous_client_id, _) = recovered_state(PreviousShutdown::Unclean);

        let prepared = runtime.prepare_recovery_import(&recovered, Duration::from_secs(30)).unwrap();
        runtime.validate_recovery_import(&prepared).await.unwrap();
        assert!(runtime.core.state.lock().unwrap().recovered_opens.is_empty());
        assert!(runtime
            .previous_client_ids(live_client, &Principal::Anonymous)
            .await
            .unwrap()
            .is_empty());

        runtime.activate_recovery_import(prepared.clone()).await.unwrap();
        assert_eq!(runtime.core.state.lock().unwrap().recovered_opens.len(), 1);
        assert_eq!(runtime.renew(live_client, &Principal::Anonymous).await, NfsStatus::Ok);
        assert!(matches!(
            runtime
                .begin_open(
                    &OpenOwner {
                        client_id: live_client,
                        owner: b"blocked-during-imported-grace".to_vec(),
                    },
                    1,
                    ShareAccess::READ.bits(),
                    ShareDeny::NONE.bits(),
                    false,
                    OwnerRequestDigest([0x91; 32]),
                    &Principal::Anonymous,
                )
                .await,
            StatefulDecision::Error(NfsStatus::Grace)
        ));
        assert!(matches!(
            runtime
                .validate_io(ANONYMOUS_STATE_ID, test_file(702), IoAccess::Read, 0, 1, &Principal::Anonymous,)
                .await,
            Err(NfsStatus::Grace)
        ));
        assert!(matches!(
            runtime
                .validate_io(READ_BYPASS_STATE_ID, test_file(702), IoAccess::Read, 0, 1, &Principal::Anonymous,)
                .await,
            Err(NfsStatus::Grace)
        ));
        clock.advance(Duration::from_secs(10));
        assert!(!runtime.grace_cleanup_due().await);
        runtime.validate_recovery_import(&prepared).await.unwrap();
        runtime.activate_recovery_import(prepared).await.unwrap();
        assert_eq!(runtime.core.state.lock().unwrap().recovered_opens.len(), 1);

        let imported_client = confirmed_client(&runtime, b"recovered-client", [0x44; 8]).await;
        assert_eq!(
            runtime
                .previous_client_ids(imported_client, &Principal::Anonymous)
                .await
                .unwrap(),
            vec![previous_client_id]
        );
    }

    #[tokio::test]
    async fn migration_import_allows_shared_client_and_identical_replay_across_exports() {
        let runtime = Nfs4Runtime::new(config()).unwrap();
        let (mut first_recovered, previous_client_id, _) = recovered_state(PreviousShutdown::Unclean);
        for (_, record) in &mut first_recovered.records {
            if let JournalRecord::Replay(replay) = record {
                replay.renewal_source = ReplayRenewalSource::StateId {
                    client_id: previous_client_id,
                };
            }
        }
        let mut second_recovered = first_recovered.clone();
        let previous_boot_tag = second_recovered.previous_boot.unwrap().boot_tag;
        let recovery_token = |index: u32| {
            state_token(StateId {
                sequence_id: 1,
                other: {
                    let mut other = [0; 12];
                    other[..4].copy_from_slice(&previous_boot_tag.to_be_bytes());
                    other[4..8].copy_from_slice(&index.to_be_bytes());
                    other[8..].copy_from_slice(&1u32.to_be_bytes());
                    other
                },
            })
        };
        let second_open_token = recovery_token(5);
        let second_lock_token = recovery_token(6);
        let second_file = RuntimeFile {
            export_id: ExportId(8),
            object: ObjectKey {
                file_id: 701,
                generation: 1,
            },
        };
        for (key, record) in &mut second_recovered.records {
            match record {
                JournalRecord::Open(open) => {
                    *key = JournalKey::Open {
                        state_token: second_open_token,
                    };
                    open.state_token = second_open_token;
                    open.object = second_file.stable();
                },
                JournalRecord::Lock(lock) => {
                    *key = JournalKey::Lock {
                        state_token: second_lock_token,
                    };
                    lock.state_token = second_lock_token;
                    lock.open_state_token = second_open_token;
                    lock.object = second_file.stable();
                },
                _ => {},
            }
        }

        let first = runtime
            .prepare_recovery_import(&first_recovered, Duration::from_secs(10))
            .unwrap();
        let second = runtime
            .prepare_recovery_import(&second_recovered, Duration::from_secs(10))
            .unwrap();
        runtime.activate_recovery_import(first).await.unwrap();
        runtime.validate_recovery_import(&second).await.unwrap();
        runtime.activate_recovery_import(second).await.unwrap();

        let clients = runtime.core.clients.lock().await;
        assert_eq!(
            clients
                .recovered_clients
                .values()
                .flatten()
                .filter(|client_id| **client_id == previous_client_id)
                .count(),
            1
        );
        drop(clients);
        let state = runtime.core.state.lock().unwrap();
        assert_eq!(state.recovered_opens.len(), 2);
        assert_eq!(state.recovered_locks.len(), 2);
        assert_eq!(state.recovered_replays.len(), 1);
        assert_eq!(state.recovered_cleanup_keys.len(), 6);
        assert_eq!(
            state
                .recovered_replays
                .values()
                .next()
                .expect("migration retained the replay")
                .3
                .stateid_renewal_client,
            Some(previous_client_id)
        );
    }
}
