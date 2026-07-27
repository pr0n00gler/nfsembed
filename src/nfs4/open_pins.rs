//! Bounded, cancellation-safe lifecycle for backend OPEN transactions and pins.
//!
//! The protocol runtime owns the authoritative OPEN state. This manager owns
//! the asynchronous backend half of that state: exact-outcome OPEN operation
//! records and object-pin cleanup. Keeping it server-wide lets a later request
//! reconcile work abandoned by a cancelled COMPOUND.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;

use super::delegation::{
    DelegationError, DelegationGrantRequest, DelegationManager, GrantOutcome, PersistentDelegationRecord,
    PreparedDelegationReclaim, PreparedReclaimOutcome,
};
use super::runtime::{DelegationEligibilityReservation, Nfs4Runtime, ReleasedOpen, RuntimeFile};
use super::types::{NfsStatus, StateId};
use crate::server::ExportState;
use crate::vfs::{
    ExportId, Nfs4OpenRequest, Nfs4OpenResult, Nfs4OpenTransaction, NfsName, ObjectKey, Principal, ProtocolVersion,
    RequestContext, VirtualFileSystem,
};

const MAINTENANCE_WORK_LIMIT: usize = 32;

/// Delegation state created before the surrounding OPEN replay record is
/// durably committed.
enum ManagedDelegationCleanup {
    Return {
        manager: Arc<DelegationManager>,
        context: RequestContext,
        object: ObjectKey,
        state_id: StateId,
    },
    Rollback(Arc<PreparedDelegationRollback>),
}

struct PreparedDelegationRollback {
    manager: Arc<DelegationManager>,
    prepared: Mutex<Option<Box<PreparedDelegationReclaim>>>,
    completed: AtomicUsize,
}

#[derive(Clone, Copy)]
enum DelegationAttachmentTarget {
    Atomic(u64),
    Retained(PinKey),
}

#[derive(Clone)]
pub(crate) struct DelegationAttachment {
    target: DelegationAttachmentTarget,
}

struct CriticalTaskTracker {
    active: AtomicUsize,
    notify: Notify,
}

impl CriticalTaskTracker {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    fn start(self: &Arc<Self>) -> CriticalTaskGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        CriticalTaskGuard { tracker: self.clone() }
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.active.load(Ordering::Acquire) == 0 {
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
        if self.tracker.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.notify.notify_waiters();
        }
    }
}

#[derive(Clone)]
struct OpenCall {
    vfs: Arc<dyn VirtualFileSystem>,
    context: RequestContext,
    parent: ObjectKey,
    name: NfsName,
    request: Nfs4OpenRequest,
    transaction: Nfs4OpenTransaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptPhase {
    Active,
    Abandoned,
    Reconciling,
    Committing(RuntimeFile),
    OrphanedCommitting(RuntimeFile),
}

struct AttemptEntry {
    call: OpenCall,
    phase: AttemptPhase,
    outcome: Option<Nfs4OpenResult>,
    delegation: Option<ManagedDelegationCleanup>,
    delegation_eligibility: Option<DelegationEligibilityReservation>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PinKey {
    export_id: ExportId,
    object: ObjectKey,
    pin: [u8; 16],
}

struct FinishJob {
    vfs: Arc<dyn VirtualFileSystem>,
    context: RequestContext,
    operation_id: u64,
    delegation: Option<ManagedDelegationCleanup>,
    delegation_eligibility: Option<DelegationEligibilityReservation>,
    in_flight: bool,
}

struct ReleaseJob {
    vfs: Arc<dyn VirtualFileSystem>,
    context: RequestContext,
    key: PinKey,
    release_done: bool,
    delegation: Option<ManagedDelegationCleanup>,
    delegation_eligibility: Option<DelegationEligibilityReservation>,
    finish: Option<FinishJob>,
    in_flight: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainPhase {
    Active,
    Committing,
    OrphanedCommitting,
}

struct RetainEntry {
    vfs: Arc<dyn VirtualFileSystem>,
    context: RequestContext,
    key: PinKey,
    acquire_pin: bool,
    delegation: Option<ManagedDelegationCleanup>,
    delegation_eligibility: Option<DelegationEligibilityReservation>,
    phase: RetainPhase,
}

struct DelegationJob {
    cleanup: Option<ManagedDelegationCleanup>,
    eligibility: Option<DelegationEligibilityReservation>,
}

struct ManagerState {
    capacity: usize,
    attempts: HashMap<u64, AttemptEntry>,
    abandoned: VecDeque<u64>,
    finishes: VecDeque<FinishJob>,
    releases: HashMap<PinKey, ReleaseJob>,
    release_order: VecDeque<PinKey>,
    retains: HashMap<PinKey, RetainEntry>,
    delegations: VecDeque<DelegationJob>,
    claimed_finishes: usize,
    claimed_delegations: usize,
    prefer_release: bool,
}

impl ManagerState {
    fn work_len(&self) -> usize {
        self.attempts
            .len()
            .saturating_add(self.finishes.len())
            .saturating_add(self.releases.len())
            .saturating_add(self.retains.len())
            .saturating_add(self.delegations.len())
            .saturating_add(self.claimed_finishes)
            .saturating_add(self.claimed_delegations)
    }

    fn has_capacity(&self) -> bool {
        self.work_len() < self.capacity
    }

    fn finish_claim_completed(&mut self) {
        assert!(self.claimed_finishes > 0, "OPEN finish claim accounting underflow");
        self.claimed_finishes -= 1;
    }

    fn delegation_claim_completed(&mut self) {
        assert!(self.claimed_delegations > 0, "OPEN delegation claim accounting underflow");
        self.claimed_delegations -= 1;
    }

    fn contains_operation(&self, operation_id: u64) -> bool {
        self.attempts.contains_key(&operation_id)
            || self.finishes.iter().any(|finish| finish.operation_id == operation_id)
            || self
                .releases
                .values()
                .filter_map(|release| release.finish.as_ref())
                .any(|finish| finish.operation_id == operation_id)
    }

    fn push_finish(&mut self, finish: FinishJob) {
        self.finishes.push_back(finish);
    }

    fn push_release(&mut self, mut release: ReleaseJob) {
        if let Some(existing) = self.releases.get_mut(&release.key) {
            if existing.delegation.is_none() {
                existing.delegation = release.delegation.take();
            }
            if existing.delegation_eligibility.is_none() {
                existing.delegation_eligibility = release.delegation_eligibility.take();
            }
            if existing.finish.is_none() {
                existing.finish = release.finish.take();
            }
            if release.delegation.is_some() || release.delegation_eligibility.is_some() {
                // A second delegation for the same pin is not expected, but
                // it still owns backend state and must not be discarded.
                self.delegations.push_back(DelegationJob {
                    cleanup: release.delegation.take(),
                    eligibility: release.delegation_eligibility.take(),
                });
            }
            if let Some(finish) = release.finish.take() {
                // A pin is acquired by exactly one state-creating OPEN.
                // Preserve an unexpected second operation record instead of
                // losing its required finish notification.
                self.finishes.push_back(finish);
            }
            return;
        }
        self.release_order.push_back(release.key);
        self.releases.insert(release.key, release);
    }
}

/// Shared manager for all NFS listeners in one server instance.
#[derive(Clone)]
pub(crate) struct OpenPinManager {
    state: Arc<Mutex<ManagerState>>,
    exports: Arc<HashMap<ExportId, Arc<dyn VirtualFileSystem>>>,
    critical_tasks: Arc<CriticalTaskTracker>,
}

impl OpenPinManager {
    pub(crate) fn new(exports: &[ExportState], capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("OPEN cleanup capacity must be greater than zero");
        }
        let exports = exports
            .iter()
            .map(|export| (export.id, export.vfs.clone()))
            .collect::<HashMap<_, _>>();
        Ok(Self {
            state: Arc::new(Mutex::new(ManagerState {
                capacity,
                attempts: HashMap::new(),
                abandoned: VecDeque::new(),
                finishes: VecDeque::new(),
                releases: HashMap::new(),
                release_order: VecDeque::new(),
                retains: HashMap::new(),
                delegations: VecDeque::new(),
                claimed_finishes: 0,
                claimed_delegations: 0,
                prefer_release: true,
            })),
            exports: Arc::new(exports),
            critical_tasks: Arc::new(CriticalTaskTracker::new()),
        })
    }

    pub(crate) fn begin(
        &self,
        vfs: Arc<dyn VirtualFileSystem>,
        context: RequestContext,
        parent: ObjectKey,
        name: NfsName,
        request: Nfs4OpenRequest,
        transaction: Nfs4OpenTransaction,
    ) -> Result<OpenPinAttempt, NfsStatus> {
        let mut state = self.lock();
        if !state.has_capacity() {
            return Err(NfsStatus::Resource);
        }
        if state.contains_operation(transaction.operation_id) {
            return Err(NfsStatus::ServerFault);
        }
        state.attempts.insert(
            transaction.operation_id,
            AttemptEntry {
                call: OpenCall {
                    vfs,
                    context,
                    parent,
                    name,
                    request,
                    transaction,
                },
                phase: AttemptPhase::Active,
                outcome: None,
                delegation: None,
                delegation_eligibility: None,
            },
        );
        Ok(OpenPinAttempt {
            manager: self.clone(),
            operation_id: transaction.operation_id,
            armed: true,
        })
    }

    /// Registers an idempotent standalone retain before its future is polled.
    /// This is used by filehandle-based reclaim OPENs that have no named
    /// atomic OPEN transaction.
    pub(crate) fn begin_retain(
        &self,
        vfs: Arc<dyn VirtualFileSystem>,
        context: RequestContext,
        file: RuntimeFile,
        pin: [u8; 16],
        acquire_pin: bool,
    ) -> Result<RetainedPinAttempt, NfsStatus> {
        let key = PinKey {
            export_id: file.export_id,
            object: file.object,
            pin,
        };
        let mut state = self.lock();
        if !state.has_capacity() {
            return Err(NfsStatus::Resource);
        }
        if state.retains.contains_key(&key) || state.releases.contains_key(&key) {
            return Err(NfsStatus::ServerFault);
        }
        state.retains.insert(
            key,
            RetainEntry {
                vfs,
                context,
                key,
                acquire_pin,
                delegation: None,
                delegation_eligibility: None,
                phase: RetainPhase::Active,
            },
        );
        Ok(RetainedPinAttempt {
            manager: self.clone(),
            key,
            armed: true,
        })
    }

    /// Adds a pin retired by the protocol runtime. When the queue is full the
    /// runtime must retain the record in its own bounded outbox and retry.
    pub(crate) fn enqueue_released(&self, released: ReleasedOpen) -> bool {
        let key = PinKey {
            export_id: released.file.export_id,
            object: released.file.object,
            pin: released.pin,
        };
        let mut state = self.lock();
        if state.releases.contains_key(&key) {
            return true;
        }
        if !state.has_capacity() {
            return false;
        }
        let Some(vfs) = self.exports.get(&released.file.export_id).cloned() else {
            // A runtime pin always belongs to a configured export. Refuse to
            // acknowledge an impossible record so it remains visible.
            return false;
        };
        state.push_release(ReleaseJob {
            vfs,
            context: cleanup_context(released.file.export_id, released.client_id),
            key,
            release_done: false,
            delegation: None,
            delegation_eligibility: None,
            finish: None,
            in_flight: false,
        });
        true
    }

    /// Moves as many runtime-owned retirement records as current manager
    /// capacity permits. Acknowledgement happens only after the manager has
    /// retained (or deduplicated) the release work.
    pub(crate) fn accept_runtime_releases(&self, runtime: &Nfs4Runtime) {
        for pending in runtime.pending_pin_releases() {
            if !self.enqueue_released(pending.open) {
                break;
            }
            // Concurrent maintainers may both snapshot and deduplicate the
            // same record; only the first acknowledgement needs to win.
            let _ = runtime.acknowledge_pin_release(pending.release_id);
        }
    }

    pub(crate) async fn grant_delegation(
        &self,
        attachment: DelegationAttachment,
        manager: Arc<DelegationManager>,
        request: DelegationGrantRequest,
    ) -> Result<GrantOutcome, DelegationError> {
        let pins = self.clone();
        let cleanup_manager = manager.clone();
        let context = request.context.clone();
        let object = request.object;
        self.run_critical(async move {
            let outcome = manager.grant(request).await;
            if let Ok(GrantOutcome::Granted(grant)) = &outcome {
                pins.attach_delegation(
                    attachment,
                    ManagedDelegationCleanup::Return {
                        manager: cleanup_manager,
                        context,
                        object,
                        state_id: grant.state_id,
                    },
                );
            }
            outcome
        })
        .await
    }

    pub(crate) async fn prepare_delegation_reclaim(
        &self,
        attachment: DelegationAttachment,
        manager: Arc<DelegationManager>,
        request: DelegationGrantRequest,
        recovered: PersistentDelegationRecord,
    ) -> Result<GrantOutcome, DelegationError> {
        let pins = self.clone();
        let cleanup_manager = manager.clone();
        self.run_critical(async move {
            match manager.prepare_reclaim_previous(request, &recovered).await? {
                PreparedReclaimOutcome::Prepared(prepared) => {
                    let grant = prepared.grant().clone();
                    pins.attach_delegation(
                        attachment,
                        ManagedDelegationCleanup::Rollback(Arc::new(PreparedDelegationRollback {
                            manager: cleanup_manager,
                            prepared: Mutex::new(Some(prepared)),
                            completed: AtomicUsize::new(0),
                        })),
                    );
                    Ok(GrantOutcome::Granted(grant))
                },
                PreparedReclaimOutcome::NotGranted(denial) => Ok(GrantOutcome::NotGranted(denial)),
                PreparedReclaimOutcome::Delay => Ok(GrantOutcome::Delay),
            }
        })
        .await
    }

    pub(crate) async fn wait_critical(&self) {
        self.critical_tasks.wait().await;
    }

    async fn run_critical<T, F>(&self, future: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let critical = self.critical_tasks.start();
        match tokio::spawn(async move {
            let _critical = critical;
            future.await
        })
        .await
        {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => panic!("critical delegation task was cancelled"),
        }
    }

    fn attach_delegation(&self, attachment: DelegationAttachment, cleanup: ManagedDelegationCleanup) {
        let mut state = self.lock();
        let mut cleanup = Some(cleanup);
        match attachment.target {
            DelegationAttachmentTarget::Atomic(operation_id) => {
                if let Some(entry) = state.attempts.get_mut(&operation_id) {
                    if entry.delegation.is_none() {
                        entry.delegation = cleanup.take();
                    }
                }
                if cleanup.is_some() {
                    if let Some(job) = state.finishes.iter_mut().find(|job| job.operation_id == operation_id) {
                        if job.delegation.is_none() {
                            job.delegation = cleanup.take();
                        }
                    }
                }
                if cleanup.is_some() {
                    if let Some(job) = state
                        .releases
                        .values_mut()
                        .find(|job| job.finish.as_ref().is_some_and(|finish| finish.operation_id == operation_id))
                    {
                        if job.delegation.is_none() {
                            job.delegation = cleanup.take();
                        }
                    }
                }
            },
            DelegationAttachmentTarget::Retained(key) => {
                if let Some(entry) = state.retains.get_mut(&key) {
                    if entry.delegation.is_none() {
                        entry.delegation = cleanup.take();
                    }
                }
                if cleanup.is_some() {
                    if let Some(job) = state.releases.get_mut(&key) {
                        if job.delegation.is_none() {
                            job.delegation = cleanup.take();
                        }
                    }
                }
            },
        }
        if let Some(cleanup) = cleanup {
            // The caller disappeared and its pin/outcome cleanup completed
            // before the shielded grant returned. Retire the orphan directly.
            state.delegations.push_back(DelegationJob {
                cleanup: Some(cleanup),
                eligibility: None,
            });
        }
    }

    fn attach_delegation_eligibility(
        &self,
        attachment: DelegationAttachment,
        reservation: DelegationEligibilityReservation,
    ) {
        let mut state = self.lock();
        let mut reservation = Some(reservation);
        match attachment.target {
            DelegationAttachmentTarget::Atomic(operation_id) => {
                if let Some(entry) = state.attempts.get_mut(&operation_id) {
                    if entry.delegation_eligibility.is_none() {
                        entry.delegation_eligibility = reservation.take();
                    }
                }
                if reservation.is_some() {
                    if let Some(job) = state.finishes.iter_mut().find(|job| job.operation_id == operation_id) {
                        if job.delegation_eligibility.is_none() {
                            job.delegation_eligibility = reservation.take();
                        }
                    }
                }
                if reservation.is_some() {
                    if let Some(job) = state
                        .releases
                        .values_mut()
                        .find(|job| job.finish.as_ref().is_some_and(|finish| finish.operation_id == operation_id))
                    {
                        if job.delegation_eligibility.is_none() {
                            job.delegation_eligibility = reservation.take();
                        }
                    }
                }
            },
            DelegationAttachmentTarget::Retained(key) => {
                if let Some(entry) = state.retains.get_mut(&key) {
                    if entry.delegation_eligibility.is_none() {
                        entry.delegation_eligibility = reservation.take();
                    }
                }
                if reservation.is_some() {
                    if let Some(job) = state.releases.get_mut(&key) {
                        if job.delegation_eligibility.is_none() {
                            job.delegation_eligibility = reservation.take();
                        }
                    }
                }
            },
        }
        if let Some(reservation) = reservation {
            // No async work can intervene between runtime reservation and
            // attachment, but preserve safety if an invariant is violated.
            state.delegations.push_back(DelegationJob {
                cleanup: None,
                eligibility: Some(reservation),
            });
        }
    }

    /// Reconciles abandoned backend calls and retries a bounded amount of
    /// release/finish work. This method is safe to call concurrently.
    pub(crate) async fn maintain(&self, runtime: &Nfs4Runtime) {
        self.wait_critical().await;
        for _ in 0..MAINTENANCE_WORK_LIMIT {
            let Some(work) = self.claim_work(false) else {
                break;
            };
            match work {
                ClaimedWork::Attempt(mut claim) => {
                    let result = match claim.outcome.clone() {
                        Some(outcome) => Ok(outcome),
                        None => {
                            claim
                                .call
                                .vfs
                                .nfs4_open(
                                    &claim.call.context,
                                    claim.call.parent,
                                    &claim.call.name,
                                    claim.call.request.clone(),
                                    claim.call.transaction,
                                )
                                .await
                        },
                    };
                    claim.complete(result);
                },
                ClaimedWork::Finish(mut claim) => {
                    if let Some(cleanup) = claim.job.delegation.as_ref() {
                        if !self.run_delegation_cleanup(cleanup).await {
                            claim.complete(false);
                            continue;
                        }
                        claim.job.delegation = None;
                        claim.job.delegation_eligibility = None;
                    } else {
                        claim.job.delegation_eligibility = None;
                    }
                    let result = claim
                        .job
                        .vfs
                        .nfs4_finish_open_operation(&claim.job.context, claim.job.operation_id)
                        .await;
                    claim.complete(result.is_ok());
                },
                ClaimedWork::Release(mut claim) => {
                    // A pending delegation candidate blocks conflicting
                    // accesses. Roll back any unacknowledged grant, then drop
                    // that reservation before pin release begins.
                    if let Some(cleanup) = claim.job.delegation.as_ref() {
                        if !self.run_delegation_cleanup(cleanup).await {
                            claim.complete(false, false);
                            continue;
                        }
                        claim.job.delegation = None;
                    }
                    claim.job.delegation_eligibility = None;
                    if !claim.job.release_done {
                        // Pin release mutates the backend's object lifetime and
                        // therefore shares the same per-file gate as READ,
                        // WRITE, CLOSE, and state expiry.
                        let _gate = runtime
                            .operation_gate(RuntimeFile {
                                export_id: claim.job.key.export_id,
                                object: claim.job.key.object,
                            })
                            .await;
                        let released = claim
                            .job
                            .vfs
                            .release_open_object(&claim.job.context, claim.job.key.object, claim.job.key.pin)
                            .await
                            .is_ok();
                        if !released {
                            claim.complete(false, false);
                            continue;
                        }
                        claim.job.release_done = true;
                    }
                    let finished = match &claim.job.finish {
                        Some(finish) => finish
                            .vfs
                            .nfs4_finish_open_operation(&finish.context, finish.operation_id)
                            .await
                            .is_ok(),
                        None => true,
                    };
                    claim.complete(true, finished);
                },
                ClaimedWork::Delegation(mut claim) => {
                    let completed = match claim.job.as_ref().and_then(|job| job.cleanup.as_ref()) {
                        Some(cleanup) => self.run_delegation_cleanup(cleanup).await,
                        None => true,
                    };
                    claim.complete(completed);
                },
            }
        }
    }

    async fn run_delegation_cleanup(&self, cleanup: &ManagedDelegationCleanup) -> bool {
        match cleanup {
            ManagedDelegationCleanup::Return {
                manager,
                context,
                object,
                state_id,
            } => {
                let manager = manager.clone();
                let context = context.clone();
                let export_id = context.export_id;
                let object = *object;
                let state_id = *state_id;
                let result = self
                    .run_critical(async move { manager.delegreturn(&context, object, state_id).await })
                    .await;
                match result {
                    Ok(()) => true,
                    Err(error) if error.status() == NfsStatus::BadStateId => true,
                    Err(error) => {
                        tracing::error!(
                            export_id = export_id.0,
                            object = object.file_id,
                            error = %error,
                            "failed to roll back an unacknowledged OPEN delegation; cleanup remains queued"
                        );
                        false
                    },
                }
            },
            ManagedDelegationCleanup::Rollback(rollback) => {
                if rollback.completed.load(Ordering::Acquire) != 0 {
                    return true;
                }
                let rollback = rollback.clone();
                self.run_critical(async move {
                    let prepared = rollback.prepared.lock().expect("prepared delegation rollback poisoned").take();
                    if let Some(prepared) = prepared {
                        if let Err(error) = rollback.manager.rollback_reclaim(prepared).await {
                            // rollback_reclaim consumes the guard and guarantees
                            // local removal even if durable restoration fails.
                            tracing::error!(
                                error = %error,
                                "durable reclaim rollback failed after removing the unacknowledged delegation"
                            );
                        }
                    }
                    rollback.completed.store(1, Ordering::Release);
                })
                .await;
                true
            },
        }
    }

    /// Resolves attempts whose caller disappeared while the protocol runtime
    /// was durably committing OPEN. The caller must first drain the runtime's
    /// critical state-transition tasks.
    pub(crate) fn reconcile_committing(&self, runtime: &Nfs4Runtime) {
        let decisions = {
            let state = self.lock();
            state
                .attempts
                .iter()
                .filter_map(|(operation_id, entry)| match entry.phase {
                    AttemptPhase::OrphanedCommitting(file) => {
                        Some((*operation_id, runtime.is_open_pin_active(file, entry.call.transaction.pin_id)))
                    },
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        for (operation_id, adopted) in decisions {
            self.resolve_committing(operation_id, adopted);
        }
        let retained = {
            let state = self.lock();
            state
                .retains
                .iter()
                .filter(|(_, entry)| entry.phase == RetainPhase::OrphanedCommitting)
                .map(|(key, _)| {
                    (
                        *key,
                        runtime.is_open_pin_active(
                            RuntimeFile {
                                export_id: key.export_id,
                                object: key.object,
                            },
                            key.pin,
                        ),
                    )
                })
                .collect::<Vec<_>>()
        };
        for (key, adopted) in retained {
            let mut state = self.lock();
            let Some(entry) = state.retains.remove(&key) else {
                continue;
            };
            queue_retain_terminal(&mut state, entry, adopted);
        }
    }

    pub(crate) fn pending_work(&self) -> usize {
        self.lock().work_len()
    }

    fn resolve_committing(&self, operation_id: u64, adopted: bool) {
        let mut state = self.lock();
        let Some(entry) = state.attempts.remove(&operation_id) else {
            return;
        };
        if !matches!(entry.phase, AttemptPhase::OrphanedCommitting(_)) {
            state.attempts.insert(operation_id, entry);
            return;
        }
        queue_terminal_entry(&mut state, entry, adopted);
    }

    fn claim_work(&self, include_committing: bool) -> Option<ClaimedWork> {
        let mut state = self.lock();

        while let Some(operation_id) = state.abandoned.pop_front() {
            let Some(entry) = state.attempts.get_mut(&operation_id) else {
                continue;
            };
            if entry.phase != AttemptPhase::Abandoned {
                continue;
            }
            entry.phase = AttemptPhase::Reconciling;
            let call = entry.call.clone();
            let outcome = entry.outcome.clone();
            drop(state);
            return Some(ClaimedWork::Attempt(AttemptClaim {
                manager: self.clone(),
                operation_id,
                call,
                outcome,
                completed: false,
            }));
        }

        if include_committing {
            // Committing entries require an explicit runtime drain/query and
            // are intentionally not treated as ordinary abandoned calls.
        }

        if let Some(job) = state.delegations.pop_front() {
            state.claimed_delegations = state.claimed_delegations.saturating_add(1);
            drop(state);
            return Some(ClaimedWork::Delegation(DelegationClaim {
                manager: self.clone(),
                job: Some(job),
                completed: false,
            }));
        }

        let prefer_release = state.prefer_release;
        state.prefer_release = !state.prefer_release;
        if prefer_release {
            if let Some(job) = take_release_job(&mut state) {
                drop(state);
                return Some(ClaimedWork::Release(ReleaseClaim {
                    manager: self.clone(),
                    job,
                    completed: false,
                }));
            }
        }

        if let Some(mut job) = state.finishes.pop_front() {
            job.in_flight = true;
            state.claimed_finishes = state.claimed_finishes.saturating_add(1);
            drop(state);
            return Some(ClaimedWork::Finish(FinishClaim {
                manager: self.clone(),
                job,
                completed: false,
            }));
        }

        if !prefer_release {
            if let Some(job) = take_release_job(&mut state) {
                drop(state);
                return Some(ClaimedWork::Release(ReleaseClaim {
                    manager: self.clone(),
                    job,
                    completed: false,
                }));
            }
        }
        None
    }

    fn lock(&self) -> MutexGuard<'_, ManagerState> {
        self.state.lock().expect("NFSv4 OPEN pin manager poisoned")
    }
}

fn take_release_job(state: &mut ManagerState) -> Option<ReleaseJob> {
    let release_candidates = state.release_order.len();
    for _ in 0..release_candidates {
        let key = state.release_order.pop_front()?;
        let Some(job) = state.releases.get_mut(&key) else {
            continue;
        };
        if job.in_flight {
            state.release_order.push_back(key);
            continue;
        }
        job.in_flight = true;
        return Some(ReleaseJob {
            vfs: job.vfs.clone(),
            context: job.context.clone(),
            key: job.key,
            release_done: job.release_done,
            delegation: job.delegation.take(),
            delegation_eligibility: job.delegation_eligibility.take(),
            finish: job.finish.as_ref().map(|finish| FinishJob {
                vfs: finish.vfs.clone(),
                context: finish.context.clone(),
                operation_id: finish.operation_id,
                delegation: None,
                delegation_eligibility: None,
                in_flight: true,
            }),
            in_flight: true,
        });
    }
    None
}

/// RAII record registered before the backend atomic OPEN future is polled.
pub(crate) struct OpenPinAttempt {
    manager: OpenPinManager,
    operation_id: u64,
    armed: bool,
}

impl OpenPinAttempt {
    pub(crate) fn record_success(&mut self, outcome: &Nfs4OpenResult) {
        let mut state = self.manager.lock();
        let entry = state
            .attempts
            .get_mut(&self.operation_id)
            .expect("live OPEN attempt remains registered");
        entry.outcome = Some(outcome.clone());
    }

    /// Marks the point immediately before the protocol runtime begins its
    /// cancellation-shielded durable OPEN transition.
    pub(crate) fn mark_committing(&mut self, file: RuntimeFile) {
        let mut state = self.manager.lock();
        let entry = state
            .attempts
            .get_mut(&self.operation_id)
            .expect("live OPEN attempt remains registered");
        entry.phase = AttemptPhase::Committing(file);
    }

    /// The backend returned a definitive error, so only its outcome-cache
    /// record remains to be retired.
    pub(crate) fn backend_failed(mut self) {
        let mut state = self.manager.lock();
        let entry = state
            .attempts
            .remove(&self.operation_id)
            .expect("live OPEN attempt remains registered");
        debug_assert!(entry.delegation.is_none());
        state.push_finish(finish_for(&entry.call));
        self.armed = false;
    }

    /// Protocol state durably adopted the successful OPEN. The backend pin,
    /// if any, now belongs to the runtime; only the operation record is
    /// finished here.
    pub(crate) fn adopt(mut self) {
        let mut state = self.manager.lock();
        let entry = state
            .attempts
            .remove(&self.operation_id)
            .expect("live OPEN attempt remains registered");
        queue_terminal_entry(&mut state, entry, true);
        self.armed = false;
    }

    /// Protocol state definitively rejected the backend result. Release an
    /// atomically acquired pin before finishing the operation record.
    pub(crate) fn cleanup(mut self) {
        let mut state = self.manager.lock();
        let entry = state
            .attempts
            .remove(&self.operation_id)
            .expect("live OPEN attempt remains registered");
        queue_terminal_entry(&mut state, entry, false);
        self.armed = false;
    }
}

impl Drop for OpenPinAttempt {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.manager.lock();
        let Some(entry) = state.attempts.get_mut(&self.operation_id) else {
            return;
        };
        if entry.phase == AttemptPhase::Active {
            entry.phase = AttemptPhase::Abandoned;
            state.abandoned.push_back(self.operation_id);
        } else if let AttemptPhase::Committing(file) = entry.phase {
            entry.phase = AttemptPhase::OrphanedCommitting(file);
        }
        // Only a caller-orphaned commit is eligible for reconciliation. A
        // live caller retains exclusive ownership of adopt/cleanup even after
        // the runtime's critical task has momentarily drained.
    }
}

/// A backend pin that may have been acquired by an idempotent standalone
/// retain. Dropping it before adoption always leaves a retryable release.
pub(crate) struct RetainedPinAttempt {
    manager: OpenPinManager,
    key: PinKey,
    armed: bool,
}

impl RetainedPinAttempt {
    pub(crate) fn backend_failed(mut self) {
        self.manager.lock().retains.remove(&self.key);
        self.armed = false;
    }

    fn mark_committing(&mut self) {
        let mut state = self.manager.lock();
        let entry = state
            .retains
            .get_mut(&self.key)
            .expect("live retained-pin attempt remains registered");
        entry.phase = RetainPhase::Committing;
    }

    fn adopt(mut self) {
        let mut state = self.manager.lock();
        let entry = state
            .retains
            .remove(&self.key)
            .expect("live retained-pin attempt remains registered");
        queue_retain_terminal(&mut state, entry, true);
        self.armed = false;
    }

    fn cleanup(mut self) {
        let mut state = self.manager.lock();
        let entry = state
            .retains
            .remove(&self.key)
            .expect("live retained-pin attempt remains registered");
        queue_retain_terminal(&mut state, entry, false);
        self.armed = false;
    }
}

impl Drop for RetainedPinAttempt {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.manager.lock();
        let Some(entry) = state.retains.remove(&self.key) else {
            return;
        };
        if entry.phase == RetainPhase::Committing {
            let mut entry = entry;
            entry.phase = RetainPhase::OrphanedCommitting;
            state.retains.insert(self.key, entry);
        } else {
            // retain_open_object is idempotent and release is explicitly safe
            // after an uncommitted/unknown retain outcome.
            queue_retain_terminal(&mut state, entry, false);
        }
    }
}

/// Uniform pin ownership passed into the protocol runtime commit boundary.
pub(crate) enum ManagedOpenPin {
    Atomic(OpenPinAttempt),
    Retained(RetainedPinAttempt),
}

impl ManagedOpenPin {
    pub(crate) fn delegation_attachment(&self) -> DelegationAttachment {
        match self {
            Self::Atomic(attempt) => DelegationAttachment {
                target: DelegationAttachmentTarget::Atomic(attempt.operation_id),
            },
            Self::Retained(attempt) => DelegationAttachment {
                target: DelegationAttachmentTarget::Retained(attempt.key),
            },
        }
    }

    pub(crate) fn attach_delegation_eligibility(&self, reservation: DelegationEligibilityReservation) {
        match self {
            Self::Atomic(attempt) => attempt.manager.attach_delegation_eligibility(
                DelegationAttachment {
                    target: DelegationAttachmentTarget::Atomic(attempt.operation_id),
                },
                reservation,
            ),
            Self::Retained(attempt) => attempt.manager.attach_delegation_eligibility(
                DelegationAttachment {
                    target: DelegationAttachmentTarget::Retained(attempt.key),
                },
                reservation,
            ),
        }
    }

    pub(crate) fn mark_committing(&mut self, file: RuntimeFile) {
        match self {
            Self::Atomic(attempt) => attempt.mark_committing(file),
            Self::Retained(attempt) => attempt.mark_committing(),
        }
    }

    pub(crate) fn adopt(self) {
        match self {
            Self::Atomic(attempt) => attempt.adopt(),
            Self::Retained(attempt) => attempt.adopt(),
        }
    }

    pub(crate) fn cleanup(self) {
        match self {
            Self::Atomic(attempt) => attempt.cleanup(),
            Self::Retained(attempt) => attempt.cleanup(),
        }
    }
}

impl From<OpenPinAttempt> for ManagedOpenPin {
    fn from(value: OpenPinAttempt) -> Self {
        Self::Atomic(value)
    }
}

impl From<RetainedPinAttempt> for ManagedOpenPin {
    fn from(value: RetainedPinAttempt) -> Self {
        Self::Retained(value)
    }
}

fn queue_terminal_entry(state: &mut ManagerState, entry: AttemptEntry, adopted: bool) {
    let mut finish = finish_for(&entry.call);
    if adopted {
        adopt_delegation(entry.delegation);
        state.push_finish(finish);
        return;
    }
    if !entry.call.transaction.acquire_pin {
        finish.delegation = entry.delegation;
        finish.delegation_eligibility = entry.delegation_eligibility;
        state.push_finish(finish);
        return;
    }
    let Some(outcome) = entry.outcome else {
        // This branch is used only after exact-outcome reconciliation. If a
        // caller invokes it earlier, retain the operation as abandoned.
        let operation_id = entry.call.transaction.operation_id;
        state.attempts.insert(
            operation_id,
            AttemptEntry {
                phase: AttemptPhase::Abandoned,
                ..entry
            },
        );
        state.abandoned.push_back(operation_id);
        return;
    };
    let key = PinKey {
        export_id: entry.call.context.export_id,
        object: outcome.value.object,
        pin: entry.call.transaction.pin_id,
    };
    state.push_release(ReleaseJob {
        vfs: entry.call.vfs,
        context: entry.call.context,
        key,
        release_done: false,
        delegation: entry.delegation,
        delegation_eligibility: entry.delegation_eligibility,
        finish: Some(finish),
        in_flight: false,
    });
}

fn queue_retain_terminal(state: &mut ManagerState, entry: RetainEntry, adopted: bool) {
    if adopted {
        adopt_delegation(entry.delegation);
    } else if entry.acquire_pin {
        state.push_release(ReleaseJob {
            vfs: entry.vfs,
            context: entry.context,
            key: entry.key,
            release_done: false,
            delegation: entry.delegation,
            delegation_eligibility: entry.delegation_eligibility,
            finish: None,
            in_flight: false,
        });
    } else if entry.delegation.is_some() || entry.delegation_eligibility.is_some() {
        state.delegations.push_back(DelegationJob {
            cleanup: entry.delegation,
            eligibility: entry.delegation_eligibility,
        });
    }
}

fn adopt_delegation(cleanup: Option<ManagedDelegationCleanup>) {
    if let Some(ManagedDelegationCleanup::Rollback(rollback)) = cleanup {
        let prepared = rollback.prepared.lock().expect("prepared delegation rollback poisoned").take();
        if let Some(prepared) = prepared {
            let _ = DelegationManager::commit_reclaim(prepared);
        }
        rollback.completed.store(1, Ordering::Release);
    }
    // An optional grant is already live and needs no additional commit.
}

fn finish_for(call: &OpenCall) -> FinishJob {
    FinishJob {
        vfs: call.vfs.clone(),
        context: call.context.clone(),
        operation_id: call.transaction.operation_id,
        delegation: None,
        delegation_eligibility: None,
        in_flight: false,
    }
}

fn cleanup_context(export_id: ExportId, client_id: u64) -> RequestContext {
    RequestContext {
        principal: Principal::Anonymous,
        client_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        export_id,
        protocol: ProtocolVersion::V4,
        client_id: Some(client_id),
    }
}

enum ClaimedWork {
    Attempt(AttemptClaim),
    Finish(FinishClaim),
    Release(ReleaseClaim),
    Delegation(DelegationClaim),
}

struct DelegationClaim {
    manager: OpenPinManager,
    job: Option<DelegationJob>,
    completed: bool,
}

impl DelegationClaim {
    fn complete(&mut self, completed: bool) {
        let mut state = self.manager.lock();
        state.delegation_claim_completed();
        if completed {
            if let Some(mut job) = self.job.take() {
                drop(job.eligibility.take());
            }
        } else {
            if let Some(job) = self.job.take() {
                state.delegations.push_back(job);
            }
        }
        self.completed = true;
    }
}

impl Drop for DelegationClaim {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.manager.lock();
            state.delegation_claim_completed();
            if let Some(job) = self.job.take() {
                state.delegations.push_front(job);
            }
        }
    }
}

struct AttemptClaim {
    manager: OpenPinManager,
    operation_id: u64,
    call: OpenCall,
    outcome: Option<Nfs4OpenResult>,
    completed: bool,
}

impl AttemptClaim {
    fn complete(&mut self, result: Result<Nfs4OpenResult, crate::vfs::NfsError>) {
        let mut state = self.manager.lock();
        let Some(mut entry) = state.attempts.remove(&self.operation_id) else {
            self.completed = true;
            return;
        };
        entry.outcome = self.outcome.take().or_else(|| result.ok());
        if entry.outcome.is_none() {
            state.push_finish(finish_for(&entry.call));
        } else {
            queue_terminal_entry(&mut state, entry, false);
        }
        self.completed = true;
    }
}

impl Drop for AttemptClaim {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = self.manager.lock();
        if let Some(entry) = state.attempts.get_mut(&self.operation_id) {
            entry.phase = AttemptPhase::Abandoned;
            state.abandoned.push_back(self.operation_id);
        }
    }
}

struct FinishClaim {
    manager: OpenPinManager,
    job: FinishJob,
    completed: bool,
}

impl FinishClaim {
    fn complete(&mut self, succeeded: bool) {
        let mut state = self.manager.lock();
        state.finish_claim_completed();
        if !succeeded {
            self.job.in_flight = false;
            state.finishes.push_back(FinishJob {
                vfs: self.job.vfs.clone(),
                context: self.job.context.clone(),
                operation_id: self.job.operation_id,
                delegation: self.job.delegation.take(),
                delegation_eligibility: self.job.delegation_eligibility.take(),
                in_flight: false,
            });
        }
        self.completed = true;
    }
}

impl Drop for FinishClaim {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.manager.lock();
            state.finish_claim_completed();
            self.job.in_flight = false;
            state.finishes.push_back(FinishJob {
                vfs: self.job.vfs.clone(),
                context: self.job.context.clone(),
                operation_id: self.job.operation_id,
                delegation: self.job.delegation.take(),
                delegation_eligibility: self.job.delegation_eligibility.take(),
                in_flight: false,
            });
        }
    }
}

struct ReleaseClaim {
    manager: OpenPinManager,
    job: ReleaseJob,
    completed: bool,
}

impl ReleaseClaim {
    fn complete(&mut self, released: bool, finished: bool) {
        let mut state = self.manager.lock();
        if released && finished {
            state.releases.remove(&self.job.key);
        } else if let Some(job) = state.releases.get_mut(&self.job.key) {
            job.release_done |= released;
            if job.delegation.is_none() {
                job.delegation = self.job.delegation.take();
            }
            if job.delegation_eligibility.is_none() {
                job.delegation_eligibility = self.job.delegation_eligibility.take();
            }
            job.in_flight = false;
            state.release_order.push_back(self.job.key);
        }
        self.completed = true;
    }
}

impl Drop for ReleaseClaim {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = self.manager.lock();
        if let Some(job) = state.releases.get_mut(&self.job.key) {
            job.release_done |= self.job.release_done;
            if job.delegation.is_none() {
                job.delegation = self.job.delegation.take();
            }
            if job.delegation_eligibility.is_none() {
                job.delegation_eligibility = self.job.delegation_eligibility.take();
            }
            job.in_flight = false;
            state.release_order.push_back(self.job.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::nfs4::runtime::RuntimeConfig;
    use crate::server::{FileHandlePolicy, FileSystemId, Nfs4Limits, SecurityPolicy};
    use crate::vfs::{
        ChangeId, ChangeInfo, CreatedObject, FileAttributes, FileType, Nfs4Capabilities, Nfs4OpenAccess,
        Nfs4OpenExpectation, NfsError, NfsTime, VfsCapabilities,
    };

    const EXPORT_ID: ExportId = ExportId(9);
    const PARENT: ObjectKey = ObjectKey {
        file_id: 1,
        generation: 1,
    };
    const FILE: ObjectKey = ObjectKey {
        file_id: 2,
        generation: 1,
    };

    struct TestVfs {
        open_calls: AtomicUsize,
        releases: AtomicUsize,
        finishes: AtomicUsize,
        release_failures: AtomicUsize,
        name_unlinked: AtomicBool,
        outcomes: Mutex<HashMap<u64, Nfs4OpenResult>>,
    }

    impl TestVfs {
        fn new() -> Self {
            Self {
                open_calls: AtomicUsize::new(0),
                releases: AtomicUsize::new(0),
                finishes: AtomicUsize::new(0),
                release_failures: AtomicUsize::new(0),
                name_unlinked: AtomicBool::new(false),
                outcomes: Mutex::new(HashMap::new()),
            }
        }

        fn result() -> Nfs4OpenResult {
            Nfs4OpenResult {
                value: CreatedObject {
                    object: FILE,
                    attributes: Some(attributes(FILE)),
                },
                change_info: ChangeInfo {
                    atomic: true,
                    before: ChangeId(1),
                    after: ChangeId(2),
                },
            }
        }
    }

    #[async_trait]
    impl VirtualFileSystem for TestVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_WRITE
        }

        fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
            Some(Nfs4Capabilities::READ_WRITE)
        }

        fn root(&self) -> ObjectKey {
            PARENT
        }

        async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            Ok(attributes(object))
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            if self.name_unlinked.load(Ordering::SeqCst) {
                return Err(NfsError::NotFound);
            }
            Ok(TestVfs::result().value)
        }

        async fn nfs4_open(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
            _request: Nfs4OpenRequest,
            transaction: Nfs4OpenTransaction,
        ) -> Result<Nfs4OpenResult, NfsError> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            let mut outcomes = self.outcomes.lock().expect("test outcome cache poisoned");
            Ok(outcomes.entry(transaction.operation_id).or_insert_with(TestVfs::result).clone())
        }

        async fn nfs4_finish_open_operation(
            &self,
            _context: &RequestContext,
            operation_id: u64,
        ) -> Result<(), NfsError> {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            self.outcomes.lock().expect("test outcome cache poisoned").remove(&operation_id);
            Ok(())
        }

        async fn retain_open_object(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            _open_instance: [u8; 16],
        ) -> Result<(), NfsError> {
            Ok(())
        }

        async fn release_open_object(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            _open_instance: [u8; 16],
        ) -> Result<(), NfsError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            let should_fail = self
                .release_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| remaining.checked_sub(1))
                .is_ok();
            if should_fail {
                Err(NfsError::Jukebox)
            } else {
                Ok(())
            }
        }
    }

    fn attributes(object: ObjectKey) -> FileAttributes {
        FileAttributes {
            file_type: if object == PARENT {
                FileType::Directory
            } else {
                FileType::Regular
            },
            mode: 0o644,
            links: 1,
            uid: 1,
            gid: 1,
            size: 0,
            used: 0,
            device: None,
            fs_id: 9,
            file_id: object.file_id,
            change_id: ChangeId(1),
            access_time: NfsTime {
                seconds: 1,
                nanoseconds: 0,
            },
            modify_time: NfsTime {
                seconds: 1,
                nanoseconds: 0,
            },
            change_time: NfsTime {
                seconds: 1,
                nanoseconds: 0,
            },
        }
    }

    fn fixture_with_capacity(capacity: usize) -> (Arc<TestVfs>, OpenPinManager, Nfs4Runtime, RequestContext) {
        let vfs = Arc::new(TestVfs::new());
        let exports = vec![ExportState {
            vfs: vfs.clone(),
            id: EXPORT_ID,
            path: "/test".to_owned(),
            fsid: FileSystemId::new(0, 9),
            security_policy: SecurityPolicy::anonymous(),
            filehandle_policy: FileHandlePolicy::Volatile,
        }];
        let manager = OpenPinManager::new(&exports, capacity).unwrap();
        let runtime = Nfs4Runtime::new(RuntimeConfig {
            lease_duration: Duration::from_secs(90),
            grace_duration: Duration::from_secs(90),
            limits: Nfs4Limits::default(),
            boot_tag: 0x1122_3344,
            write_verifier: [0x11; 8],
            stable_journal: None,
            recovered: None,
        })
        .unwrap();
        (vfs, manager, runtime, cleanup_context(EXPORT_ID, 7))
    }

    fn fixture() -> (Arc<TestVfs>, OpenPinManager, Nfs4Runtime, RequestContext) {
        fixture_with_capacity(8)
    }

    fn request() -> Nfs4OpenRequest {
        Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: None,
            truncate_existing: false,
        }
    }

    fn transaction(operation_id: u64) -> Nfs4OpenTransaction {
        Nfs4OpenTransaction {
            operation_id,
            expected: Nfs4OpenExpectation::Missing,
            pin_id: [operation_id as u8; 16],
            acquire_pin: true,
        }
    }

    #[tokio::test]
    async fn abandoned_missing_open_retries_exact_outcome_after_external_unlink() {
        let (vfs, manager, runtime, context) = fixture();
        let name = NfsName::new(b"new".to_vec()).unwrap();
        let transaction = transaction(1);
        let attempt = manager
            .begin(vfs.clone(), context.clone(), PARENT, name.clone(), request(), transaction)
            .unwrap();
        let first = vfs.nfs4_open(&context, PARENT, &name, request(), transaction).await.unwrap();
        assert_eq!(first.value.object, FILE);

        // Simulate cancellation immediately after the backend committed and
        // an external namespace actor unlinked the just-created name.
        vfs.name_unlinked.store(true, Ordering::SeqCst);
        drop(attempt);
        manager.maintain(&runtime).await;

        assert_eq!(vfs.open_calls.load(Ordering::SeqCst), 2);
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
        assert_eq!(vfs.finishes.load(Ordering::SeqCst), 1);
        assert_eq!(manager.pending_work(), 0);
    }

    #[tokio::test]
    async fn failed_release_remains_bounded_and_is_retried() {
        let (vfs, manager, runtime, context) = fixture();
        let name = NfsName::new(b"new".to_vec()).unwrap();
        let transaction = transaction(2);
        let mut attempt = manager
            .begin(vfs.clone(), context.clone(), PARENT, name.clone(), request(), transaction)
            .unwrap();
        let opened = vfs.nfs4_open(&context, PARENT, &name, request(), transaction).await.unwrap();
        attempt.record_success(&opened);
        attempt.cleanup();

        vfs.release_failures.store(MAINTENANCE_WORK_LIMIT, Ordering::SeqCst);
        manager.maintain(&runtime).await;
        assert_eq!(manager.pending_work(), 1);
        vfs.release_failures.store(0, Ordering::SeqCst);
        manager.maintain(&runtime).await;
        assert_eq!(manager.pending_work(), 0);
        assert_eq!(vfs.finishes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn active_backend_outcome_is_not_finished_before_runtime_completion() {
        let (vfs, manager, runtime, context) = fixture();
        let attempt = manager
            .begin(vfs.clone(), context, PARENT, NfsName::new(b"new".to_vec()).unwrap(), request(), transaction(3))
            .unwrap();

        // Compound keeps this guard armed while owner replay persistence is
        // in progress. Concurrent maintenance must not retire the backend's
        // exact outcome record during that window.
        manager.maintain(&runtime).await;
        assert_eq!(vfs.finishes.load(Ordering::SeqCst), 0);
        assert_eq!(manager.pending_work(), 1);

        attempt.backend_failed();
        manager.maintain(&runtime).await;
        assert_eq!(vfs.finishes.load(Ordering::SeqCst), 1);
        assert_eq!(manager.pending_work(), 0);
    }

    #[tokio::test]
    async fn cancelled_standalone_retain_queues_idempotent_release() {
        let (vfs, manager, runtime, context) = fixture();
        let attempt = manager
            .begin_retain(
                vfs.clone(),
                context,
                RuntimeFile {
                    export_id: EXPORT_ID,
                    object: FILE,
                },
                [7; 16],
                true,
            )
            .unwrap();
        drop(attempt);
        manager.maintain(&runtime).await;
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
        assert_eq!(manager.pending_work(), 0);
    }

    #[tokio::test]
    async fn pin_release_waits_for_the_runtime_file_operation_gate() {
        let (vfs, manager, runtime, context) = fixture();
        let file = RuntimeFile {
            export_id: EXPORT_ID,
            object: FILE,
        };
        let attempt = manager.begin_retain(vfs.clone(), context, file, [8; 16], true).unwrap();
        drop(attempt);

        let gate = runtime.operation_gate(file).await;
        let maintenance = tokio::spawn({
            let manager = manager.clone();
            let runtime = runtime.clone();
            async move { manager.maintain(&runtime).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 0);

        drop(gate);
        maintenance.await.unwrap();
        assert_eq!(vfs.releases.load(Ordering::SeqCst), 1);
        assert_eq!(manager.pending_work(), 0);
    }

    #[test]
    fn reconciliation_never_consumes_a_live_atomic_commit_guard() {
        let (vfs, manager, runtime, context) = fixture();
        let mut transaction = transaction(31);
        transaction.acquire_pin = false;
        let mut attempt = manager
            .begin(vfs, context, PARENT, NfsName::new(b"live-atomic".to_vec()).unwrap(), request(), transaction)
            .unwrap();
        attempt.mark_committing(RuntimeFile {
            export_id: EXPORT_ID,
            object: FILE,
        });

        manager.reconcile_committing(&runtime);
        assert!(manager.lock().contains_operation(transaction.operation_id));
        attempt.cleanup();
        assert_eq!(manager.pending_work(), 1);
    }

    #[test]
    fn reconciliation_never_consumes_a_live_retain_commit_guard() {
        let (vfs, manager, runtime, context) = fixture();
        let file = RuntimeFile {
            export_id: EXPORT_ID,
            object: FILE,
        };
        let pin = [32; 16];
        let mut attempt = manager.begin_retain(vfs, context, file, pin, true).unwrap();
        attempt.mark_committing();

        manager.reconcile_committing(&runtime);
        assert!(manager.lock().retains.contains_key(&PinKey {
            export_id: EXPORT_ID,
            object: FILE,
            pin,
        }));
        attempt.cleanup();
        assert_eq!(manager.pending_work(), 1);
    }

    #[tokio::test]
    async fn cancelled_blocked_delegation_work_keeps_its_capacity_slot() {
        let (vfs, manager, runtime, context) = fixture_with_capacity(1);
        let attempt = manager
            .begin(
                vfs.clone(),
                context.clone(),
                PARENT,
                NfsName::new(b"first".to_vec()).unwrap(),
                request(),
                transaction(11),
            )
            .unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let caller = tokio::spawn({
            let manager = manager.clone();
            let entered = entered.clone();
            let release = release.clone();
            async move {
                manager
                    .run_critical(async move {
                        entered.notify_one();
                        release.notified().await;
                    })
                    .await;
            }
        });
        entered.notified().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        drop(attempt);

        let maintenance = tokio::spawn({
            let manager = manager.clone();
            let runtime = runtime.clone();
            async move { manager.maintain(&runtime).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(vfs.open_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            manager.begin(
                vfs.clone(),
                context,
                PARENT,
                NfsName::new(b"second".to_vec()).unwrap(),
                request(),
                transaction(12),
            ),
            Err(NfsStatus::Resource)
        ));

        release.notify_waiters();
        maintenance.await.unwrap();
        assert_eq!(vfs.open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(manager.pending_work(), 0);
    }

    #[test]
    fn claimed_delegation_work_remains_capacity_charged_until_completion() {
        let (vfs, manager, _runtime, context) = fixture_with_capacity(1);
        manager.lock().delegations.push_back(DelegationJob {
            cleanup: None,
            eligibility: None,
        });

        let claimed = manager.claim_work(false).expect("delegation work");
        assert_eq!(manager.pending_work(), 1);
        assert!(matches!(
            manager.begin(vfs, context, PARENT, NfsName::new(b"second".to_vec()).unwrap(), request(), transaction(41),),
            Err(NfsStatus::Resource)
        ));
        drop(claimed);
        assert_eq!(manager.pending_work(), 1, "cancelled claim must requeue in the same charged slot");

        let Some(ClaimedWork::Delegation(mut claimed)) = manager.claim_work(false) else {
            panic!("requeued delegation work");
        };
        claimed.complete(true);
        assert_eq!(manager.pending_work(), 0);
    }

    #[test]
    fn claimed_finish_work_remains_capacity_charged_until_completion() {
        let (vfs, manager, _runtime, context) = fixture_with_capacity(1);
        manager.lock().finishes.push_back(FinishJob {
            vfs: vfs.clone(),
            context: context.clone(),
            operation_id: 51,
            delegation: None,
            delegation_eligibility: None,
            in_flight: false,
        });

        let claimed = manager.claim_work(false).expect("finish work");
        assert_eq!(manager.pending_work(), 1);
        assert!(matches!(
            manager.begin(vfs, context, PARENT, NfsName::new(b"second".to_vec()).unwrap(), request(), transaction(52),),
            Err(NfsStatus::Resource)
        ));
        drop(claimed);
        assert_eq!(manager.pending_work(), 1, "cancelled claim must requeue in the same charged slot");

        let Some(ClaimedWork::Finish(mut claimed)) = manager.claim_work(false) else {
            panic!("requeued finish work");
        };
        claimed.complete(true);
        assert_eq!(manager.pending_work(), 0);
    }
}
