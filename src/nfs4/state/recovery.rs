use std::collections::HashSet;
use std::hash::Hash;
use std::time::Duration;

use super::lease::LeaseClock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryMode {
    /// No prior reclaimable state is available. Reclaims are safely rejected.
    RejectReclaims,
    /// A bounded grace period backed by a recovered stable-state image.
    Grace,
    Normal,
}

#[derive(Debug)]
pub(crate) struct RecoveryState<C, T> {
    mode: RecoveryMode,
    grace_deadline: Option<Duration>,
    reclaimable_clients: HashSet<C>,
    clock: T,
}

impl<C, T> RecoveryState<C, T>
where
    C: Clone + Eq + Hash,
    T: LeaseClock,
{
    pub fn reject_reclaims(clock: T) -> Self {
        Self {
            mode: RecoveryMode::RejectReclaims,
            grace_deadline: None,
            reclaimable_clients: HashSet::new(),
            clock,
        }
    }

    pub fn from_recovered(
        clock: T,
        grace_duration: Duration,
        reclaimable_clients: impl IntoIterator<Item = C>,
    ) -> Result<Self, RecoveryConfigError> {
        if grace_duration.is_zero() {
            return Err(RecoveryConfigError::ZeroGrace);
        }
        Ok(Self {
            mode: RecoveryMode::Grace,
            grace_deadline: Some(clock.now().saturating_add(grace_duration)),
            reclaimable_clients: reclaimable_clients.into_iter().collect(),
            clock,
        })
    }

    /// Starts or extends grace when recovery state is imported after server
    /// startup, as happens at migration commit.
    pub fn begin_grace(
        &mut self,
        grace_duration: Duration,
        reclaimable_clients: impl IntoIterator<Item = C>,
    ) -> Result<Duration, RecoveryConfigError> {
        if grace_duration.is_zero() {
            return Err(RecoveryConfigError::ZeroGrace);
        }
        let deadline = self.clock.now().saturating_add(grace_duration);
        if self.mode != RecoveryMode::Grace {
            self.reclaimable_clients.clear();
        }
        self.mode = RecoveryMode::Grace;
        let effective_deadline = self.grace_deadline.map_or(deadline, |existing| existing.max(deadline));
        self.grace_deadline = Some(effective_deadline);
        self.reclaimable_clients.extend(reclaimable_clients);
        Ok(effective_deadline)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mode(&self) -> RecoveryMode {
        self.mode
    }

    /// Applies the common grace/reclaim gate used by OPEN and LOCK.
    pub fn allow(&mut self, client: &C, reclaim: bool) -> Result<(), RecoveryError> {
        match (self.mode, reclaim) {
            (RecoveryMode::RejectReclaims, true) | (RecoveryMode::Normal, true) => Err(RecoveryError::NoGrace),
            (RecoveryMode::RejectReclaims, false) | (RecoveryMode::Normal, false) => Ok(()),
            (RecoveryMode::Grace, false) => Err(RecoveryError::Grace),
            (RecoveryMode::Grace, true) if self.reclaimable_clients.contains(client) => Ok(()),
            (RecoveryMode::Grace, true) => Err(RecoveryError::ReclaimBad),
        }
    }

    pub fn complete_client_reclaim(&mut self, client: &C) {
        self.reclaimable_clients.remove(client);
    }

    pub fn add_reclaimable(&mut self, client: C) {
        if self.mode == RecoveryMode::Grace {
            self.reclaimable_clients.insert(client);
        }
    }

    pub fn end_grace(&mut self) {
        self.mode = RecoveryMode::Normal;
        self.grace_deadline = None;
        self.reclaimable_clients.clear();
    }

    /// Grace remains active after its time bound until the caller has durably
    /// revoked unreclaimed state and explicitly calls [`Self::end_grace`].
    pub fn cleanup_due(&self) -> bool {
        self.mode == RecoveryMode::Grace && self.grace_deadline.is_some_and(|deadline| deadline <= self.clock.now())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RecoveryConfigError {
    #[error("NFSv4 grace duration must be non-zero")]
    ZeroGrace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RecoveryError {
    #[error("server is in its recovery grace period")]
    Grace,
    #[error("server has no grace period in which this state can be reclaimed")]
    NoGrace,
    #[error("client is not eligible to reclaim this state")]
    ReclaimBad,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs4::state::lease::ManualLeaseClock;

    #[test]
    fn durable_grace_allows_only_known_reclaims() {
        let clock = ManualLeaseClock::default();
        let mut recovery = RecoveryState::from_recovered(clock, Duration::from_secs(90), [7u64]).unwrap();
        assert_eq!(recovery.allow(&7, false), Err(RecoveryError::Grace));
        assert_eq!(recovery.allow(&8, true), Err(RecoveryError::ReclaimBad));
        assert_eq!(recovery.allow(&7, true), Ok(()));
    }

    #[test]
    fn in_memory_mode_rejects_reclaims_without_blocking_new_state() {
        let mut recovery = RecoveryState::reject_reclaims(ManualLeaseClock::default());
        assert_eq!(recovery.allow(&1u64, true), Err(RecoveryError::NoGrace));
        assert_eq!(recovery.allow(&1, false), Ok(()));
    }

    #[test]
    fn grace_ends_only_after_explicit_cleanup() {
        let clock = ManualLeaseClock::default();
        let mut recovery = RecoveryState::from_recovered(clock, Duration::from_secs(5), [1u64]).unwrap();
        recovery.clock.advance(Duration::from_secs(5));
        assert!(recovery.cleanup_due());
        assert_eq!(recovery.mode(), RecoveryMode::Grace);
        assert_eq!(recovery.allow(&1, false), Err(RecoveryError::Grace));
        recovery.end_grace();
        assert_eq!(recovery.mode(), RecoveryMode::Normal);
        assert_eq!(recovery.allow(&1, true), Err(RecoveryError::NoGrace));
    }

    #[test]
    fn imported_recovery_reenters_and_extends_grace() {
        let clock = std::sync::Arc::new(ManualLeaseClock::default());
        let mut recovery = RecoveryState::reject_reclaims(clock.clone());
        assert_eq!(recovery.allow(&7u64, false), Ok(()));

        assert_eq!(recovery.begin_grace(Duration::from_secs(5), [7]).unwrap(), Duration::from_secs(5));
        assert_eq!(recovery.allow(&8, false), Err(RecoveryError::Grace));
        assert_eq!(recovery.allow(&7, true), Ok(()));

        clock.advance(Duration::from_secs(3));
        assert_eq!(recovery.begin_grace(Duration::from_secs(5), [8]).unwrap(), Duration::from_secs(8));
        clock.advance(Duration::from_secs(2));
        assert_eq!(recovery.allow(&8, true), Ok(()));
        assert_eq!(recovery.allow(&9, false), Err(RecoveryError::Grace));
    }
}
