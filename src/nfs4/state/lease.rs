use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) trait LeaseClock: Send + Sync + 'static {
    fn now(&self) -> Duration;
}

impl<T> LeaseClock for Arc<T>
where
    T: LeaseClock + ?Sized,
{
    fn now(&self) -> Duration {
        (**self).now()
    }
}

#[derive(Debug)]
pub(crate) struct SystemLeaseClock {
    origin: Instant,
}

impl SystemLeaseClock {
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl LeaseClock for SystemLeaseClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ManualLeaseClock {
    now: Mutex<Duration>,
}

impl ManualLeaseClock {
    #[cfg(test)]
    pub fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("manual lease clock poisoned");
        *now = now.saturating_add(duration);
    }
}

impl LeaseClock for ManualLeaseClock {
    fn now(&self) -> Duration {
        *self.now.lock().expect("manual lease clock poisoned")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Lease {
    deadline: Duration,
}

/// One common lease deadline for every piece of state owned by a client.
#[derive(Debug)]
pub(crate) struct LeaseTable<C, T> {
    duration: Duration,
    clock: T,
    clients: HashMap<C, Lease>,
}

impl<C, T> LeaseTable<C, T>
where
    C: Clone + Eq + Hash,
    T: LeaseClock,
{
    pub fn new(duration: Duration, clock: T) -> Result<Self, LeaseConfigError> {
        if duration.is_zero() {
            return Err(LeaseConfigError::ZeroDuration);
        }
        Ok(Self {
            duration,
            clock,
            clients: HashMap::new(),
        })
    }

    /// Starts the common lease after client confirmation. SETCLIENTID itself
    /// deliberately does not call this method.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn confirm(&mut self, client: C) {
        self.clients.insert(
            client,
            Lease {
                deadline: self.deadline_from_now(),
            },
        );
    }

    /// Starts a client's first lease or renews an existing live lease.
    ///
    /// The runtime calls this only after an operation has supplied a valid
    /// confirmed clientid or non-special stateid. SETCLIENTID and
    /// SETCLIENTID_CONFIRM themselves deliberately do not call it.
    pub fn touch(&mut self, client: C) -> Result<(), LeaseError> {
        let now = self.clock.now();
        if self.clients.get(&client).is_some_and(|lease| lease.deadline <= now) {
            return Err(LeaseError::Expired);
        }
        self.clients.insert(
            client,
            Lease {
                deadline: now.saturating_add(self.duration),
            },
        );
        Ok(())
    }

    /// Renews all state for a confirmed client after an RFC-renewing
    /// operation. SETCLIENTID and SETCLIENTID_CONFIRM callers must not invoke
    /// this method.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn renew(&mut self, client: &C) -> Result<(), LeaseError> {
        let deadline = self.deadline_from_now();
        let lease = self.clients.get_mut(client).ok_or(LeaseError::UnknownClient)?;
        if lease.deadline <= self.clock.now() {
            return Err(LeaseError::Expired);
        }
        lease.deadline = deadline;
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_active(&self, client: &C) -> bool {
        self.clients.get(client).is_some_and(|lease| lease.deadline > self.clock.now())
    }

    /// Removes and returns every client whose lease has expired. State
    /// revocation is performed by the caller after releasing this table.
    pub fn expire_due(&mut self) -> Vec<C> {
        let now = self.clock.now();
        let expired: Vec<_> = self
            .clients
            .iter()
            .filter_map(|(client, lease)| (lease.deadline <= now).then_some(client.clone()))
            .collect();
        for client in &expired {
            self.clients.remove(client);
        }
        expired
    }

    pub fn remove(&mut self, client: &C) -> bool {
        self.clients.remove(client).is_some()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn remaining(&self, client: &C) -> Option<Duration> {
        let now = self.clock.now();
        self.clients.get(client).map(|lease| lease.deadline.saturating_sub(now))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn deadline_from_now(&self) -> Duration {
        self.clock.now().saturating_add(self.duration)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum LeaseConfigError {
    #[error("NFSv4 lease duration must be non-zero")]
    ZeroDuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum LeaseError {
    #[error("unknown NFSv4 client")]
    #[cfg_attr(not(test), allow(dead_code))]
    UnknownClient,
    #[error("NFSv4 client lease has expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_renewal_extends_the_clients_common_lease() {
        let clock = ManualLeaseClock::default();
        let mut leases = LeaseTable::new(Duration::from_secs(90), clock).unwrap();
        leases.confirm(7u64);
        leases.clock.advance(Duration::from_secs(80));
        leases.renew(&7).unwrap();
        leases.clock.advance(Duration::from_secs(20));
        assert!(leases.is_active(&7));
        assert_eq!(leases.remaining(&7), Some(Duration::from_secs(70)));
    }

    #[test]
    fn expiry_is_reported_once_for_out_of_lock_revocation() {
        let clock = ManualLeaseClock::default();
        let mut leases = LeaseTable::new(Duration::from_secs(5), clock).unwrap();
        leases.confirm(1u64);
        leases.confirm(2u64);
        leases.clock.advance(Duration::from_secs(5));
        let mut expired = leases.expire_due();
        expired.sort_unstable();
        assert_eq!(expired, vec![1, 2]);
        assert!(leases.expire_due().is_empty());
    }

    #[test]
    fn an_expired_lease_cannot_be_resurrected_by_renew() {
        let clock = ManualLeaseClock::default();
        let mut leases = LeaseTable::new(Duration::from_secs(1), clock).unwrap();
        leases.confirm(9u64);
        leases.clock.advance(Duration::from_secs(2));
        assert_eq!(leases.renew(&9), Err(LeaseError::Expired));
    }
}
