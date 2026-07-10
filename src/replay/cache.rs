use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::vfs::ExportId;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReplayKey {
    pub client_addr: SocketAddr,
    pub export_id: ExportId,
    pub xid: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestFingerprint(pub [u8; 32]);

pub enum ReplayDecision {
    Execute(ReplayLease),
    Replay(Bytes),
    Wait(oneshot::Receiver<Result<Bytes, ReplayError>>),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayError {
    #[error("replay cache capacity is exhausted by in-flight requests")]
    Capacity,
    #[error("the original request was cancelled")]
    Cancelled,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayEntryKey {
    request: ReplayKey,
    fingerprint: RequestFingerprint,
    generation: u64,
}

#[derive(Clone, Copy)]
struct LatestGeneration {
    fingerprint: RequestFingerprint,
    generation: u64,
}

enum ReplayState {
    InFlight {
        waiters: Vec<oneshot::Sender<Result<Bytes, ReplayError>>>,
    },
    Completed {
        encoded_reply: Bytes,
        completed_at: Instant,
    },
}

/// Ownership token for an in-flight replay entry. Dropping an unfinished
/// lease cancels the entry and releases all exact-duplicate waiters.
pub struct ReplayLease {
    cache: Arc<ReplayCache>,
    key: ReplayEntryKey,
    finished: bool,
}

impl ReplayLease {
    pub fn complete(mut self, reply: Bytes) {
        self.cache.complete(&self.key, reply);
        self.finished = true;
    }

    pub fn cancel(mut self) {
        self.cache.cancel(&self.key);
        self.finished = true;
    }
}

impl Drop for ReplayLease {
    fn drop(&mut self) {
        if !self.finished {
            self.cache.cancel(&self.key);
        }
    }
}

pub struct ReplayCache {
    capacity: usize,
    max_completed_bytes: usize,
    ttl: Duration,
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    entries: HashMap<ReplayEntryKey, ReplayState>,
    latest: HashMap<ReplayKey, LatestGeneration>,
    completed_bytes: usize,
    next_generation: u64,
}

impl ReplayCache {
    pub fn new(capacity: usize, max_completed_bytes: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            max_completed_bytes,
            ttl,
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                latest: HashMap::new(),
                completed_bytes: 0,
                next_generation: 0,
            }),
        }
    }

    pub async fn begin(
        self: &Arc<Self>,
        key: ReplayKey,
        fingerprint: RequestFingerprint,
    ) -> Result<ReplayDecision, ReplayError> {
        let now = Instant::now();
        let mut inner = self.inner();
        Self::expire(&mut inner, now, self.ttl);
        if let Some(latest) = inner.latest.get(&key).copied() {
            if latest.fingerprint == fingerprint {
                let entry_key = ReplayEntryKey {
                    request: key.clone(),
                    fingerprint,
                    generation: latest.generation,
                };
                if let Some(state) = inner.entries.get_mut(&entry_key) {
                    match state {
                        ReplayState::InFlight { waiters } => {
                            // Duplicate callers share only the current
                            // generation. Closed waiters are discarded before
                            // adding the new receiver so a disconnected client
                            // cannot consume cache capacity.
                            waiters.retain(|waiter| !waiter.is_closed());
                            let (send, receive) = oneshot::channel();
                            waiters.push(send);
                            return Ok(ReplayDecision::Wait(receive));
                        },
                        ReplayState::Completed { encoded_reply, .. } => {
                            return Ok(ReplayDecision::Replay(encoded_reply.clone()));
                        },
                    }
                }
            }
        }

        Self::remove_completed_for_request(&mut inner, &key);
        if inner.entries.len() >= self.capacity && !Self::evict_oldest_completed(&mut inner) {
            return Err(ReplayError::Capacity);
        }
        let generation = inner.next_generation;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        let entry_key = ReplayEntryKey {
            request: key.clone(),
            fingerprint,
            generation,
        };
        inner.latest.insert(
            key,
            LatestGeneration {
                fingerprint,
                generation,
            },
        );
        inner
            .entries
            .insert(entry_key.clone(), ReplayState::InFlight { waiters: Vec::new() });
        Ok(ReplayDecision::Execute(ReplayLease {
            cache: self.clone(),
            key: entry_key,
            finished: false,
        }))
    }

    /// Stores the reply before callers attempt socket delivery.
    fn complete(&self, key: &ReplayEntryKey, reply: Bytes) {
        let mut inner = self.inner();
        let waiters = match inner.entries.remove(key) {
            Some(ReplayState::InFlight { waiters }) => waiters,
            Some(state) => {
                inner.entries.insert(key.clone(), state);
                return;
            },
            None => return,
        };
        let is_latest = Self::is_latest(&inner, key);
        let mut retained = false;
        if is_latest && reply.len() <= self.max_completed_bytes {
            while inner.completed_bytes.saturating_add(reply.len()) > self.max_completed_bytes {
                if !Self::evict_oldest_completed(&mut inner) {
                    break;
                }
            }
            if inner.completed_bytes.saturating_add(reply.len()) <= self.max_completed_bytes {
                inner.completed_bytes = inner.completed_bytes.saturating_add(reply.len());
                inner.entries.insert(
                    key.clone(),
                    ReplayState::Completed {
                        encoded_reply: reply.clone(),
                        completed_at: Instant::now(),
                    },
                );
                retained = true;
            }
        }
        if is_latest && !retained {
            inner.latest.remove(&key.request);
        }
        for waiter in waiters {
            let _ = waiter.send(Ok(reply.clone()));
        }
    }

    fn cancel(&self, key: &ReplayEntryKey) {
        let mut inner = self.inner();
        let waiters = match inner.entries.remove(key) {
            Some(ReplayState::InFlight { waiters }) => waiters,
            Some(state) => {
                inner.entries.insert(key.clone(), state);
                Vec::new()
            },
            None => Vec::new(),
        };
        if Self::is_latest(&inner, key) {
            inner.latest.remove(&key.request);
        }
        for waiter in waiters {
            let _ = waiter.send(Err(ReplayError::Cancelled));
        }
    }

    pub async fn len(&self) -> usize {
        self.inner().entries.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner().entries.is_empty()
    }

    pub async fn retained_bytes(&self) -> usize {
        self.inner().completed_bytes
    }

    fn inner(&self) -> MutexGuard<'_, CacheInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn expire(inner: &mut CacheInner, now: Instant, ttl: Duration) {
        let expired = inner
            .entries
            .iter()
            .filter_map(|(key, state)| match state {
                ReplayState::Completed { completed_at, .. } if now.duration_since(*completed_at) >= ttl => {
                    Some(key.clone())
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        for key in expired {
            Self::remove_completed(inner, &key);
        }
    }

    fn remove_completed_for_request(inner: &mut CacheInner, request: &ReplayKey) {
        let completed = inner
            .entries
            .iter()
            .filter_map(|(key, state)| {
                (&key.request == request && matches!(state, ReplayState::Completed { .. })).then_some(key.clone())
            })
            .collect::<Vec<_>>();
        for key in completed {
            Self::remove_completed(inner, &key);
        }
    }

    fn remove_completed(inner: &mut CacheInner, key: &ReplayEntryKey) {
        if let Some(ReplayState::Completed { encoded_reply, .. }) = inner.entries.remove(key) {
            inner.completed_bytes = inner.completed_bytes.saturating_sub(encoded_reply.len());
        }
        if Self::is_latest(inner, key) {
            inner.latest.remove(&key.request);
        }
    }

    fn is_latest(inner: &CacheInner, key: &ReplayEntryKey) -> bool {
        inner
            .latest
            .get(&key.request)
            .is_some_and(|latest| latest.generation == key.generation && latest.fingerprint == key.fingerprint)
    }

    fn evict_oldest_completed(inner: &mut CacheInner) -> bool {
        let oldest = inner
            .entries
            .iter()
            .filter_map(|(key, state)| match state {
                ReplayState::Completed { completed_at, .. } => Some((key.clone(), *completed_at)),
                ReplayState::InFlight { .. } => None,
            })
            .min_by_key(|(_, completed_at)| *completed_at)
            .map(|(key, _)| key);
        if let Some(oldest) = oldest {
            Self::remove_completed(inner, &oldest);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(xid: u32) -> ReplayKey {
        ReplayKey {
            client_addr: "127.0.0.1:1234".parse().unwrap(),
            export_id: ExportId(1),
            xid,
        }
    }

    #[tokio::test]
    async fn duplicates_wait_then_replay() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([7; 32]);
        let lease = match cache.begin(key(1), fingerprint).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        let waiter = match cache.begin(key(1), fingerprint).await.unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected waiter"),
        };
        lease.complete(Bytes::from_static(b"reply"));
        assert_eq!(waiter.await.unwrap().unwrap(), Bytes::from_static(b"reply"));
        assert!(matches!(cache.begin(key(1), fingerprint).await.unwrap(), ReplayDecision::Replay(_)));
    }

    #[tokio::test]
    async fn different_fingerprint_is_xid_reuse() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let first = match cache.begin(key(1), RequestFingerprint([1; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        let second = match cache.begin(key(1), RequestFingerprint([2; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected XID reuse execution"),
        };
        drop((first, second));
    }

    #[tokio::test]
    async fn cancelled_leader_releases_waiters_and_capacity() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([3; 32]);
        let lease = match cache.begin(key(1), fingerprint).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        let waiter = match cache.begin(key(1), fingerprint).await.unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected waiter"),
        };
        drop(lease);
        assert_eq!(waiter.await.unwrap(), Err(ReplayError::Cancelled));
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn capacity_one_allows_completed_xid_reuse() {
        let cache = Arc::new(ReplayCache::new(1, 1024, Duration::from_secs(10)));
        let first = match cache.begin(key(1), RequestFingerprint([1; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        first.complete(Bytes::from_static(b"first"));
        assert!(matches!(
            cache.begin(key(1), RequestFingerprint([2; 32])).await.unwrap(),
            ReplayDecision::Execute(_)
        ));
    }

    #[tokio::test]
    async fn xid_reuse_history_treats_a_b_a_as_three_generations() {
        let cache = Arc::new(ReplayCache::new(4, 1024, Duration::from_secs(10)));
        let fingerprint_a = RequestFingerprint([1; 32]);
        let fingerprint_b = RequestFingerprint([2; 32]);
        let first = match cache.begin(key(1), fingerprint_a).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        let first_waiter = match cache.begin(key(1), fingerprint_a).await.unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected a waiter for the first A generation"),
        };
        let second = match cache.begin(key(1), fingerprint_b).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected B execution"),
        };
        let third = match cache.begin(key(1), fingerprint_a).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected a new A execution instead of waiting for the old generation"),
        };
        let third_waiter = match cache.begin(key(1), fingerprint_a).await.unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected a waiter for the latest A generation"),
        };

        first.complete(Bytes::from_static(b"first-a"));
        assert_eq!(first_waiter.await.unwrap().unwrap(), Bytes::from_static(b"first-a"));
        second.complete(Bytes::from_static(b"b"));
        third.complete(Bytes::from_static(b"third-a"));
        assert_eq!(third_waiter.await.unwrap().unwrap(), Bytes::from_static(b"third-a"));
        assert!(matches!(cache.begin(key(1), fingerprint_a).await.unwrap(), ReplayDecision::Replay(_)));
    }

    #[tokio::test]
    async fn completed_reply_bytes_evict_old_entries_and_skip_oversized_replies() {
        let cache = Arc::new(ReplayCache::new(4, 5, Duration::from_secs(10)));
        let first = match cache.begin(key(1), RequestFingerprint([1; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        first.complete(Bytes::from_static(b"1234"));
        let second = match cache.begin(key(2), RequestFingerprint([2; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected second execution"),
        };
        second.complete(Bytes::from_static(b"5678"));
        assert_eq!(cache.retained_bytes().await, 4);
        assert_eq!(cache.len().await, 1);
        assert!(matches!(
            cache.begin(key(1), RequestFingerprint([1; 32])).await.unwrap(),
            ReplayDecision::Execute(_)
        ));

        let oversized = match cache.begin(key(3), RequestFingerprint([3; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected oversized execution"),
        };
        oversized.complete(Bytes::from_static(b"123456"));
        assert!(cache.retained_bytes().await <= 5);
        assert!(!matches!(
            cache.begin(key(3), RequestFingerprint([3; 32])).await.unwrap(),
            ReplayDecision::Replay(_)
        ));

        for xid in 10..100 {
            let lease = match cache.begin(key(xid), RequestFingerprint([xid as u8; 32])).await.unwrap() {
                ReplayDecision::Execute(lease) => lease,
                _ => panic!("expected oversized execution"),
            };
            lease.complete(Bytes::from_static(b"123456"));
        }
        let inner = cache.inner();
        assert!(inner.latest.len() <= inner.entries.len());
        assert!(inner.entries.len() <= cache.capacity);
    }

    #[tokio::test]
    async fn concurrent_xid_reuse_does_not_cancel_exact_waiters() {
        let cache = Arc::new(ReplayCache::new(4, 1024, Duration::from_secs(10)));
        let first_fingerprint = RequestFingerprint([1; 32]);
        let first = match cache.begin(key(1), first_fingerprint).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected first execution"),
        };
        let waiter = match cache.begin(key(1), first_fingerprint).await.unwrap() {
            ReplayDecision::Wait(waiter) => waiter,
            _ => panic!("expected exact waiter"),
        };
        let reused = match cache.begin(key(1), RequestFingerprint([2; 32])).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected independent XID reuse"),
        };
        first.complete(Bytes::from_static(b"first"));
        assert_eq!(waiter.await.unwrap().unwrap(), Bytes::from_static(b"first"));
        drop(reused);
    }

    #[tokio::test]
    async fn ttl_never_expires_a_live_leader() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::ZERO));
        let fingerprint = RequestFingerprint([4; 32]);
        let lease = match cache.begin(key(1), fingerprint).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        assert!(matches!(cache.begin(key(1), fingerprint).await.unwrap(), ReplayDecision::Wait(_)));
        drop(lease);
    }

    #[tokio::test]
    async fn disconnected_duplicate_waiters_do_not_exhaust_entry_capacity() {
        let cache = Arc::new(ReplayCache::new(2, 1024, Duration::from_secs(10)));
        let fingerprint = RequestFingerprint([5; 32]);
        let lease = match cache.begin(key(1), fingerprint).await.unwrap() {
            ReplayDecision::Execute(lease) => lease,
            _ => panic!("expected execution lease"),
        };
        for _ in 0..8 {
            let waiter = match cache.begin(key(1), fingerprint).await.unwrap() {
                ReplayDecision::Wait(waiter) => waiter,
                _ => panic!("expected duplicate waiter"),
            };
            drop(waiter);
        }

        assert!(matches!(
            cache.begin(key(2), RequestFingerprint([6; 32])).await.unwrap(),
            ReplayDecision::Execute(_)
        ));
        drop(lease);
    }
}
