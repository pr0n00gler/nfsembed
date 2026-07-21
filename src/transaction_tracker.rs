use std::collections::{hash_map, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `TransactionTracker` tracks the state of transactions to detect retransmissions.
pub struct TransactionTracker {
    retention_period: Duration,
    state: Mutex<TrackerState>,
}

#[derive(Default)]
struct TrackerState {
    // Intern the client address once, then keep each client's XIDs in a nested
    // map so high request volume does not duplicate address strings.
    transactions: HashMap<Arc<str>, HashMap<u32, TransactionState>>,
    // Completion timestamps are appended monotonically under `state`'s lock,
    // allowing TTL cleanup to inspect only the queue front.
    completed_order: VecDeque<CompletedTransaction>,
}

struct CompletedTransaction {
    client_addr: Arc<str>,
    xid: u32,
    completed_at: Instant,
}

impl TransactionTracker {
    pub fn new(retention_period: Duration) -> Self {
        Self {
            retention_period,
            state: Mutex::new(TrackerState::default()),
        }
    }

    /// Checks if the transaction is a retransmission.
    /// If it's a new transaction, it is marked as `InProgress`.
    ///
    /// Returns `true` if the transaction is a retransmission, `false` otherwise.
    pub fn is_retransmission(&self, xid: u32, client_addr: &str) -> bool {
        let mut state = self.state.lock().expect("unable to unlock transactions mutex");
        housekeeping(&mut state, Instant::now(), self.retention_period);
        let transactions = if let Some(transactions) = state.transactions.get_mut(client_addr) {
            transactions
        } else {
            state.transactions.entry(Arc::from(client_addr)).or_default()
        };
        if let hash_map::Entry::Vacant(e) = transactions.entry(xid) {
            e.insert(TransactionState::InProgress);
            false
        } else {
            true
        }
    }

    /// Marks the transaction as processed.
    pub fn mark_processed(&self, xid: u32, client_addr: &str) {
        let mut state = self.state.lock().expect("unable to unlock transactions mutex");
        // Timestamp while holding the same lock that orders the queue so the
        // completion deque remains monotonically ordered for front-only TTL
        // expiry.
        let completed_at = Instant::now();
        let Some(client_key) = state.transactions.get_key_value(client_addr).map(|(key, _)| key.clone()) else {
            return;
        };
        if let Some(tx) = state
            .transactions
            .get_mut(client_addr)
            .and_then(|transactions| transactions.get_mut(&xid))
        {
            *tx = TransactionState::Completed(completed_at);
            state.completed_order.push_back(CompletedTransaction {
                client_addr: client_key,
                xid,
                completed_at,
            });
        }
    }
}

fn housekeeping(state: &mut TrackerState, now: Instant, max_age: Duration) {
    while state
        .completed_order
        .front()
        .is_some_and(|completed| now.saturating_duration_since(completed.completed_at) >= max_age)
    {
        let completed = state.completed_order.pop_front().expect("front checked above");
        let remove_client = if let Some(transactions) = state.transactions.get_mut(completed.client_addr.as_ref()) {
            // A later completion for the same XID supersedes this queued item;
            // compare timestamps before removing the current map entry.
            if matches!(transactions.get(&completed.xid), Some(TransactionState::Completed(at)) if *at == completed.completed_at)
            {
                transactions.remove(&completed.xid);
            }
            transactions.is_empty()
        } else {
            false
        };
        if remove_client {
            state.transactions.remove(completed.client_addr.as_ref());
        }
    }
}

#[derive(Clone, Copy)]
pub enum TransactionState {
    InProgress,
    Completed(Instant),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_in_progress_and_completed_retransmissions() {
        let tracker = TransactionTracker::new(Duration::from_secs(60));
        assert!(!tracker.is_retransmission(7, "client"));
        assert!(tracker.is_retransmission(7, "client"));
        tracker.mark_processed(7, "client");
        assert!(tracker.is_retransmission(7, "client"));
    }

    #[test]
    fn expires_completed_transactions_without_scanning_all_clients() {
        let tracker = TransactionTracker::new(Duration::ZERO);
        assert!(!tracker.is_retransmission(7, "client"));
        tracker.mark_processed(7, "client");
        assert!(!tracker.is_retransmission(7, "client"));
    }

    #[test]
    fn stores_one_address_for_many_transactions_from_the_same_client() {
        let tracker = TransactionTracker::new(Duration::from_secs(60));
        for xid in 0..128 {
            assert!(!tracker.is_retransmission(xid, "client"));
        }
        let state = tracker.state.lock().unwrap();
        assert_eq!(state.transactions.len(), 1);
        assert_eq!(state.transactions["client"].len(), 128);
    }
}
