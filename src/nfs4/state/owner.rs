/// Digest of the complete state-owner operation that consumes a sequence ID.
///
/// The RPC XID is intentionally not part of this value: RFC 7530 requires an
/// owner replay to work when a retry uses a different XID or connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OwnerRequestDigest(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerReplay<R, E> {
    pub sequence_id: u32,
    pub digest: OwnerRequestDigest,
    pub result: R,
    /// Effects on the surrounding COMPOUND context, such as changing the
    /// current filehandle after a replayed OPEN.
    pub context_effect: E,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SequenceDecision<R, E> {
    Execute,
    Replay { result: R, context_effect: E },
    InProgress,
    BadSequence,
}

/// Non-evictable replay state for one live open-owner or lock-owner.
#[derive(Clone, Debug)]
pub(crate) struct OwnerSequence<R, E> {
    initial_sequence_id: u32,
    last: Option<OwnerReplay<R, E>>,
    pending: Option<(u32, OwnerRequestDigest)>,
}

impl<R, E> OwnerSequence<R, E>
where
    R: Clone,
    E: Clone,
{
    pub fn new(initial_sequence_id: u32) -> Self {
        Self {
            initial_sequence_id,
            last: None,
            pending: None,
        }
    }

    pub fn decide(&self, sequence_id: u32, digest: OwnerRequestDigest) -> SequenceDecision<R, E> {
        if let Some((pending_sequence, pending_digest)) = self.pending {
            return if sequence_id == pending_sequence && digest == pending_digest {
                SequenceDecision::InProgress
            } else {
                SequenceDecision::BadSequence
            };
        }
        let Some(last) = &self.last else {
            return if sequence_id == self.initial_sequence_id {
                SequenceDecision::Execute
            } else {
                SequenceDecision::BadSequence
            };
        };

        if sequence_id == last.sequence_id {
            return if digest == last.digest {
                SequenceDecision::Replay {
                    result: last.result.clone(),
                    context_effect: last.context_effect.clone(),
                }
            } else {
                SequenceDecision::BadSequence
            };
        }

        if sequence_id == next_sequence_id(last.sequence_id) {
            SequenceDecision::Execute
        } else {
            SequenceDecision::BadSequence
        }
    }

    /// Atomically marks the next owner request as executing.  An exact
    /// concurrent retransmission observes `InProgress`; it must never execute
    /// the non-idempotent operation a second time.
    pub fn reserve(&mut self, sequence_id: u32, digest: OwnerRequestDigest) -> SequenceDecision<R, E> {
        let decision = self.decide(sequence_id, digest);
        if matches!(decision, SequenceDecision::Execute) {
            self.pending = Some((sequence_id, digest));
        }
        decision
    }

    pub fn cancel(&mut self, sequence_id: u32, digest: OwnerRequestDigest) -> bool {
        if self.pending == Some((sequence_id, digest)) {
            self.pending = None;
            true
        } else {
            false
        }
    }

    /// Records the result of an operation whose status consumes the seqid.
    ///
    /// Callers must use the RFC operation-specific exception table before
    /// invoking this method; errors listed as non-consuming are not recorded.
    pub fn commit(
        &mut self,
        sequence_id: u32,
        digest: OwnerRequestDigest,
        result: R,
        context_effect: E,
    ) -> Result<(), SequenceCommitError> {
        if self.pending == Some((sequence_id, digest)) {
            self.pending = None;
        } else if !matches!(self.decide(sequence_id, digest), SequenceDecision::Execute) {
            return Err(SequenceCommitError::NotExecutable);
        }
        self.last = Some(OwnerReplay {
            sequence_id,
            digest,
            result,
            context_effect,
        });
        Ok(())
    }

    pub fn last(&self) -> Option<&OwnerReplay<R, E>> {
        self.last.as_ref()
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}

fn next_sequence_id(current: u32) -> u32 {
    if current == u32::MAX {
        1
    } else {
        current + 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SequenceCommitError {
    #[error("state-owner sequence ID is not executable")]
    NotExecutable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> OwnerRequestDigest {
        OwnerRequestDigest([value; 32])
    }

    #[test]
    fn exact_retry_replays_result_and_compound_effect() {
        let mut sequence = OwnerSequence::new(0);
        assert_eq!(sequence.decide(0, digest(1)), SequenceDecision::Execute);
        sequence.commit(0, digest(1), "open-result", "set-current-fh").unwrap();
        assert_eq!(
            sequence.decide(0, digest(1)),
            SequenceDecision::Replay {
                result: "open-result",
                context_effect: "set-current-fh",
            }
        );
    }

    #[test]
    fn same_seqid_with_different_request_is_bad() {
        let mut sequence = OwnerSequence::new(0);
        sequence.commit(0, digest(1), (), ()).unwrap();
        assert_eq!(sequence.decide(0, digest(2)), SequenceDecision::BadSequence);
    }

    #[test]
    fn sequence_ids_wrap_modulo_u32() {
        let mut sequence = OwnerSequence::new(u32::MAX);
        sequence.commit(u32::MAX, digest(1), (), ()).unwrap();
        assert_eq!(sequence.decide(1, digest(2)), SequenceDecision::Execute);
        assert_eq!(sequence.decide(0, digest(2)), SequenceDecision::BadSequence);
    }

    #[test]
    fn skipped_or_old_sequence_ids_are_bad() {
        let mut sequence = OwnerSequence::new(7);
        sequence.commit(7, digest(1), (), ()).unwrap();
        assert_eq!(sequence.decide(9, digest(2)), SequenceDecision::BadSequence);
        assert_eq!(sequence.decide(6, digest(3)), SequenceDecision::BadSequence);
    }

    #[test]
    fn reservation_blocks_concurrent_execution_and_can_be_cancelled() {
        let mut sequence = OwnerSequence::<(), ()>::new(4);
        assert_eq!(sequence.reserve(4, digest(1)), SequenceDecision::Execute);
        assert_eq!(sequence.decide(4, digest(1)), SequenceDecision::InProgress);
        assert_eq!(sequence.decide(4, digest(2)), SequenceDecision::BadSequence);
        assert!(sequence.cancel(4, digest(1)));
        assert_eq!(sequence.reserve(4, digest(1)), SequenceDecision::Execute);
        sequence.commit(4, digest(1), (), ()).unwrap();
        assert_eq!(
            sequence.decide(4, digest(1)),
            SequenceDecision::Replay {
                result: (),
                context_effect: (),
            }
        );
    }
}
