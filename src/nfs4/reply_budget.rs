//! Exact incremental accounting for bounded NFSv4 COMPOUND replies.
//!
//! RPC record limits are enforced again by the final encoder. This layer is
//! earlier: it lets execution cap read-only results and refuse a later
//! state-changing operation before that operation can have side effects whose
//! successful result no longer fits on the wire.

use super::codec::{encoded_compound_res_len, encoded_res_op_len};
use super::types::ResOp;
use crate::rpc::codec::EncodeError;

/// Every simple operation error is an operation number followed by status.
pub(crate) const SIMPLE_ERROR_RESULT_BYTES: usize = 8;

/// Successful state-changing NFSv4.0 results are fixed and comfortably below
/// this bound, including OPEN with the library's bounded delegation ACE.
///
/// Variable-size failure arms such as LOCK denial and SETCLIENTID client
/// address diagnostics do not acknowledge a side effect and are handled by
/// the exact post-execution check.
pub(crate) const SIDE_EFFECT_RESULT_RESERVE: usize = 256;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CompoundReplyBudget<'a> {
    tag: &'a [u8],
    max_body_bytes: usize,
}

impl<'a> CompoundReplyBudget<'a> {
    pub(crate) const fn new(tag: &'a [u8], max_body_bytes: usize) -> Self {
        Self { tag, max_body_bytes }
    }

    pub(crate) fn used(&self, completed: &[ResOp]) -> Result<usize, EncodeError> {
        encoded_compound_res_len(self.tag, completed)
    }

    pub(crate) fn remaining(&self, completed: &[ResOp]) -> Result<usize, EncodeError> {
        Ok(self.max_body_bytes.saturating_sub(self.used(completed)?))
    }

    #[cfg(test)]
    pub(crate) fn result_fits(&self, completed: &[ResOp], result: &ResOp) -> Result<bool, EncodeError> {
        Ok(encoded_res_op_len(result)? <= self.remaining(completed)?)
    }

    pub(crate) fn result_fits_with_reserve(
        &self,
        completed: &[ResOp],
        result: &ResOp,
        reserve_after: usize,
    ) -> Result<bool, EncodeError> {
        let available = self.remaining(completed)?;
        Ok(encoded_res_op_len(result)?
            .checked_add(reserve_after)
            .is_some_and(|required| required <= available))
    }

    pub(crate) fn can_start_side_effect(&self, completed: &[ResOp], reserve_after: usize) -> Result<bool, EncodeError> {
        let available = self.remaining(completed)?;
        Ok(SIDE_EFFECT_RESULT_RESERVE
            .checked_add(reserve_after)
            .is_some_and(|required| required <= available))
    }

    /// Maximum READ payload that leaves `reserve_after` bytes for a following
    /// result. The fixed successful READ result is:
    ///
    /// `opnum + status + eof + opaque-length == 16 bytes`.
    #[cfg(test)]
    pub(crate) fn read_data_limit(
        &self,
        completed: &[ResOp],
        requested: u32,
        reserve_after: usize,
    ) -> Result<Option<u32>, EncodeError> {
        const READ_FIXED_BYTES: usize = 16;
        let available = self.remaining(completed)?.saturating_sub(reserve_after);
        if available < READ_FIXED_BYTES {
            return Ok(None);
        }
        let payload = (available - READ_FIXED_BYTES) & !3;
        Ok(Some(requested.min(u32::try_from(payload).unwrap_or(u32::MAX))))
    }

    /// Maximum complete encoded operation result while retaining the requested
    /// following-result reserve.
    pub(crate) fn operation_result_limit(
        &self,
        completed: &[ResOp],
        reserve_after: usize,
    ) -> Result<usize, EncodeError> {
        Ok(self.remaining(completed)?.saturating_sub(reserve_after))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs4::types::{NfsResult, NfsStatus, ReadOk, ResOp};

    #[test]
    fn exact_result_fit_uses_xdr_padding() {
        let completed = [ResOp::PutRootFh(NfsStatus::Ok)];
        let result = ResOp::Read(NfsResult::Ok(ReadOk {
            eof: false,
            data: vec![1; 5],
        }));
        let used = encoded_compound_res_len(b"x", &completed).unwrap();
        let result_size = encoded_res_op_len(&result).unwrap();
        let exact = CompoundReplyBudget::new(b"x", used + result_size);
        assert!(exact.result_fits(&completed, &result).unwrap());

        let short = CompoundReplyBudget::new(b"x", used + result_size - 1);
        assert!(!short.result_fits(&completed, &result).unwrap());
    }

    #[test]
    fn read_limit_leaves_space_for_following_error() {
        let completed = [ResOp::PutRootFh(NfsStatus::Ok)];
        let used = encoded_compound_res_len(b"", &completed).unwrap();
        let budget = CompoundReplyBudget::new(b"", used + 16 + 12 + SIMPLE_ERROR_RESULT_BYTES);
        assert_eq!(budget.read_data_limit(&completed, u32::MAX, SIMPLE_ERROR_RESULT_BYTES).unwrap(), Some(12));
    }

    #[test]
    fn side_effect_reservation_is_conservative() {
        let completed = [ResOp::PutRootFh(NfsStatus::Ok)];
        let used = encoded_compound_res_len(b"", &completed).unwrap();
        let exact = CompoundReplyBudget::new(b"", used + SIDE_EFFECT_RESULT_RESERVE + SIMPLE_ERROR_RESULT_BYTES);
        assert!(exact.can_start_side_effect(&completed, SIMPLE_ERROR_RESULT_BYTES).unwrap());

        let short = CompoundReplyBudget::new(b"", used + SIDE_EFFECT_RESULT_RESERVE + SIMPLE_ERROR_RESULT_BYTES - 1);
        assert!(!short.can_start_side_effect(&completed, SIMPLE_ERROR_RESULT_BYTES).unwrap());
    }
}
