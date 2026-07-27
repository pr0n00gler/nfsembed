/*
 * Copyright (c) 2015 IETF Trust and the persons identified
 * as authors of the code. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *   disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific contributors, may be used to
 *   endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This code was derived from RFC 7531. */

//! Bounded, whole-record XDR encoding and decoding for NFSv4.0.

use bytes::Bytes;

use super::types::*;
pub use crate::rpc::codec::{DecodeError, EncodeError};
use crate::rpc::codec::{Decoder, Encoder};
use crate::rpc::reply::EncodedReply;

/// Allocation and collection limits for one predecoded COMPOUND record.
///
/// The RPC record layer must independently impose a maximum record size.
/// These limits prevent individual XDR counts from driving disproportionate
/// allocation even when the containing record itself is bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    pub max_operations: usize,
    pub max_tag_bytes: usize,
    pub max_component_bytes: usize,
    pub max_bitmap_words: usize,
    pub max_attribute_bytes: usize,
    pub max_io_bytes: usize,
    pub max_string_bytes: usize,
    pub max_security_infos: usize,
    pub max_directory_entries: usize,
    pub max_ace_who_bytes: usize,
    pub max_oid_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_operations: 128,
            max_tag_bytes: NFS4_OPAQUE_LIMIT,
            max_component_bytes: NFS4_OPAQUE_LIMIT,
            max_bitmap_words: 64,
            max_attribute_bytes: 1024 * 1024,
            max_io_bytes: 16 * 1024 * 1024,
            max_string_bytes: 4096,
            max_security_infos: 64,
            max_directory_entries: 65_536,
            max_ace_who_bytes: NFS4_OPAQUE_LIMIT,
            max_oid_bytes: NFS4_OPAQUE_LIMIT,
        }
    }
}

impl CompoundArgs {
    pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        decode_compound_args(input, limits)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        encode_compound_args(self)
    }
}

impl CompoundRes {
    pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        decode_compound_res(input, limits)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        encode_compound_res(self)
    }
}

impl CallbackCompoundArgs {
    pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        decode_callback_compound_args(input, limits)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        encode_callback_compound_args(self)
    }
}

impl CallbackCompoundRes {
    pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        decode_callback_compound_res(input, limits)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        encode_callback_compound_res(self)
    }
}

/// Result of fully predecoding a server-side COMPOUND request.
///
/// A request whose operation count exceeds the configured execution limit is
/// still decoded through the end of the XDR record. This lets dispatch return
/// `NFS4ERR_RESOURCE` only for an otherwise valid COMPOUND while preserving an
/// RPC XDR error for a truncated or malformed operation beyond the limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PredecodedCompoundArgs {
    Ready(CompoundArgs),
    TooManyOperations {
        tag: Utf8String,
        minor_version: u32,
        actual: usize,
        limit: usize,
    },
}

pub(crate) fn predecode_compound_args(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<PredecodedCompoundArgs, DecodeError> {
    let mut decoder = Decoder::new(input);
    let tag = decoder.read_opaque("NFSv4 COMPOUND tag", limits.max_tag_bytes)?;
    let minor_version = decoder.read_u32()?;
    let operation_count = usize::try_from(decoder.read_u32()?).map_err(|_| DecodeError::Overflow)?;

    if operation_count <= limits.max_operations {
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(operation_count)
            .map_err(|_| DecodeError::LimitExceeded {
                field: "NFSv4 operations",
                actual: operation_count,
                limit: limits.max_operations,
            })?;
        for _ in 0..operation_count {
            operations.push(decode_arg_op(&mut decoder, limits)?);
        }
        decoder.finish()?;
        return Ok(PredecodedCompoundArgs::Ready(CompoundArgs {
            tag,
            minor_version,
            operations,
        }));
    }

    // Every nfs_argop4 has at least a four-byte discriminant. Reject an
    // impossible count immediately instead of looping on an attacker-chosen
    // u32 value when the record is already known to be truncated.
    if operation_count > decoder.remaining() / 4 {
        return Err(DecodeError::Truncated);
    }
    for _ in 0..operation_count {
        // Keep at most one decoded operation live while validating the entire
        // over-limit array. No operation is made available for execution.
        let _ = decode_arg_op(&mut decoder, limits)?;
    }
    decoder.finish()?;
    Ok(PredecodedCompoundArgs::TooManyOperations {
        tag,
        minor_version,
        actual: operation_count,
        limit: limits.max_operations,
    })
}

pub fn decode_compound_args(input: &[u8], limits: DecodeLimits) -> Result<CompoundArgs, DecodeError> {
    let mut decoder = Decoder::new(input);
    let value = CompoundArgs {
        tag: decoder.read_opaque("NFSv4 COMPOUND tag", limits.max_tag_bytes)?,
        minor_version: decoder.read_u32()?,
        operations: decoder
            .read_array("NFSv4 operations", limits.max_operations, |decoder| decode_arg_op(decoder, limits))?,
    };
    decoder.finish()?;
    Ok(value)
}

pub fn encode_compound_args(value: &CompoundArgs) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(&value.tag)?;
    encoder.write_u32(value.minor_version);
    encode_array(&mut encoder, &value.operations, encode_arg_op)?;
    Ok(encoder.into_bytes())
}

pub fn decode_compound_res(input: &[u8], limits: DecodeLimits) -> Result<CompoundRes, DecodeError> {
    let mut decoder = Decoder::new(input);
    let value = CompoundRes {
        status: decode_status(&mut decoder)?,
        tag: decoder.read_opaque("NFSv4 COMPOUND result tag", limits.max_tag_bytes)?,
        operations: decoder
            .read_array("NFSv4 results", limits.max_operations, |decoder| decode_res_op(decoder, limits))?,
    };
    decoder.finish()?;
    Ok(value)
}

pub fn encode_compound_res(value: &CompoundRes) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encode_status(&mut encoder, value.status);
    encoder.write_opaque(&value.tag)?;
    encode_array(&mut encoder, &value.operations, encode_res_op)?;
    Ok(encoder.into_bytes())
}

/// Returns the exact XDR size of a COMPOUND result without allocating.
///
/// The outer status does not affect the encoded size, so callers building a
/// result incrementally only need the echoed tag and the completed operation
/// prefix. The returned length includes the outer status, tag, result-array
/// count, every operation discriminant, and all XDR padding.
pub(crate) fn encoded_compound_res_len(tag: &[u8], operations: &[ResOp]) -> Result<usize, EncodeError> {
    let operations_len = encoded_res_ops_len(operations)?;
    checked_encoded_sum(&[4, encoded_opaque_len(tag.len())?, 4, operations_len])
}

/// Consumes a COMPOUND result and builds a bounded scatter/gather RPC reply.
///
/// `rpc_prefix` is the complete accepted-RPC-reply header through
/// `accept_stat`. Every successful READ payload is retained as its own
/// immutable segment. Other XDR fields and the exact zero padding around READ
/// payloads are encoded into bounded control segments.
pub(crate) fn encode_compound_res_segmented(
    value: CompoundRes,
    rpc_prefix: Bytes,
    limits: DecodeLimits,
    max_rpc_record_size: usize,
) -> Result<EncodedReply, EncodeError> {
    let CompoundRes {
        status,
        tag,
        operations,
    } = value;
    if tag.len() > limits.max_tag_bytes || operations.len() > limits.max_operations {
        return Err(EncodeError::TooLarge(tag.len().max(operations.len())));
    }

    let body_len = encoded_compound_res_len(&tag, &operations)?;
    let reply_len = rpc_prefix
        .len()
        .checked_add(body_len)
        .ok_or(EncodeError::TooLarge(usize::MAX))?;
    if reply_len > max_rpc_record_size {
        return Err(EncodeError::TooLarge(reply_len));
    }

    let max_segments = limits
        .max_operations
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or(EncodeError::TooLarge(limits.max_operations))?;
    let mut builder = CompoundReplySegments::new(rpc_prefix, max_rpc_record_size, max_segments)?;
    let mut header = Encoder::with_capacity(
        8usize
            .checked_add(encoded_opaque_len(tag.len())?)
            .ok_or(EncodeError::TooLarge(tag.len()))?,
    );
    encode_status(&mut header, status);
    header.write_opaque(&tag)?;
    header.write_u32(u32::try_from(operations.len()).map_err(|_| EncodeError::TooLarge(operations.len()))?);
    builder.append_control(header.into_bytes())?;

    for operation in operations {
        match operation {
            ResOp::Read(NfsResult::Ok(ReadOk { eof, data })) => {
                let mut read_header = Encoder::with_capacity(16);
                read_header.write_u32(OpNum::Read as u32);
                encode_status(&mut read_header, NfsStatus::Ok);
                read_header.write_bool(eof);
                read_header.write_u32(u32::try_from(data.len()).map_err(|_| EncodeError::TooLarge(data.len()))?);
                builder.append_control(read_header.into_bytes())?;
                builder.push_read_payload(Bytes::from(data))?;
            },
            operation => {
                let operation_len = encoded_res_op_len(&operation)?;
                let mut encoded = Encoder::with_capacity(operation_len);
                encode_res_op(&mut encoded, &operation)?;
                debug_assert_eq!(encoded.len(), operation_len);
                builder.append_control(encoded.into_bytes())?;
            },
        }
    }

    let reply = builder.finish()?;
    debug_assert_eq!(reply.len(), reply_len);
    Ok(reply)
}

fn encoded_res_ops_len(operations: &[ResOp]) -> Result<usize, EncodeError> {
    u32::try_from(operations.len()).map_err(|_| EncodeError::TooLarge(operations.len()))?;
    operations
        .iter()
        .try_fold(0usize, |length, operation| checked_encoded_sum(&[length, encoded_res_op_len(operation)?]))
}

pub(crate) fn encoded_res_op_len(operation: &ResOp) -> Result<usize, EncodeError> {
    let body_len = match operation {
        ResOp::Access(result) => encoded_nfs_result_len(result, |_| Ok(8))?,
        ResOp::Close(result) => encoded_nfs_result_len(result, |_| Ok(16))?,
        ResOp::Commit(result) => encoded_nfs_result_len(result, |_| Ok(NFS4_VERIFIER_SIZE))?,
        ResOp::Create(result) => encoded_nfs_result_len(result, |value| {
            checked_encoded_sum(&[20, encoded_bitmap_len(&value.attributes_set)?])
        })?,
        ResOp::DelegPurge(_) | ResOp::DelegReturn(_) => 4,
        ResOp::GetAttr(result) => encoded_nfs_result_len(result, encoded_file_attributes_len)?,
        ResOp::GetFh(result) => encoded_nfs_result_len(result, |file_handle| {
            if file_handle.as_bytes().len() > NFS4_FHSIZE {
                return Err(EncodeError::TooLarge(file_handle.as_bytes().len()));
            }
            encoded_opaque_len(file_handle.as_bytes().len())
        })?,
        ResOp::Link(result) => encoded_nfs_result_len(result, |_| Ok(20))?,
        ResOp::Lock(result) => match result {
            LockResult::Ok(_) => 4 + 16,
            LockResult::Denied(denied) => checked_encoded_sum(&[4, encoded_lock_denied_len(denied)?])?,
            LockResult::Err(_) => 4,
        },
        ResOp::LockTest(result) => match result {
            LockTestResult::Ok => 4,
            LockTestResult::Denied(denied) => checked_encoded_sum(&[4, encoded_lock_denied_len(denied)?])?,
            LockTestResult::Err(_) => 4,
        },
        ResOp::LockUnlock(result) => encoded_nfs_result_len(result, |_| Ok(16))?,
        ResOp::Lookup(_)
        | ResOp::LookupParent(_)
        | ResOp::NotVerify(_)
        | ResOp::OpenAttr(_)
        | ResOp::PutFh(_)
        | ResOp::PutPublicFh(_)
        | ResOp::PutRootFh(_)
        | ResOp::Renew(_)
        | ResOp::RestoreFh(_)
        | ResOp::SaveFh(_)
        | ResOp::SetClientIdConfirm(_)
        | ResOp::Verify(_)
        | ResOp::ReleaseLockOwner(_)
        | ResOp::Illegal(_) => 4,
        ResOp::Open(result) => encoded_nfs_result_len(result, encoded_open_ok_len)?,
        ResOp::OpenConfirm(result) | ResOp::OpenDowngrade(result) => encoded_nfs_result_len(result, |_| Ok(16))?,
        ResOp::Read(result) => {
            encoded_nfs_result_len(result, |value| checked_encoded_sum(&[4, encoded_opaque_len(value.data.len())?]))?
        },
        ResOp::ReadDir(result) => encoded_nfs_result_len(result, encoded_directory_list_len)?,
        ResOp::ReadLink(result) => encoded_nfs_result_len(result, |value| encoded_opaque_len(value.link.len()))?,
        ResOp::Remove(result) => encoded_nfs_result_len(result, |_| Ok(20))?,
        ResOp::Rename(result) => encoded_nfs_result_len(result, |_| Ok(40))?,
        ResOp::SecInfo(result) => encoded_nfs_result_len(result, |values| {
            u32::try_from(values.len()).map_err(|_| EncodeError::TooLarge(values.len()))?;
            values
                .iter()
                .try_fold(4usize, |length, value| checked_encoded_sum(&[length, encoded_security_info_len(value)?]))
        })?,
        ResOp::SetAttr(result) => checked_encoded_sum(&[4, encoded_bitmap_len(&result.attributes_set)?])?,
        ResOp::SetClientId(result) => match result {
            SetClientIdResult::Ok(_) => 4 + 8 + NFS4_VERIFIER_SIZE,
            SetClientIdResult::ClientIdInUse(address) => checked_encoded_sum(&[
                4,
                encoded_opaque_len(address.netid.len())?,
                encoded_opaque_len(address.address.len())?,
            ])?,
            SetClientIdResult::Err(_) => 4,
        },
        ResOp::Write(result) => encoded_nfs_result_len(result, |_| Ok(4 + 4 + NFS4_VERIFIER_SIZE))?,
    };
    checked_encoded_sum(&[4, body_len])
}

fn encoded_nfs_result_len<T>(
    result: &NfsResult<T>,
    ok_len: impl FnOnce(&T) -> Result<usize, EncodeError>,
) -> Result<usize, EncodeError> {
    match result {
        NfsResult::Ok(value) => checked_encoded_sum(&[4, ok_len(value)?]),
        NfsResult::Err(_) => Ok(4),
    }
}

fn encoded_bitmap_len(bitmap: &[u32]) -> Result<usize, EncodeError> {
    u32::try_from(bitmap.len()).map_err(|_| EncodeError::TooLarge(bitmap.len()))?;
    let words = bitmap.len().checked_mul(4).ok_or(EncodeError::TooLarge(bitmap.len()))?;
    checked_encoded_sum(&[4, words])
}

fn encoded_file_attributes_len(attributes: &FileAttributes) -> Result<usize, EncodeError> {
    checked_encoded_sum(&[
        encoded_bitmap_len(&attributes.mask)?,
        encoded_opaque_len(attributes.values.len())?,
    ])
}

fn encoded_lock_denied_len(denied: &LockDenied) -> Result<usize, EncodeError> {
    if denied.owner.owner.len() > NFS4_OPAQUE_LIMIT {
        return Err(EncodeError::TooLarge(denied.owner.owner.len()));
    }
    checked_encoded_sum(&[28, encoded_opaque_len(denied.owner.owner.len())?])
}

fn encoded_nfs_ace_len(ace: &NfsAce) -> Result<usize, EncodeError> {
    checked_encoded_sum(&[12, encoded_opaque_len(ace.who.len())?])
}

fn encoded_open_delegation_len(delegation: &OpenDelegation) -> Result<usize, EncodeError> {
    match delegation {
        OpenDelegation::None => Ok(4),
        OpenDelegation::Read(read) => checked_encoded_sum(&[4, 16, 4, encoded_nfs_ace_len(&read.permissions)?]),
        OpenDelegation::Write(write) => checked_encoded_sum(&[4, 16, 4, 12, encoded_nfs_ace_len(&write.permissions)?]),
    }
}

fn encoded_open_ok_len(value: &OpenOk) -> Result<usize, EncodeError> {
    checked_encoded_sum(&[
        16,
        20,
        4,
        encoded_bitmap_len(&value.attributes_set)?,
        encoded_open_delegation_len(&value.delegation)?,
    ])
}

fn encoded_directory_list_len(value: &ReadDirOk) -> Result<usize, EncodeError> {
    value.entries.iter().try_fold(NFS4_VERIFIER_SIZE + 4 + 4, |length, entry| {
        checked_encoded_sum(&[
            length,
            4,
            8,
            encoded_opaque_len(entry.name.len())?,
            encoded_file_attributes_len(&entry.attributes)?,
        ])
    })
}

fn encoded_security_info_len(info: &SecurityInfo) -> Result<usize, EncodeError> {
    match info {
        SecurityInfo::RpcSecGss(gss) => checked_encoded_sum(&[4, encoded_opaque_len(gss.oid.len())?, 4, 4]),
        SecurityInfo::Other(_) => Ok(4),
    }
}

fn encoded_opaque_len(length: usize) -> Result<usize, EncodeError> {
    u32::try_from(length).map_err(|_| EncodeError::TooLarge(length))?;
    let padding = (4usize.wrapping_sub(length & 3)) & 3;
    checked_encoded_sum(&[4, length, padding])
}

fn checked_encoded_sum(lengths: &[usize]) -> Result<usize, EncodeError> {
    lengths
        .iter()
        .try_fold(0usize, |total, length| total.checked_add(*length).ok_or(EncodeError::TooLarge(usize::MAX)))
}

struct CompoundReplySegments {
    segments: Vec<Bytes>,
    pending_control: Vec<u8>,
    encoded_len: usize,
    max_record_size: usize,
    max_segments: usize,
}

impl CompoundReplySegments {
    fn new(prefix: Bytes, max_record_size: usize, max_segments: usize) -> Result<Self, EncodeError> {
        if prefix.len() > max_record_size || max_segments == 0 {
            return Err(EncodeError::TooLarge(prefix.len()));
        }
        let encoded_len = prefix.len();
        Ok(Self {
            segments: vec![prefix],
            pending_control: Vec::new(),
            encoded_len,
            max_record_size,
            max_segments,
        })
    }

    fn append_control(&mut self, encoded: Vec<u8>) -> Result<(), EncodeError> {
        self.ensure_pending_add(encoded.len())?;
        self.pending_control.extend_from_slice(&encoded);
        Ok(())
    }

    fn push_read_payload(&mut self, data: Bytes) -> Result<(), EncodeError> {
        let padding = (4usize.wrapping_sub(data.len() & 3)) & 3;
        self.ensure_pending_add(data.len().checked_add(padding).ok_or(EncodeError::TooLarge(data.len()))?)?;
        self.ensure_segment_slots(2)?;
        self.flush_control()?;
        self.encoded_len = self
            .encoded_len
            .checked_add(data.len())
            .ok_or(EncodeError::TooLarge(data.len()))?;
        self.segments.push(data);
        self.pending_control.resize(padding, 0);
        Ok(())
    }

    fn finish(mut self) -> Result<EncodedReply, EncodeError> {
        self.flush_control()?;
        EncodedReply::try_from_segments(self.segments).map_err(|_| EncodeError::TooLarge(usize::MAX))
    }

    fn ensure_pending_add(&self, additional: usize) -> Result<(), EncodeError> {
        let total = self
            .encoded_len
            .checked_add(self.pending_control.len())
            .and_then(|length| length.checked_add(additional))
            .ok_or(EncodeError::TooLarge(additional))?;
        if total > self.max_record_size {
            return Err(EncodeError::TooLarge(total));
        }
        Ok(())
    }

    fn ensure_segment_slots(&self, additional: usize) -> Result<(), EncodeError> {
        let count = self
            .segments
            .len()
            .checked_add(additional)
            .ok_or(EncodeError::TooLarge(usize::MAX))?;
        if count > self.max_segments {
            return Err(EncodeError::TooLarge(count));
        }
        Ok(())
    }

    fn flush_control(&mut self) -> Result<(), EncodeError> {
        if self.pending_control.is_empty() {
            return Ok(());
        }
        self.ensure_segment_slots(1)?;
        let control = std::mem::take(&mut self.pending_control);
        self.encoded_len = self
            .encoded_len
            .checked_add(control.len())
            .ok_or(EncodeError::TooLarge(control.len()))?;
        self.segments.push(Bytes::from(control));
        Ok(())
    }
}

pub fn decode_callback_compound_args(input: &[u8], limits: DecodeLimits) -> Result<CallbackCompoundArgs, DecodeError> {
    let mut decoder = Decoder::new(input);
    let value = CallbackCompoundArgs {
        tag: decoder.read_opaque("NFSv4 callback tag", limits.max_tag_bytes)?,
        minor_version: decoder.read_u32()?,
        callback_identifier: decoder.read_u32()?,
        operations: decoder.read_array("NFSv4 callback operations", limits.max_operations, |decoder| {
            decode_callback_arg_op(decoder, limits)
        })?,
    };
    decoder.finish()?;
    Ok(value)
}

pub fn encode_callback_compound_args(value: &CallbackCompoundArgs) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(&value.tag)?;
    encoder.write_u32(value.minor_version);
    encoder.write_u32(value.callback_identifier);
    encode_array(&mut encoder, &value.operations, encode_callback_arg_op)?;
    Ok(encoder.into_bytes())
}

pub fn decode_callback_compound_res(input: &[u8], limits: DecodeLimits) -> Result<CallbackCompoundRes, DecodeError> {
    let mut decoder = Decoder::new(input);
    let value = CallbackCompoundRes {
        status: decode_status(&mut decoder)?,
        tag: decoder.read_opaque("NFSv4 callback result tag", limits.max_tag_bytes)?,
        operations: decoder.read_array("NFSv4 callback results", limits.max_operations, |decoder| {
            decode_callback_res_op(decoder, limits)
        })?,
    };
    decoder.finish()?;
    Ok(value)
}

pub fn encode_callback_compound_res(value: &CallbackCompoundRes) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encode_status(&mut encoder, value.status);
    encoder.write_opaque(&value.tag)?;
    encode_array(&mut encoder, &value.operations, encode_callback_res_op)?;
    Ok(encoder.into_bytes())
}

fn encode_array<T>(
    encoder: &mut Encoder,
    values: &[T],
    mut encode: impl FnMut(&mut Encoder, &T) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    encoder.write_u32(u32::try_from(values.len()).map_err(|_| EncodeError::TooLarge(values.len()))?);
    for value in values {
        encode(encoder, value)?;
    }
    Ok(())
}

fn decode_status(decoder: &mut Decoder<'_>) -> Result<NfsStatus, DecodeError> {
    decoder.read_enum("nfsstat4", NfsStatus::from_code)
}

fn encode_status(encoder: &mut Encoder, status: NfsStatus) {
    encoder.write_u32(status as u32);
}

fn decode_state_id(decoder: &mut Decoder<'_>) -> Result<StateId, DecodeError> {
    Ok(StateId {
        sequence_id: decoder.read_u32()?,
        other: decoder.read_fixed()?,
    })
}

fn encode_state_id(encoder: &mut Encoder, state_id: &StateId) {
    encoder.write_u32(state_id.sequence_id);
    encoder.write_fixed(&state_id.other);
}

fn decode_bitmap(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<Bitmap, DecodeError> {
    decoder.read_array("NFSv4 bitmap words", limits.max_bitmap_words, Decoder::read_u32)
}

fn encode_bitmap(encoder: &mut Encoder, bitmap: &Bitmap) -> Result<(), EncodeError> {
    encode_array(encoder, bitmap, |encoder, word| {
        encoder.write_u32(*word);
        Ok(())
    })
}

fn decode_file_attributes(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<FileAttributes, DecodeError> {
    Ok(FileAttributes {
        mask: decode_bitmap(decoder, limits)?,
        values: decoder.read_opaque("NFSv4 attribute values", limits.max_attribute_bytes)?,
    })
}

fn encode_file_attributes(encoder: &mut Encoder, attributes: &FileAttributes) -> Result<(), EncodeError> {
    encode_bitmap(encoder, &attributes.mask)?;
    encoder.write_opaque(&attributes.values)
}

fn decode_file_handle(decoder: &mut Decoder<'_>) -> Result<NfsFileHandle, DecodeError> {
    Ok(NfsFileHandle(decoder.read_opaque("NFSv4 file handle", NFS4_FHSIZE)?))
}

fn encode_file_handle(encoder: &mut Encoder, file_handle: &NfsFileHandle) -> Result<(), EncodeError> {
    encode_bounded_opaque(encoder, file_handle.as_bytes(), NFS4_FHSIZE)
}

fn decode_component(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<Component, DecodeError> {
    decoder.read_opaque("NFSv4 component", limits.max_component_bytes)
}

fn decode_change_info(decoder: &mut Decoder<'_>) -> Result<ChangeInfo, DecodeError> {
    Ok(ChangeInfo {
        atomic: decoder.read_bool()?,
        before: decoder.read_u64()?,
        after: decoder.read_u64()?,
    })
}

fn encode_change_info(encoder: &mut Encoder, change: &ChangeInfo) {
    encoder.write_bool(change.atomic);
    encoder.write_u64(change.before);
    encoder.write_u64(change.after);
}

fn decode_client_address(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<ClientAddress, DecodeError> {
    Ok(ClientAddress {
        netid: decoder.read_opaque("NFSv4 network id", limits.max_string_bytes)?,
        address: decoder.read_opaque("NFSv4 universal address", limits.max_string_bytes)?,
    })
}

fn encode_client_address(encoder: &mut Encoder, address: &ClientAddress) -> Result<(), EncodeError> {
    encoder.write_opaque(&address.netid)?;
    encoder.write_opaque(&address.address)
}

fn decode_lock_type(decoder: &mut Decoder<'_>) -> Result<LockType, DecodeError> {
    decoder.read_enum("nfs_lock_type4", LockType::from_code)
}

fn decode_lock_owner(decoder: &mut Decoder<'_>) -> Result<LockOwner, DecodeError> {
    Ok(LockOwner {
        client_id: decoder.read_u64()?,
        owner: decoder.read_opaque("NFSv4 lock owner", NFS4_OPAQUE_LIMIT)?,
    })
}

fn encode_lock_owner(encoder: &mut Encoder, owner: &LockOwner) -> Result<(), EncodeError> {
    encoder.write_u64(owner.client_id);
    encode_bounded_opaque(encoder, &owner.owner, NFS4_OPAQUE_LIMIT)
}

fn decode_lock_denied(decoder: &mut Decoder<'_>) -> Result<LockDenied, DecodeError> {
    Ok(LockDenied {
        offset: decoder.read_u64()?,
        length: decoder.read_u64()?,
        lock_type: decode_lock_type(decoder)?,
        owner: decode_lock_owner(decoder)?,
    })
}

fn encode_lock_denied(encoder: &mut Encoder, denied: &LockDenied) -> Result<(), EncodeError> {
    encoder.write_u64(denied.offset);
    encoder.write_u64(denied.length);
    encoder.write_u32(denied.lock_type as u32);
    encode_lock_owner(encoder, &denied.owner)
}

fn decode_nfs_ace(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<NfsAce, DecodeError> {
    Ok(NfsAce {
        ace_type: decoder.read_u32()?,
        flags: decoder.read_u32()?,
        access_mask: decoder.read_u32()?,
        who: decoder.read_opaque("NFSv4 ACE who", limits.max_ace_who_bytes)?,
    })
}

fn encode_nfs_ace(encoder: &mut Encoder, ace: &NfsAce) -> Result<(), EncodeError> {
    encoder.write_u32(ace.ace_type);
    encoder.write_u32(ace.flags);
    encoder.write_u32(ace.access_mask);
    encoder.write_opaque(&ace.who)
}

fn decode_status_result<T>(
    decoder: &mut Decoder<'_>,
    decode_ok: impl FnOnce(&mut Decoder<'_>) -> Result<T, DecodeError>,
) -> Result<NfsResult<T>, DecodeError> {
    let status = decode_status(decoder)?;
    if status == NfsStatus::Ok {
        Ok(NfsResult::Ok(decode_ok(decoder)?))
    } else {
        Ok(NfsResult::Err(status))
    }
}

fn encode_status_result<T>(
    encoder: &mut Encoder,
    result: &NfsResult<T>,
    encode_ok: impl FnOnce(&mut Encoder, &T) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    match result {
        NfsResult::Ok(value) => {
            encode_status(encoder, NfsStatus::Ok);
            encode_ok(encoder, value)
        },
        NfsResult::Err(status) => {
            encode_status(encoder, *status);
            Ok(())
        },
    }
}

fn encode_bounded_opaque(encoder: &mut Encoder, value: &[u8], limit: usize) -> Result<(), EncodeError> {
    if value.len() > limit {
        return Err(EncodeError::TooLarge(value.len()));
    }
    encoder.write_opaque(value)
}

fn decode_create_type(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<CreateType, DecodeError> {
    let file_type = decoder.read_enum("nfs_ftype4", NfsFileType::from_code)?;
    Ok(match file_type {
        NfsFileType::Symlink => CreateType::Symlink(decoder.read_opaque("NFSv4 symbolic link", limits.max_io_bytes)?),
        NfsFileType::Block => CreateType::Block(SpecData {
            major: decoder.read_u32()?,
            minor: decoder.read_u32()?,
        }),
        NfsFileType::Character => CreateType::Character(SpecData {
            major: decoder.read_u32()?,
            minor: decoder.read_u32()?,
        }),
        NfsFileType::Socket => CreateType::Socket,
        NfsFileType::Fifo => CreateType::Fifo,
        NfsFileType::Directory => CreateType::Directory,
        other => CreateType::Other(other),
    })
}

fn encode_create_type(encoder: &mut Encoder, create_type: &CreateType) -> Result<(), EncodeError> {
    encoder.write_u32(create_type.file_type() as u32);
    match create_type {
        CreateType::Symlink(link) => encoder.write_opaque(link),
        CreateType::Block(device) | CreateType::Character(device) => {
            encoder.write_u32(device.major);
            encoder.write_u32(device.minor);
            Ok(())
        },
        CreateType::Socket | CreateType::Fifo | CreateType::Directory | CreateType::Other(_) => Ok(()),
    }
}

fn decode_open_how(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<OpenHow, DecodeError> {
    match decoder.read_u32()? {
        0 => Ok(OpenHow::NoCreate),
        1 => {
            let mode = decoder.read_enum("createmode4", CreateMode::from_code)?;
            Ok(OpenHow::Create(match mode {
                CreateMode::Unchecked => CreateHow::Unchecked(decode_file_attributes(decoder, limits)?),
                CreateMode::Guarded => CreateHow::Guarded(decode_file_attributes(decoder, limits)?),
                CreateMode::Exclusive => CreateHow::Exclusive(decoder.read_fixed()?),
            }))
        },
        value => Err(DecodeError::InvalidDiscriminant {
            kind: "opentype4",
            value,
        }),
    }
}

fn encode_open_how(encoder: &mut Encoder, how: &OpenHow) -> Result<(), EncodeError> {
    match how {
        OpenHow::NoCreate => {
            encoder.write_u32(0);
            Ok(())
        },
        OpenHow::Create(create_how) => {
            encoder.write_u32(1);
            encoder.write_u32(create_how.mode() as u32);
            match create_how {
                CreateHow::Unchecked(attributes) | CreateHow::Guarded(attributes) => {
                    encode_file_attributes(encoder, attributes)
                },
                CreateHow::Exclusive(verifier) => {
                    encoder.write_fixed(verifier);
                    Ok(())
                },
            }
        },
    }
}

fn decode_open_claim(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<OpenClaim, DecodeError> {
    match decoder.read_u32()? {
        0 => Ok(OpenClaim::Null(decode_component(decoder, limits)?)),
        1 => Ok(OpenClaim::Previous(decoder.read_enum("open_delegation_type4", OpenDelegationType::from_code)?)),
        2 => Ok(OpenClaim::DelegateCurrent {
            delegate_state_id: decode_state_id(decoder)?,
            file: decode_component(decoder, limits)?,
        }),
        3 => Ok(OpenClaim::DelegatePrevious(decode_component(decoder, limits)?)),
        value => Err(DecodeError::InvalidDiscriminant {
            kind: "open_claim_type4",
            value,
        }),
    }
}

fn encode_open_claim(encoder: &mut Encoder, claim: &OpenClaim) -> Result<(), EncodeError> {
    match claim {
        OpenClaim::Null(file) => {
            encoder.write_u32(0);
            encoder.write_opaque(file)
        },
        OpenClaim::Previous(delegation_type) => {
            encoder.write_u32(1);
            encoder.write_u32(*delegation_type as u32);
            Ok(())
        },
        OpenClaim::DelegateCurrent {
            delegate_state_id,
            file,
        } => {
            encoder.write_u32(2);
            encode_state_id(encoder, delegate_state_id);
            encoder.write_opaque(file)
        },
        OpenClaim::DelegatePrevious(file) => {
            encoder.write_u32(3);
            encoder.write_opaque(file)
        },
    }
}

fn decode_space_limit(decoder: &mut Decoder<'_>) -> Result<SpaceLimit, DecodeError> {
    match decoder.read_u32()? {
        1 => Ok(SpaceLimit::Size(decoder.read_u64()?)),
        2 => Ok(SpaceLimit::Blocks {
            block_count: decoder.read_u32()?,
            bytes_per_block: decoder.read_u32()?,
        }),
        value => Err(DecodeError::InvalidDiscriminant {
            kind: "limit_by4",
            value,
        }),
    }
}

fn encode_space_limit(encoder: &mut Encoder, limit: &SpaceLimit) {
    match limit {
        SpaceLimit::Size(size) => {
            encoder.write_u32(1);
            encoder.write_u64(*size);
        },
        SpaceLimit::Blocks {
            block_count,
            bytes_per_block,
        } => {
            encoder.write_u32(2);
            encoder.write_u32(*block_count);
            encoder.write_u32(*bytes_per_block);
        },
    }
}

fn decode_open_delegation(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<OpenDelegation, DecodeError> {
    let delegation_type = decoder.read_enum("open_delegation_type4", OpenDelegationType::from_code)?;
    Ok(match delegation_type {
        OpenDelegationType::None => OpenDelegation::None,
        OpenDelegationType::Read => OpenDelegation::Read(OpenReadDelegation {
            state_id: decode_state_id(decoder)?,
            recall: decoder.read_bool()?,
            permissions: decode_nfs_ace(decoder, limits)?,
        }),
        OpenDelegationType::Write => OpenDelegation::Write(OpenWriteDelegation {
            state_id: decode_state_id(decoder)?,
            recall: decoder.read_bool()?,
            space_limit: decode_space_limit(decoder)?,
            permissions: decode_nfs_ace(decoder, limits)?,
        }),
    })
}

fn encode_open_delegation(encoder: &mut Encoder, delegation: &OpenDelegation) -> Result<(), EncodeError> {
    match delegation {
        OpenDelegation::None => {
            encoder.write_u32(OpenDelegationType::None as u32);
            Ok(())
        },
        OpenDelegation::Read(read) => {
            encoder.write_u32(OpenDelegationType::Read as u32);
            encode_state_id(encoder, &read.state_id);
            encoder.write_bool(read.recall);
            encode_nfs_ace(encoder, &read.permissions)
        },
        OpenDelegation::Write(write) => {
            encoder.write_u32(OpenDelegationType::Write as u32);
            encode_state_id(encoder, &write.state_id);
            encoder.write_bool(write.recall);
            encode_space_limit(encoder, &write.space_limit);
            encode_nfs_ace(encoder, &write.permissions)
        },
    }
}

fn decode_security_info(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<SecurityInfo, DecodeError> {
    let flavor = decoder.read_u32()?;
    if flavor == RPCSEC_GSS {
        Ok(SecurityInfo::RpcSecGss(RpcSecGssInfo {
            oid: decoder.read_opaque("NFSv4 security OID", limits.max_oid_bytes)?,
            qop: decoder.read_u32()?,
            service: decoder.read_enum("rpc_gss_svc_t", RpcGssService::from_code)?,
        }))
    } else {
        Ok(SecurityInfo::Other(flavor))
    }
}

fn encode_security_info(encoder: &mut Encoder, info: &SecurityInfo) -> Result<(), EncodeError> {
    match info {
        SecurityInfo::RpcSecGss(gss) => {
            encoder.write_u32(RPCSEC_GSS);
            encoder.write_opaque(&gss.oid)?;
            encoder.write_u32(gss.qop);
            encoder.write_u32(gss.service as u32);
        },
        SecurityInfo::Other(flavor) => encoder.write_u32(*flavor),
    }
    Ok(())
}

fn decode_arg_op(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<ArgOp, DecodeError> {
    let requested_opcode = decoder.read_u32()?;
    let Some(opnum) = OpNum::from_code(requested_opcode) else {
        return Ok(ArgOp::Illegal { requested_opcode });
    };

    Ok(match opnum {
        OpNum::Access => ArgOp::Access(AccessArgs {
            access: decoder.read_u32()?,
        }),
        OpNum::Close => ArgOp::Close(CloseArgs {
            sequence_id: decoder.read_u32()?,
            open_state_id: decode_state_id(decoder)?,
        }),
        OpNum::Commit => ArgOp::Commit(CommitArgs {
            offset: decoder.read_u64()?,
            count: decoder.read_u32()?,
        }),
        OpNum::Create => ArgOp::Create(CreateArgs {
            object_type: decode_create_type(decoder, limits)?,
            name: decode_component(decoder, limits)?,
            attributes: decode_file_attributes(decoder, limits)?,
        }),
        OpNum::DelegPurge => ArgOp::DelegPurge(DelegPurgeArgs {
            client_id: decoder.read_u64()?,
        }),
        OpNum::DelegReturn => ArgOp::DelegReturn(DelegReturnArgs {
            delegation_state_id: decode_state_id(decoder)?,
        }),
        OpNum::GetAttr => ArgOp::GetAttr(GetAttrArgs {
            requested_attributes: decode_bitmap(decoder, limits)?,
        }),
        OpNum::GetFh => ArgOp::GetFh,
        OpNum::Link => ArgOp::Link(LinkArgs {
            new_name: decode_component(decoder, limits)?,
        }),
        OpNum::Lock => ArgOp::Lock(LockArgs {
            lock_type: decode_lock_type(decoder)?,
            reclaim: decoder.read_bool()?,
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
            locker: if decoder.read_bool()? {
                Locker::New(OpenToLockOwner {
                    open_sequence_id: decoder.read_u32()?,
                    open_state_id: decode_state_id(decoder)?,
                    lock_sequence_id: decoder.read_u32()?,
                    lock_owner: decode_lock_owner(decoder)?,
                })
            } else {
                Locker::Existing(ExistingLockOwner {
                    lock_state_id: decode_state_id(decoder)?,
                    lock_sequence_id: decoder.read_u32()?,
                })
            },
        }),
        OpNum::LockTest => ArgOp::LockTest(LockTestArgs {
            lock_type: decode_lock_type(decoder)?,
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
            owner: decode_lock_owner(decoder)?,
        }),
        OpNum::LockUnlock => ArgOp::LockUnlock(LockUnlockArgs {
            lock_type: decode_lock_type(decoder)?,
            sequence_id: decoder.read_u32()?,
            lock_state_id: decode_state_id(decoder)?,
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
        }),
        OpNum::Lookup => ArgOp::Lookup(LookupArgs {
            name: decode_component(decoder, limits)?,
        }),
        OpNum::LookupParent => ArgOp::LookupParent,
        OpNum::NotVerify => ArgOp::NotVerify(NotVerifyArgs {
            attributes: decode_file_attributes(decoder, limits)?,
        }),
        OpNum::Open => ArgOp::Open(OpenArgs {
            sequence_id: decoder.read_u32()?,
            share_access: decoder.read_u32()?,
            share_deny: decoder.read_u32()?,
            owner: OpenOwner {
                client_id: decoder.read_u64()?,
                owner: decoder.read_opaque("NFSv4 open owner", NFS4_OPAQUE_LIMIT)?,
            },
            how: decode_open_how(decoder, limits)?,
            claim: decode_open_claim(decoder, limits)?,
        }),
        OpNum::OpenAttr => ArgOp::OpenAttr(OpenAttrArgs {
            create_directory: decoder.read_bool()?,
        }),
        OpNum::OpenConfirm => ArgOp::OpenConfirm(OpenConfirmArgs {
            open_state_id: decode_state_id(decoder)?,
            sequence_id: decoder.read_u32()?,
        }),
        OpNum::OpenDowngrade => ArgOp::OpenDowngrade(OpenDowngradeArgs {
            open_state_id: decode_state_id(decoder)?,
            sequence_id: decoder.read_u32()?,
            share_access: decoder.read_u32()?,
            share_deny: decoder.read_u32()?,
        }),
        OpNum::PutFh => ArgOp::PutFh(PutFhArgs {
            object: decode_file_handle(decoder)?,
        }),
        OpNum::PutPublicFh => ArgOp::PutPublicFh,
        OpNum::PutRootFh => ArgOp::PutRootFh,
        OpNum::Read => ArgOp::Read(ReadArgs {
            state_id: decode_state_id(decoder)?,
            offset: decoder.read_u64()?,
            count: decoder.read_u32()?,
        }),
        OpNum::ReadDir => ArgOp::ReadDir(ReadDirArgs {
            cookie: decoder.read_u64()?,
            cookie_verifier: decoder.read_fixed()?,
            directory_count: decoder.read_u32()?,
            max_count: decoder.read_u32()?,
            requested_attributes: decode_bitmap(decoder, limits)?,
        }),
        OpNum::ReadLink => ArgOp::ReadLink,
        OpNum::Remove => ArgOp::Remove(RemoveArgs {
            target: decode_component(decoder, limits)?,
        }),
        OpNum::Rename => ArgOp::Rename(RenameArgs {
            old_name: decode_component(decoder, limits)?,
            new_name: decode_component(decoder, limits)?,
        }),
        OpNum::Renew => ArgOp::Renew(RenewArgs {
            client_id: decoder.read_u64()?,
        }),
        OpNum::RestoreFh => ArgOp::RestoreFh,
        OpNum::SaveFh => ArgOp::SaveFh,
        OpNum::SecInfo => ArgOp::SecInfo(SecInfoArgs {
            name: decode_component(decoder, limits)?,
        }),
        OpNum::SetAttr => ArgOp::SetAttr(SetAttrArgs {
            state_id: decode_state_id(decoder)?,
            attributes: decode_file_attributes(decoder, limits)?,
        }),
        OpNum::SetClientId => ArgOp::SetClientId(SetClientIdArgs {
            client: NfsClientId {
                verifier: decoder.read_fixed()?,
                id: decoder.read_opaque("NFSv4 client id", NFS4_OPAQUE_LIMIT)?,
            },
            callback: CallbackClient {
                program: decoder.read_u32()?,
                location: decode_client_address(decoder, limits)?,
            },
            callback_identifier: decoder.read_u32()?,
        }),
        OpNum::SetClientIdConfirm => ArgOp::SetClientIdConfirm(SetClientIdConfirmArgs {
            client_id: decoder.read_u64()?,
            confirmation: decoder.read_fixed()?,
        }),
        OpNum::Verify => ArgOp::Verify(VerifyArgs {
            attributes: decode_file_attributes(decoder, limits)?,
        }),
        OpNum::Write => ArgOp::Write(WriteArgs {
            state_id: decode_state_id(decoder)?,
            offset: decoder.read_u64()?,
            stability: decoder.read_enum("stable_how4", StableHow::from_code)?,
            data: decoder.read_opaque("NFSv4 WRITE data", limits.max_io_bytes)?,
        }),
        OpNum::ReleaseLockOwner => ArgOp::ReleaseLockOwner(ReleaseLockOwnerArgs {
            lock_owner: decode_lock_owner(decoder)?,
        }),
        OpNum::Illegal => ArgOp::Illegal { requested_opcode },
    })
}

fn encode_arg_op(encoder: &mut Encoder, operation: &ArgOp) -> Result<(), EncodeError> {
    encoder.write_u32(operation.opcode());
    match operation {
        ArgOp::Access(args) => encoder.write_u32(args.access),
        ArgOp::Close(args) => {
            encoder.write_u32(args.sequence_id);
            encode_state_id(encoder, &args.open_state_id);
        },
        ArgOp::Commit(args) => {
            encoder.write_u64(args.offset);
            encoder.write_u32(args.count);
        },
        ArgOp::Create(args) => {
            encode_create_type(encoder, &args.object_type)?;
            encoder.write_opaque(&args.name)?;
            encode_file_attributes(encoder, &args.attributes)?;
        },
        ArgOp::DelegPurge(args) => encoder.write_u64(args.client_id),
        ArgOp::DelegReturn(args) => encode_state_id(encoder, &args.delegation_state_id),
        ArgOp::GetAttr(args) => encode_bitmap(encoder, &args.requested_attributes)?,
        ArgOp::GetFh => {},
        ArgOp::Link(args) => encoder.write_opaque(&args.new_name)?,
        ArgOp::Lock(args) => {
            encoder.write_u32(args.lock_type as u32);
            encoder.write_bool(args.reclaim);
            encoder.write_u64(args.offset);
            encoder.write_u64(args.length);
            match &args.locker {
                Locker::New(owner) => {
                    encoder.write_bool(true);
                    encoder.write_u32(owner.open_sequence_id);
                    encode_state_id(encoder, &owner.open_state_id);
                    encoder.write_u32(owner.lock_sequence_id);
                    encode_lock_owner(encoder, &owner.lock_owner)?;
                },
                Locker::Existing(owner) => {
                    encoder.write_bool(false);
                    encode_state_id(encoder, &owner.lock_state_id);
                    encoder.write_u32(owner.lock_sequence_id);
                },
            }
        },
        ArgOp::LockTest(args) => {
            encoder.write_u32(args.lock_type as u32);
            encoder.write_u64(args.offset);
            encoder.write_u64(args.length);
            encode_lock_owner(encoder, &args.owner)?;
        },
        ArgOp::LockUnlock(args) => {
            encoder.write_u32(args.lock_type as u32);
            encoder.write_u32(args.sequence_id);
            encode_state_id(encoder, &args.lock_state_id);
            encoder.write_u64(args.offset);
            encoder.write_u64(args.length);
        },
        ArgOp::Lookup(args) => encoder.write_opaque(&args.name)?,
        ArgOp::LookupParent => {},
        ArgOp::NotVerify(args) => encode_file_attributes(encoder, &args.attributes)?,
        ArgOp::Open(args) => {
            encoder.write_u32(args.sequence_id);
            encoder.write_u32(args.share_access);
            encoder.write_u32(args.share_deny);
            encoder.write_u64(args.owner.client_id);
            encode_bounded_opaque(encoder, &args.owner.owner, NFS4_OPAQUE_LIMIT)?;
            encode_open_how(encoder, &args.how)?;
            encode_open_claim(encoder, &args.claim)?;
        },
        ArgOp::OpenAttr(args) => encoder.write_bool(args.create_directory),
        ArgOp::OpenConfirm(args) => {
            encode_state_id(encoder, &args.open_state_id);
            encoder.write_u32(args.sequence_id);
        },
        ArgOp::OpenDowngrade(args) => {
            encode_state_id(encoder, &args.open_state_id);
            encoder.write_u32(args.sequence_id);
            encoder.write_u32(args.share_access);
            encoder.write_u32(args.share_deny);
        },
        ArgOp::PutFh(args) => encode_file_handle(encoder, &args.object)?,
        ArgOp::PutPublicFh | ArgOp::PutRootFh => {},
        ArgOp::Read(args) => {
            encode_state_id(encoder, &args.state_id);
            encoder.write_u64(args.offset);
            encoder.write_u32(args.count);
        },
        ArgOp::ReadDir(args) => {
            encoder.write_u64(args.cookie);
            encoder.write_fixed(&args.cookie_verifier);
            encoder.write_u32(args.directory_count);
            encoder.write_u32(args.max_count);
            encode_bitmap(encoder, &args.requested_attributes)?;
        },
        ArgOp::ReadLink => {},
        ArgOp::Remove(args) => encoder.write_opaque(&args.target)?,
        ArgOp::Rename(args) => {
            encoder.write_opaque(&args.old_name)?;
            encoder.write_opaque(&args.new_name)?;
        },
        ArgOp::Renew(args) => encoder.write_u64(args.client_id),
        ArgOp::RestoreFh | ArgOp::SaveFh => {},
        ArgOp::SecInfo(args) => encoder.write_opaque(&args.name)?,
        ArgOp::SetAttr(args) => {
            encode_state_id(encoder, &args.state_id);
            encode_file_attributes(encoder, &args.attributes)?;
        },
        ArgOp::SetClientId(args) => {
            encoder.write_fixed(&args.client.verifier);
            encode_bounded_opaque(encoder, &args.client.id, NFS4_OPAQUE_LIMIT)?;
            encoder.write_u32(args.callback.program);
            encode_client_address(encoder, &args.callback.location)?;
            encoder.write_u32(args.callback_identifier);
        },
        ArgOp::SetClientIdConfirm(args) => {
            encoder.write_u64(args.client_id);
            encoder.write_fixed(&args.confirmation);
        },
        ArgOp::Verify(args) => encode_file_attributes(encoder, &args.attributes)?,
        ArgOp::Write(args) => {
            encode_state_id(encoder, &args.state_id);
            encoder.write_u64(args.offset);
            encoder.write_u32(args.stability as u32);
            encoder.write_opaque(&args.data)?;
        },
        ArgOp::ReleaseLockOwner(args) => encode_lock_owner(encoder, &args.lock_owner)?,
        ArgOp::Illegal { .. } => {},
    }
    Ok(())
}

fn decode_open_ok(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<OpenOk, DecodeError> {
    Ok(OpenOk {
        state_id: decode_state_id(decoder)?,
        change_info: decode_change_info(decoder)?,
        result_flags: decoder.read_u32()?,
        attributes_set: decode_bitmap(decoder, limits)?,
        delegation: decode_open_delegation(decoder, limits)?,
    })
}

fn encode_open_ok(encoder: &mut Encoder, value: &OpenOk) -> Result<(), EncodeError> {
    encode_state_id(encoder, &value.state_id);
    encode_change_info(encoder, &value.change_info);
    encoder.write_u32(value.result_flags);
    encode_bitmap(encoder, &value.attributes_set)?;
    encode_open_delegation(encoder, &value.delegation)
}

fn decode_directory_list(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<ReadDirOk, DecodeError> {
    let cookie_verifier = decoder.read_fixed()?;
    let mut entries = Vec::new();
    while decoder.read_bool()? {
        if entries.len() == limits.max_directory_entries {
            return Err(DecodeError::LimitExceeded {
                field: "NFSv4 directory entries",
                actual: entries.len().saturating_add(1),
                limit: limits.max_directory_entries,
            });
        }
        entries.push(DirectoryEntry {
            cookie: decoder.read_u64()?,
            name: decode_component(decoder, limits)?,
            attributes: decode_file_attributes(decoder, limits)?,
        });
    }
    let eof = decoder.read_bool()?;
    Ok(ReadDirOk {
        cookie_verifier,
        entries,
        eof,
    })
}

fn encode_directory_list(encoder: &mut Encoder, value: &ReadDirOk) -> Result<(), EncodeError> {
    encoder.write_fixed(&value.cookie_verifier);
    for entry in &value.entries {
        encoder.write_bool(true);
        encoder.write_u64(entry.cookie);
        encoder.write_opaque(&entry.name)?;
        encode_file_attributes(encoder, &entry.attributes)?;
    }
    encoder.write_bool(false);
    encoder.write_bool(value.eof);
    Ok(())
}

fn decode_res_op(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<ResOp, DecodeError> {
    let opnum = decoder.read_enum("nfs_opnum4", OpNum::from_code)?;
    Ok(match opnum {
        OpNum::Access => ResOp::Access(decode_status_result(decoder, |decoder| {
            Ok(AccessOk {
                supported: decoder.read_u32()?,
                access: decoder.read_u32()?,
            })
        })?),
        OpNum::Close => ResOp::Close(decode_status_result(decoder, decode_state_id)?),
        OpNum::Commit => ResOp::Commit(decode_status_result(decoder, |decoder| {
            Ok(CommitOk {
                write_verifier: decoder.read_fixed()?,
            })
        })?),
        OpNum::Create => ResOp::Create(decode_status_result(decoder, |decoder| {
            Ok(CreateOk {
                change_info: decode_change_info(decoder)?,
                attributes_set: decode_bitmap(decoder, limits)?,
            })
        })?),
        OpNum::DelegPurge => ResOp::DelegPurge(decode_status(decoder)?),
        OpNum::DelegReturn => ResOp::DelegReturn(decode_status(decoder)?),
        OpNum::GetAttr => {
            ResOp::GetAttr(decode_status_result(decoder, |decoder| decode_file_attributes(decoder, limits))?)
        },
        OpNum::GetFh => ResOp::GetFh(decode_status_result(decoder, decode_file_handle)?),
        OpNum::Link => ResOp::Link(decode_status_result(decoder, |decoder| {
            Ok(LinkOk {
                change_info: decode_change_info(decoder)?,
            })
        })?),
        OpNum::Lock => {
            let status = decode_status(decoder)?;
            ResOp::Lock(match status {
                NfsStatus::Ok => LockResult::Ok(decode_state_id(decoder)?),
                NfsStatus::Denied => LockResult::Denied(decode_lock_denied(decoder)?),
                other => LockResult::Err(other),
            })
        },
        OpNum::LockTest => {
            let status = decode_status(decoder)?;
            ResOp::LockTest(match status {
                NfsStatus::Ok => LockTestResult::Ok,
                NfsStatus::Denied => LockTestResult::Denied(decode_lock_denied(decoder)?),
                other => LockTestResult::Err(other),
            })
        },
        OpNum::LockUnlock => ResOp::LockUnlock(decode_status_result(decoder, decode_state_id)?),
        OpNum::Lookup => ResOp::Lookup(decode_status(decoder)?),
        OpNum::LookupParent => ResOp::LookupParent(decode_status(decoder)?),
        OpNum::NotVerify => ResOp::NotVerify(decode_status(decoder)?),
        OpNum::Open => ResOp::Open(decode_status_result(decoder, |decoder| decode_open_ok(decoder, limits))?),
        OpNum::OpenAttr => ResOp::OpenAttr(decode_status(decoder)?),
        OpNum::OpenConfirm => ResOp::OpenConfirm(decode_status_result(decoder, decode_state_id)?),
        OpNum::OpenDowngrade => ResOp::OpenDowngrade(decode_status_result(decoder, decode_state_id)?),
        OpNum::PutFh => ResOp::PutFh(decode_status(decoder)?),
        OpNum::PutPublicFh => ResOp::PutPublicFh(decode_status(decoder)?),
        OpNum::PutRootFh => ResOp::PutRootFh(decode_status(decoder)?),
        OpNum::Read => ResOp::Read(decode_status_result(decoder, |decoder| {
            Ok(ReadOk {
                eof: decoder.read_bool()?,
                data: decoder.read_opaque("NFSv4 READ data", limits.max_io_bytes)?,
            })
        })?),
        OpNum::ReadDir => {
            ResOp::ReadDir(decode_status_result(decoder, |decoder| decode_directory_list(decoder, limits))?)
        },
        OpNum::ReadLink => ResOp::ReadLink(decode_status_result(decoder, |decoder| {
            Ok(ReadLinkOk {
                link: decoder.read_opaque("NFSv4 READLINK data", limits.max_io_bytes)?,
            })
        })?),
        OpNum::Remove => ResOp::Remove(decode_status_result(decoder, |decoder| {
            Ok(RemoveOk {
                change_info: decode_change_info(decoder)?,
            })
        })?),
        OpNum::Rename => ResOp::Rename(decode_status_result(decoder, |decoder| {
            Ok(RenameOk {
                source_change_info: decode_change_info(decoder)?,
                target_change_info: decode_change_info(decoder)?,
            })
        })?),
        OpNum::Renew => ResOp::Renew(decode_status(decoder)?),
        OpNum::RestoreFh => ResOp::RestoreFh(decode_status(decoder)?),
        OpNum::SaveFh => ResOp::SaveFh(decode_status(decoder)?),
        OpNum::SecInfo => ResOp::SecInfo(decode_status_result(decoder, |decoder| {
            decoder.read_array("NFSv4 security flavors", limits.max_security_infos, |decoder| {
                decode_security_info(decoder, limits)
            })
        })?),
        OpNum::SetAttr => ResOp::SetAttr(SetAttrResult {
            status: decode_status(decoder)?,
            attributes_set: decode_bitmap(decoder, limits)?,
        }),
        OpNum::SetClientId => {
            let status = decode_status(decoder)?;
            ResOp::SetClientId(match status {
                NfsStatus::Ok => SetClientIdResult::Ok(SetClientIdOk {
                    client_id: decoder.read_u64()?,
                    confirmation: decoder.read_fixed()?,
                }),
                NfsStatus::ClientIdInUse => SetClientIdResult::ClientIdInUse(decode_client_address(decoder, limits)?),
                other => SetClientIdResult::Err(other),
            })
        },
        OpNum::SetClientIdConfirm => ResOp::SetClientIdConfirm(decode_status(decoder)?),
        OpNum::Verify => ResOp::Verify(decode_status(decoder)?),
        OpNum::Write => ResOp::Write(decode_status_result(decoder, |decoder| {
            Ok(WriteOk {
                count: decoder.read_u32()?,
                committed: decoder.read_enum("stable_how4", StableHow::from_code)?,
                write_verifier: decoder.read_fixed()?,
            })
        })?),
        OpNum::ReleaseLockOwner => ResOp::ReleaseLockOwner(decode_status(decoder)?),
        OpNum::Illegal => ResOp::Illegal(decode_status(decoder)?),
    })
}

fn encode_res_op(encoder: &mut Encoder, operation: &ResOp) -> Result<(), EncodeError> {
    encoder.write_u32(operation.opnum() as u32);
    match operation {
        ResOp::Access(result) => encode_status_result(encoder, result, |encoder, value| {
            encoder.write_u32(value.supported);
            encoder.write_u32(value.access);
            Ok(())
        })?,
        ResOp::Close(result) => encode_status_result(encoder, result, |encoder, state_id| {
            encode_state_id(encoder, state_id);
            Ok(())
        })?,
        ResOp::Commit(result) => encode_status_result(encoder, result, |encoder, value| {
            encoder.write_fixed(&value.write_verifier);
            Ok(())
        })?,
        ResOp::Create(result) => encode_status_result(encoder, result, |encoder, value| {
            encode_change_info(encoder, &value.change_info);
            encode_bitmap(encoder, &value.attributes_set)
        })?,
        ResOp::DelegPurge(status) | ResOp::DelegReturn(status) => encode_status(encoder, *status),
        ResOp::GetAttr(result) => encode_status_result(encoder, result, encode_file_attributes)?,
        ResOp::GetFh(result) => encode_status_result(encoder, result, encode_file_handle)?,
        ResOp::Link(result) => encode_status_result(encoder, result, |encoder, value| {
            encode_change_info(encoder, &value.change_info);
            Ok(())
        })?,
        ResOp::Lock(result) => match result {
            LockResult::Ok(state_id) => {
                encode_status(encoder, NfsStatus::Ok);
                encode_state_id(encoder, state_id);
            },
            LockResult::Denied(denied) => {
                encode_status(encoder, NfsStatus::Denied);
                encode_lock_denied(encoder, denied)?;
            },
            LockResult::Err(status) => encode_status(encoder, *status),
        },
        ResOp::LockTest(result) => match result {
            LockTestResult::Ok => encode_status(encoder, NfsStatus::Ok),
            LockTestResult::Denied(denied) => {
                encode_status(encoder, NfsStatus::Denied);
                encode_lock_denied(encoder, denied)?;
            },
            LockTestResult::Err(status) => encode_status(encoder, *status),
        },
        ResOp::LockUnlock(result) => encode_status_result(encoder, result, |encoder, state_id| {
            encode_state_id(encoder, state_id);
            Ok(())
        })?,
        ResOp::Lookup(status)
        | ResOp::LookupParent(status)
        | ResOp::NotVerify(status)
        | ResOp::OpenAttr(status)
        | ResOp::PutFh(status)
        | ResOp::PutPublicFh(status)
        | ResOp::PutRootFh(status)
        | ResOp::Renew(status)
        | ResOp::RestoreFh(status)
        | ResOp::SaveFh(status)
        | ResOp::SetClientIdConfirm(status)
        | ResOp::Verify(status)
        | ResOp::ReleaseLockOwner(status)
        | ResOp::Illegal(status) => encode_status(encoder, *status),
        ResOp::Open(result) => encode_status_result(encoder, result, encode_open_ok)?,
        ResOp::OpenConfirm(result) | ResOp::OpenDowngrade(result) => {
            encode_status_result(encoder, result, |encoder, state_id| {
                encode_state_id(encoder, state_id);
                Ok(())
            })?
        },
        ResOp::Read(result) => encode_status_result(encoder, result, |encoder, value| {
            encoder.write_bool(value.eof);
            encoder.write_opaque(&value.data)
        })?,
        ResOp::ReadDir(result) => encode_status_result(encoder, result, encode_directory_list)?,
        ResOp::ReadLink(result) => {
            encode_status_result(encoder, result, |encoder, value| encoder.write_opaque(&value.link))?
        },
        ResOp::Remove(result) => encode_status_result(encoder, result, |encoder, value| {
            encode_change_info(encoder, &value.change_info);
            Ok(())
        })?,
        ResOp::Rename(result) => encode_status_result(encoder, result, |encoder, value| {
            encode_change_info(encoder, &value.source_change_info);
            encode_change_info(encoder, &value.target_change_info);
            Ok(())
        })?,
        ResOp::SecInfo(result) => encode_status_result(encoder, result, |encoder, values| {
            encode_array(encoder, values, encode_security_info)
        })?,
        ResOp::SetAttr(result) => {
            encode_status(encoder, result.status);
            encode_bitmap(encoder, &result.attributes_set)?;
        },
        ResOp::SetClientId(result) => match result {
            SetClientIdResult::Ok(value) => {
                encode_status(encoder, NfsStatus::Ok);
                encoder.write_u64(value.client_id);
                encoder.write_fixed(&value.confirmation);
            },
            SetClientIdResult::ClientIdInUse(address) => {
                encode_status(encoder, NfsStatus::ClientIdInUse);
                encode_client_address(encoder, address)?;
            },
            SetClientIdResult::Err(status) => encode_status(encoder, *status),
        },
        ResOp::Write(result) => encode_status_result(encoder, result, |encoder, value| {
            encoder.write_u32(value.count);
            encoder.write_u32(value.committed as u32);
            encoder.write_fixed(&value.write_verifier);
            Ok(())
        })?,
    }
    Ok(())
}

fn decode_callback_arg_op(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<CallbackArgOp, DecodeError> {
    let requested_opcode = decoder.read_u32()?;
    let Some(opnum) = CallbackOpNum::from_code(requested_opcode) else {
        return Ok(CallbackArgOp::Illegal { requested_opcode });
    };
    Ok(match opnum {
        CallbackOpNum::GetAttr => CallbackArgOp::GetAttr(CallbackGetAttrArgs {
            file_handle: decode_file_handle(decoder)?,
            requested_attributes: decode_bitmap(decoder, limits)?,
        }),
        CallbackOpNum::Recall => CallbackArgOp::Recall(CallbackRecallArgs {
            state_id: decode_state_id(decoder)?,
            truncate: decoder.read_bool()?,
            file_handle: decode_file_handle(decoder)?,
        }),
        CallbackOpNum::Illegal => CallbackArgOp::Illegal { requested_opcode },
    })
}

fn encode_callback_arg_op(encoder: &mut Encoder, operation: &CallbackArgOp) -> Result<(), EncodeError> {
    encoder.write_u32(operation.opcode());
    match operation {
        CallbackArgOp::GetAttr(args) => {
            encode_file_handle(encoder, &args.file_handle)?;
            encode_bitmap(encoder, &args.requested_attributes)?;
        },
        CallbackArgOp::Recall(args) => {
            encode_state_id(encoder, &args.state_id);
            encoder.write_bool(args.truncate);
            encode_file_handle(encoder, &args.file_handle)?;
        },
        CallbackArgOp::Illegal { .. } => {},
    }
    Ok(())
}

fn decode_callback_res_op(decoder: &mut Decoder<'_>, limits: DecodeLimits) -> Result<CallbackResOp, DecodeError> {
    let opnum = decoder.read_enum("nfs_cb_opnum4", CallbackOpNum::from_code)?;
    Ok(match opnum {
        CallbackOpNum::GetAttr => {
            CallbackResOp::GetAttr(decode_status_result(decoder, |decoder| decode_file_attributes(decoder, limits))?)
        },
        CallbackOpNum::Recall => CallbackResOp::Recall(decode_status(decoder)?),
        CallbackOpNum::Illegal => CallbackResOp::Illegal(decode_status(decoder)?),
    })
}

fn encode_callback_res_op(encoder: &mut Encoder, operation: &CallbackResOp) -> Result<(), EncodeError> {
    encoder.write_u32(operation.opnum() as u32);
    match operation {
        CallbackResOp::GetAttr(result) => encode_status_result(encoder, result, encode_file_attributes)?,
        CallbackResOp::Recall(status) | CallbackResOp::Illegal(status) => encode_status(encoder, *status),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_predecoder_distinguishes_valid_operation_exhaustion_from_bad_xdr() {
        let limits = DecodeLimits {
            max_operations: 2,
            ..DecodeLimits::default()
        };
        let over_limit = CompoundArgs {
            tag: b"COMP6".to_vec(),
            minor_version: 0,
            operations: vec![ArgOp::PutRootFh; 3],
        };
        let encoded = encode_compound_args(&over_limit).expect("encode over-limit COMPOUND");
        assert_eq!(
            predecode_compound_args(&encoded, limits),
            Ok(PredecodedCompoundArgs::TooManyOperations {
                tag: b"COMP6".to_vec(),
                minor_version: 0,
                actual: 3,
                limit: 2,
            })
        );

        let at_limit = CompoundArgs {
            operations: vec![ArgOp::PutRootFh; 2],
            ..over_limit.clone()
        };
        let encoded_at_limit = encode_compound_args(&at_limit).expect("encode bounded COMPOUND");
        assert_eq!(predecode_compound_args(&encoded_at_limit, limits), Ok(PredecodedCompoundArgs::Ready(at_limit)));

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(predecode_compound_args(&truncated, limits), Err(DecodeError::Truncated));

        let mut trailing = encoded;
        trailing.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(predecode_compound_args(&trailing, limits), Err(DecodeError::TrailingBytes));

        let mut invalid_late_operation = Encoder::new();
        invalid_late_operation.write_opaque(b"COMP6").unwrap();
        invalid_late_operation.write_u32(0);
        invalid_late_operation.write_u32(3);
        invalid_late_operation.write_u32(OpNum::PutRootFh as u32);
        invalid_late_operation.write_u32(OpNum::PutRootFh as u32);
        invalid_late_operation.write_u32(OpNum::OpenAttr as u32);
        invalid_late_operation.write_u32(2);
        assert_eq!(
            predecode_compound_args(&invalid_late_operation.into_bytes(), limits),
            Err(DecodeError::InvalidBoolean(2))
        );
    }

    fn state_id(seed: u8) -> StateId {
        StateId {
            sequence_id: u32::from(seed),
            other: [seed; NFS4_OTHER_SIZE],
        }
    }

    fn attributes() -> FileAttributes {
        FileAttributes {
            mask: vec![0x8000_0013, 1 << (FATTR4_OWNER - 32)],
            values: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    #[test]
    fn compound_args_round_trip_every_discriminant() {
        let lock_owner = LockOwner {
            client_id: 8,
            owner: b"lock-owner".to_vec(),
        };
        let operations = vec![
            ArgOp::Access(AccessArgs { access: ACCESS4_READ }),
            ArgOp::Close(CloseArgs {
                sequence_id: 1,
                open_state_id: state_id(1),
            }),
            ArgOp::Commit(CommitArgs { offset: 2, count: 3 }),
            ArgOp::Create(CreateArgs {
                object_type: CreateType::Symlink(b"target".to_vec()),
                name: b"name".to_vec(),
                attributes: attributes(),
            }),
            ArgOp::DelegPurge(DelegPurgeArgs { client_id: 4 }),
            ArgOp::DelegReturn(DelegReturnArgs {
                delegation_state_id: state_id(2),
            }),
            ArgOp::GetAttr(GetAttrArgs {
                requested_attributes: vec![7],
            }),
            ArgOp::GetFh,
            ArgOp::Link(LinkArgs {
                new_name: b"link".to_vec(),
            }),
            ArgOp::Lock(LockArgs {
                lock_type: LockType::Write,
                reclaim: false,
                offset: 5,
                length: 6,
                locker: Locker::New(OpenToLockOwner {
                    open_sequence_id: 7,
                    open_state_id: state_id(3),
                    lock_sequence_id: 8,
                    lock_owner: lock_owner.clone(),
                }),
            }),
            ArgOp::LockTest(LockTestArgs {
                lock_type: LockType::Read,
                offset: 9,
                length: 10,
                owner: lock_owner.clone(),
            }),
            ArgOp::LockUnlock(LockUnlockArgs {
                lock_type: LockType::Write,
                sequence_id: 11,
                lock_state_id: state_id(4),
                offset: 12,
                length: 13,
            }),
            ArgOp::Lookup(LookupArgs {
                name: b"lookup".to_vec(),
            }),
            ArgOp::LookupParent,
            ArgOp::NotVerify(NotVerifyArgs {
                attributes: attributes(),
            }),
            ArgOp::Open(OpenArgs {
                sequence_id: 14,
                share_access: OPEN4_SHARE_ACCESS_BOTH,
                share_deny: OPEN4_SHARE_DENY_NONE,
                owner: OpenOwner {
                    client_id: 15,
                    owner: b"open-owner".to_vec(),
                },
                how: OpenHow::Create(CreateHow::Exclusive([16; NFS4_VERIFIER_SIZE])),
                claim: OpenClaim::DelegateCurrent {
                    delegate_state_id: state_id(5),
                    file: b"open".to_vec(),
                },
            }),
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::OpenConfirm(OpenConfirmArgs {
                open_state_id: state_id(6),
                sequence_id: 17,
            }),
            ArgOp::OpenDowngrade(OpenDowngradeArgs {
                open_state_id: state_id(7),
                sequence_id: 18,
                share_access: OPEN4_SHARE_ACCESS_READ,
                share_deny: OPEN4_SHARE_DENY_WRITE,
            }),
            ArgOp::PutFh(PutFhArgs {
                object: NfsFileHandle(vec![19, 20]),
            }),
            ArgOp::PutPublicFh,
            ArgOp::PutRootFh,
            ArgOp::Read(ReadArgs {
                state_id: state_id(8),
                offset: 21,
                count: 22,
            }),
            ArgOp::ReadDir(ReadDirArgs {
                cookie: 23,
                cookie_verifier: [24; NFS4_VERIFIER_SIZE],
                directory_count: 25,
                max_count: 26,
                requested_attributes: vec![27],
            }),
            ArgOp::ReadLink,
            ArgOp::Remove(RemoveArgs {
                target: b"remove".to_vec(),
            }),
            ArgOp::Rename(RenameArgs {
                old_name: b"old".to_vec(),
                new_name: b"new".to_vec(),
            }),
            ArgOp::Renew(RenewArgs { client_id: 28 }),
            ArgOp::RestoreFh,
            ArgOp::SaveFh,
            ArgOp::SecInfo(SecInfoArgs {
                name: b"security".to_vec(),
            }),
            ArgOp::SetAttr(SetAttrArgs {
                state_id: state_id(9),
                attributes: attributes(),
            }),
            ArgOp::SetClientId(SetClientIdArgs {
                client: NfsClientId {
                    verifier: [29; NFS4_VERIFIER_SIZE],
                    id: b"client".to_vec(),
                },
                callback: CallbackClient {
                    program: 0x4000_1000,
                    location: ClientAddress {
                        netid: b"tcp".to_vec(),
                        address: b"127.0.0.1.8.1".to_vec(),
                    },
                },
                callback_identifier: 30,
            }),
            ArgOp::SetClientIdConfirm(SetClientIdConfirmArgs {
                client_id: 31,
                confirmation: [32; NFS4_VERIFIER_SIZE],
            }),
            ArgOp::Verify(VerifyArgs {
                attributes: attributes(),
            }),
            ArgOp::Write(WriteArgs {
                state_id: state_id(10),
                offset: 33,
                stability: StableHow::FileSync,
                data: b"write".to_vec(),
            }),
            ArgOp::ReleaseLockOwner(ReleaseLockOwnerArgs { lock_owner }),
            ArgOp::Illegal { requested_opcode: 99 },
        ];
        let compound = CompoundArgs {
            tag: b"all-args".to_vec(),
            minor_version: 0,
            operations,
        };

        let encoded = compound.encode().unwrap();
        assert_eq!(CompoundArgs::decode(&encoded, DecodeLimits::default()).unwrap(), compound);
    }

    #[test]
    fn compound_results_round_trip_success_and_special_union_arms() {
        let denied = LockDenied {
            offset: 1,
            length: 2,
            lock_type: LockType::Write,
            owner: LockOwner {
                client_id: 3,
                owner: b"owner".to_vec(),
            },
        };
        let operations = vec![
            ResOp::Access(NfsResult::Ok(AccessOk {
                supported: ACCESS4_READ | ACCESS4_LOOKUP,
                access: ACCESS4_READ,
            })),
            ResOp::Close(NfsResult::Ok(state_id(1))),
            ResOp::Commit(NfsResult::Ok(CommitOk {
                write_verifier: [2; NFS4_VERIFIER_SIZE],
            })),
            ResOp::Create(NfsResult::Ok(CreateOk {
                change_info: ChangeInfo {
                    atomic: true,
                    before: 3,
                    after: 4,
                },
                attributes_set: vec![5],
            })),
            ResOp::DelegPurge(NfsStatus::NotSupported),
            ResOp::DelegReturn(NfsStatus::Ok),
            ResOp::GetAttr(NfsResult::Ok(attributes())),
            ResOp::GetFh(NfsResult::Ok(NfsFileHandle(vec![6, 7]))),
            ResOp::Link(NfsResult::Ok(LinkOk {
                change_info: ChangeInfo {
                    atomic: false,
                    before: 8,
                    after: 9,
                },
            })),
            ResOp::Lock(LockResult::Denied(denied.clone())),
            ResOp::LockTest(LockTestResult::Denied(denied)),
            ResOp::LockUnlock(NfsResult::Ok(state_id(2))),
            ResOp::Lookup(NfsStatus::Ok),
            ResOp::LookupParent(NfsStatus::NoFileHandle),
            ResOp::NotVerify(NfsStatus::Same),
            ResOp::Open(NfsResult::Ok(OpenOk {
                state_id: state_id(3),
                change_info: ChangeInfo {
                    atomic: true,
                    before: 10,
                    after: 11,
                },
                result_flags: OPEN4_RESULT_CONFIRM,
                attributes_set: vec![12],
                delegation: OpenDelegation::Write(OpenWriteDelegation {
                    state_id: state_id(4),
                    recall: false,
                    space_limit: SpaceLimit::Blocks {
                        block_count: 13,
                        bytes_per_block: 4096,
                    },
                    permissions: NfsAce {
                        ace_type: 0,
                        flags: 0,
                        access_mask: 14,
                        who: b"OWNER@".to_vec(),
                    },
                }),
            })),
            ResOp::OpenAttr(NfsStatus::Ok),
            ResOp::OpenConfirm(NfsResult::Ok(state_id(5))),
            ResOp::OpenDowngrade(NfsResult::Ok(state_id(6))),
            ResOp::PutFh(NfsStatus::Ok),
            ResOp::PutPublicFh(NfsStatus::NotSupported),
            ResOp::PutRootFh(NfsStatus::Ok),
            ResOp::Read(NfsResult::Ok(ReadOk {
                eof: true,
                data: b"data".to_vec(),
            })),
            ResOp::ReadDir(NfsResult::Ok(ReadDirOk {
                cookie_verifier: [15; NFS4_VERIFIER_SIZE],
                entries: vec![DirectoryEntry {
                    cookie: 16,
                    name: b"entry".to_vec(),
                    attributes: attributes(),
                }],
                eof: true,
            })),
            ResOp::ReadLink(NfsResult::Ok(ReadLinkOk { link: b"link".to_vec() })),
            ResOp::Remove(NfsResult::Ok(RemoveOk {
                change_info: ChangeInfo {
                    atomic: true,
                    before: 17,
                    after: 18,
                },
            })),
            ResOp::Rename(NfsResult::Ok(RenameOk {
                source_change_info: ChangeInfo {
                    atomic: true,
                    before: 19,
                    after: 20,
                },
                target_change_info: ChangeInfo {
                    atomic: false,
                    before: 21,
                    after: 22,
                },
            })),
            ResOp::Renew(NfsStatus::Ok),
            ResOp::RestoreFh(NfsStatus::Ok),
            ResOp::SaveFh(NfsStatus::Ok),
            ResOp::SecInfo(NfsResult::Ok(vec![
                SecurityInfo::Other(1),
                SecurityInfo::RpcSecGss(RpcSecGssInfo {
                    oid: vec![42, 134, 72],
                    qop: 0,
                    service: RpcGssService::Integrity,
                }),
            ])),
            ResOp::SetAttr(SetAttrResult {
                status: NfsStatus::Access,
                attributes_set: vec![23],
            }),
            ResOp::SetClientId(SetClientIdResult::ClientIdInUse(ClientAddress {
                netid: b"tcp6".to_vec(),
                address: b"::1.8.1".to_vec(),
            })),
            ResOp::SetClientIdConfirm(NfsStatus::Ok),
            ResOp::Verify(NfsStatus::NotSame),
            ResOp::Write(NfsResult::Ok(WriteOk {
                count: 24,
                committed: StableHow::DataSync,
                write_verifier: [25; NFS4_VERIFIER_SIZE],
            })),
            ResOp::ReleaseLockOwner(NfsStatus::LocksHeld),
            ResOp::Illegal(NfsStatus::OperationIllegal),
        ];
        let compound = CompoundRes {
            status: NfsStatus::OperationIllegal,
            tag: b"all-results".to_vec(),
            operations,
        };

        let encoded = compound.encode().unwrap();
        assert_eq!(encoded_compound_res_len(&compound.tag, &compound.operations).unwrap(), encoded.len());
        assert_eq!(CompoundRes::decode(&encoded, DecodeLimits::default()).unwrap(), compound);
    }

    #[test]
    fn segmented_compound_reply_matches_contiguous_wire_with_multiple_reads() {
        let response = CompoundRes::from_operations(
            b"reads".to_vec(),
            vec![
                ResOp::PutRootFh(NfsStatus::Ok),
                ResOp::Read(NfsResult::Ok(ReadOk {
                    eof: false,
                    data: b"a".to_vec(),
                })),
                ResOp::SaveFh(NfsStatus::Ok),
                ResOp::Read(NfsResult::Ok(ReadOk {
                    eof: true,
                    data: b"bcde".to_vec(),
                })),
                ResOp::RestoreFh(NfsStatus::Ok),
            ],
        );
        let contiguous_body = encode_compound_res(&response).unwrap();
        let rpc_prefix = Bytes::from_static(b"accepted-rpc-prefix");
        let expected = [rpc_prefix.as_ref(), contiguous_body.as_slice()].concat();
        let reply =
            encode_compound_res_segmented(response, rpc_prefix.clone(), DecodeLimits::default(), expected.len())
                .unwrap();

        let segments: Vec<_> = reply.segments().collect();
        assert_eq!(segments.len(), 6);
        assert_eq!(segments[0], rpc_prefix.as_ref());
        assert_eq!(segments[2], b"a");
        assert_eq!(&segments[3][..3], &[0, 0, 0]);
        assert_eq!(segments[4], b"bcde");
        assert_eq!(reply.clone().into_bytes().as_ref(), expected);
        assert_eq!(reply.len(), expected.len());
    }

    #[test]
    fn segmented_read_padding_and_record_boundary_are_exact() {
        for data_len in 0..=8 {
            let response = CompoundRes::from_operations(
                Vec::new(),
                vec![ResOp::Read(NfsResult::Ok(ReadOk {
                    eof: true,
                    data: vec![0x5a; data_len],
                }))],
            );
            let contiguous = encode_compound_res(&response).unwrap();
            let prefix = Bytes::from_static(b"rpc");
            let exact_limit = prefix.len() + contiguous.len();
            let reply =
                encode_compound_res_segmented(response.clone(), prefix.clone(), DecodeLimits::default(), exact_limit)
                    .unwrap();
            assert_eq!(reply.clone().into_bytes().as_ref(), [prefix.as_ref(), contiguous.as_slice()].concat());
            assert_eq!(reply.len(), exact_limit);
            assert_eq!(reply.segments().nth(2).unwrap(), vec![0x5a; data_len]);

            assert!(matches!(
                encode_compound_res_segmented(
                    response,
                    prefix.clone(),
                    DecodeLimits::default(),
                    exact_limit - 1,
                ),
                Err(EncodeError::TooLarge(actual)) if actual == exact_limit
            ));
        }
    }

    #[test]
    fn segmented_reply_rejects_result_and_segment_counts_above_decode_limit() {
        let response = CompoundRes::from_operations(
            Vec::new(),
            vec![
                ResOp::Read(NfsResult::Ok(ReadOk {
                    eof: false,
                    data: vec![1],
                })),
                ResOp::Read(NfsResult::Ok(ReadOk {
                    eof: true,
                    data: vec![2],
                })),
            ],
        );
        let limits = DecodeLimits {
            max_operations: 1,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            encode_compound_res_segmented(response, Bytes::new(), limits, 1024),
            Err(EncodeError::TooLarge(2))
        ));
    }

    #[test]
    fn callbacks_round_trip() {
        let arguments = CallbackCompoundArgs {
            tag: b"callback".to_vec(),
            minor_version: 0,
            callback_identifier: 7,
            operations: vec![
                CallbackArgOp::GetAttr(CallbackGetAttrArgs {
                    file_handle: NfsFileHandle(vec![1, 2, 3]),
                    requested_attributes: vec![4],
                }),
                CallbackArgOp::Recall(CallbackRecallArgs {
                    state_id: state_id(5),
                    truncate: true,
                    file_handle: NfsFileHandle(vec![6]),
                }),
                CallbackArgOp::Illegal { requested_opcode: 77 },
            ],
        };
        let bytes = arguments.encode().unwrap();
        assert_eq!(CallbackCompoundArgs::decode(&bytes, DecodeLimits::default()).unwrap(), arguments);

        let results = CallbackCompoundRes {
            status: NfsStatus::OperationIllegal,
            tag: b"callback".to_vec(),
            operations: vec![
                CallbackResOp::GetAttr(NfsResult::Ok(attributes())),
                CallbackResOp::Recall(NfsStatus::Ok),
                CallbackResOp::Illegal(NfsStatus::OperationIllegal),
            ],
        };
        let bytes = results.encode().unwrap();
        assert_eq!(CallbackCompoundRes::decode(&bytes, DecodeLimits::default()).unwrap(), results);
    }

    #[test]
    fn rejects_trailing_bytes_and_collection_counts_before_allocating() {
        let compound = CompoundArgs {
            tag: Vec::new(),
            minor_version: 0,
            operations: Vec::new(),
        };
        let mut trailing = compound.encode().unwrap();
        trailing.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(CompoundArgs::decode(&trailing, DecodeLimits::default()), Err(DecodeError::TrailingBytes));

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&0u32.to_be_bytes());
        oversized.extend_from_slice(&0u32.to_be_bytes());
        oversized.extend_from_slice(&129u32.to_be_bytes());
        assert!(matches!(
            CompoundArgs::decode(&oversized, DecodeLimits::default()),
            Err(DecodeError::LimitExceeded {
                field: "NFSv4 operations",
                actual: 129,
                limit: 128
            })
        ));
    }

    #[test]
    fn unknown_request_operation_is_retained_as_illegal() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&2u32.to_be_bytes());

        let decoded = CompoundArgs::decode(&wire, DecodeLimits::default()).unwrap();
        assert_eq!(decoded.operations, vec![ArgOp::Illegal { requested_opcode: 2 }]);
    }

    #[test]
    fn rejects_noncanonical_xdr_boolean_inside_operation() {
        let arguments = CompoundArgs {
            tag: Vec::new(),
            minor_version: 0,
            operations: vec![ArgOp::OpenAttr(OpenAttrArgs {
                create_directory: false,
            })],
        };
        let mut wire = arguments.encode().unwrap();
        let final_word = wire.len() - 4;
        wire[final_word..].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(CompoundArgs::decode(&wire, DecodeLimits::default()), Err(DecodeError::InvalidBoolean(2)));
    }
}
