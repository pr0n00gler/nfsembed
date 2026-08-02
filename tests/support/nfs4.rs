//! Focused NFSv4.0 wire fixtures.
//!
//! These helpers intentionally encode raw RPC/XDR and do not depend on the
//! server's in-progress NFSv4 implementation. They are suitable for golden
//! fixtures, malformed-input tests, and future black-box protocol tests.

use nfsembed::rpc::codec::{DecodeError, EncodeError, Encoder};

pub const NFS_PROGRAM: u32 = 100_003;
pub const NFS4_VERSION: u32 = 4;
pub const NFS4_MINOR_VERSION: u32 = 0;
pub const NFS4_PROC_NULL: u32 = 0;
pub const NFS4_PROC_COMPOUND: u32 = 1;

pub const NFS4_OK: u32 = 0;
pub const NFS4ERR_MINOR_VERS_MISMATCH: u32 = 10_021;
pub const NFS4ERR_OP_ILLEGAL: u32 = 10_044;

pub const OP_ACCESS: u32 = 3;
pub const OP_CLOSE: u32 = 4;
pub const OP_COMMIT: u32 = 5;
pub const OP_CREATE: u32 = 6;
pub const OP_DELEGPURGE: u32 = 7;
pub const OP_DELEGRETURN: u32 = 8;
pub const OP_GETATTR: u32 = 9;
pub const OP_GETFH: u32 = 10;
pub const OP_LINK: u32 = 11;
pub const OP_LOCK: u32 = 12;
pub const OP_LOCKT: u32 = 13;
pub const OP_LOCKU: u32 = 14;
pub const OP_LOOKUP: u32 = 15;
pub const OP_LOOKUPP: u32 = 16;
pub const OP_NVERIFY: u32 = 17;
pub const OP_OPEN: u32 = 18;
pub const OP_OPENATTR: u32 = 19;
pub const OP_OPEN_CONFIRM: u32 = 20;
pub const OP_OPEN_DOWNGRADE: u32 = 21;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTPUBFH: u32 = 23;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_REMOVE: u32 = 28;
pub const OP_RENAME: u32 = 29;
pub const OP_RENEW: u32 = 30;
pub const OP_RESTOREFH: u32 = 31;
pub const OP_SAVEFH: u32 = 32;
pub const OP_SECINFO: u32 = 33;
pub const OP_SETATTR: u32 = 34;
pub const OP_SETCLIENTID: u32 = 35;
pub const OP_SETCLIENTID_CONFIRM: u32 = 36;
pub const OP_VERIFY: u32 = 37;
pub const OP_WRITE: u32 = 38;
pub const OP_RELEASE_LOCKOWNER: u32 = 39;
pub const OP_ILLEGAL: u32 = 10_044;

pub const MAX_COMPOUND_TAG_SIZE: usize = 1_024;
pub const MAX_COMPOUND_OPERATIONS: usize = 128;
pub const MAX_NFS4_FILE_HANDLE_SIZE: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueAuth {
    pub flavor: u32,
    pub body: Vec<u8>,
}

impl OpaqueAuth {
    pub fn none() -> Self {
        Self {
            flavor: 0,
            body: Vec::new(),
        }
    }

    pub fn raw(flavor: u32, body: impl Into<Vec<u8>>) -> Self {
        Self {
            flavor,
            body: body.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StableHow {
    Unstable = 0,
    DataSync = 1,
    FileSync = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateId {
    pub sequence_id: u32,
    pub other: [u8; 12],
}

impl StateId {
    pub const ANONYMOUS: Self = Self {
        sequence_id: 0,
        other: [0; 12],
    };

    pub fn encode_into(self, encoder: &mut Encoder) {
        encoder.write_u32(self.sequence_id);
        encoder.write_fixed(&self.other);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4Operation {
    pub number: u32,
    pub arguments: Vec<u8>,
}

impl Nfs4Operation {
    pub fn new(number: u32, arguments: Vec<u8>) -> Self {
        Self { number, arguments }
    }

    pub fn empty(number: u32) -> Self {
        Self::new(number, Vec::new())
    }

    pub fn access(mask: u32) -> Self {
        Self::encoded(OP_ACCESS, |encoder| {
            encoder.write_u32(mask);
            Ok(())
        })
        .expect("fixed-width ACCESS arguments cannot fail to encode")
    }

    pub fn commit(offset: u64, count: u32) -> Self {
        Self::encoded(OP_COMMIT, |encoder| {
            encoder.write_u64(offset);
            encoder.write_u32(count);
            Ok(())
        })
        .expect("fixed-width COMMIT arguments cannot fail to encode")
    }

    pub fn getattr(bitmap_words: &[u32]) -> Result<Self, EncodeError> {
        Self::encoded(OP_GETATTR, |encoder| encode_bitmap(encoder, bitmap_words))
    }

    pub fn getfh() -> Self {
        Self::empty(OP_GETFH)
    }

    pub fn lookup(component: &[u8]) -> Result<Self, EncodeError> {
        Self::encoded(OP_LOOKUP, |encoder| encoder.write_opaque(component))
    }

    pub fn lookupp() -> Self {
        Self::empty(OP_LOOKUPP)
    }

    pub fn putfh(file_handle: &[u8]) -> Result<Self, EncodeError> {
        Self::encoded(OP_PUTFH, |encoder| encoder.write_opaque(file_handle))
    }

    pub fn putpubfh() -> Self {
        Self::empty(OP_PUTPUBFH)
    }

    pub fn putrootfh() -> Self {
        Self::empty(OP_PUTROOTFH)
    }

    pub fn read(state_id: StateId, offset: u64, count: u32) -> Self {
        Self::encoded(OP_READ, |encoder| {
            state_id.encode_into(encoder);
            encoder.write_u64(offset);
            encoder.write_u32(count);
            Ok(())
        })
        .expect("fixed-width READ arguments cannot fail to encode")
    }

    pub fn remove(component: &[u8]) -> Result<Self, EncodeError> {
        Self::encoded(OP_REMOVE, |encoder| encoder.write_opaque(component))
    }

    pub fn rename(old_component: &[u8], new_component: &[u8]) -> Result<Self, EncodeError> {
        Self::encoded(OP_RENAME, |encoder| {
            encoder.write_opaque(old_component)?;
            encoder.write_opaque(new_component)
        })
    }

    pub fn restorefh() -> Self {
        Self::empty(OP_RESTOREFH)
    }

    pub fn savefh() -> Self {
        Self::empty(OP_SAVEFH)
    }

    pub fn write(state_id: StateId, offset: u64, stability: StableHow, data: &[u8]) -> Result<Self, EncodeError> {
        Self::encoded(OP_WRITE, |encoder| {
            state_id.encode_into(encoder);
            encoder.write_u64(offset);
            encoder.write_u32(stability as u32);
            encoder.write_opaque(data)
        })
    }

    fn encoded(number: u32, encode: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>) -> Result<Self, EncodeError> {
        let mut encoder = Encoder::new();
        encode(&mut encoder)?;
        Ok(Self::new(number, encoder.into_bytes()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompoundRequest {
    pub tag: Vec<u8>,
    pub minor_version: u32,
    pub operations: Vec<Nfs4Operation>,
}

impl CompoundRequest {
    pub fn new(tag: impl AsRef<[u8]>) -> Self {
        Self {
            tag: tag.as_ref().to_vec(),
            minor_version: NFS4_MINOR_VERSION,
            operations: Vec::new(),
        }
    }

    pub fn with_minor_version(mut self, minor_version: u32) -> Self {
        self.minor_version = minor_version;
        self
    }

    pub fn with_operation(mut self, operation: Nfs4Operation) -> Self {
        self.operations.push(operation);
        self
    }

    pub fn push(&mut self, operation: Nfs4Operation) {
        self.operations.push(operation);
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let operation_count =
            u32::try_from(self.operations.len()).map_err(|_| EncodeError::TooLarge(self.operations.len()))?;
        let mut encoder = Encoder::new();
        encoder.write_opaque(&self.tag)?;
        encoder.write_u32(self.minor_version);
        encoder.write_u32(operation_count);
        for operation in &self.operations {
            encoder.write_u32(operation.number);
            encoder.write_fixed(&operation.arguments);
        }
        Ok(encoder.into_bytes())
    }

    pub fn encode_rpc_call(&self, xid: u32, credential: &OpaqueAuth) -> Result<Vec<u8>, EncodeError> {
        self.encode_rpc_call_with_verifier(xid, credential, &OpaqueAuth::none())
    }

    pub fn encode_rpc_call_with_verifier(
        &self,
        xid: u32,
        credential: &OpaqueAuth,
        verifier: &OpaqueAuth,
    ) -> Result<Vec<u8>, EncodeError> {
        let arguments = self.encode()?;
        let mut encoder = Encoder::new();
        encoder.write_u32(xid);
        encoder.write_u32(0);
        encoder.write_u32(2);
        encoder.write_u32(NFS_PROGRAM);
        encoder.write_u32(NFS4_VERSION);
        encoder.write_u32(NFS4_PROC_COMPOUND);
        encoder.write_u32(credential.flavor);
        encoder.write_opaque(&credential.body)?;
        encoder.write_u32(verifier.flavor);
        encoder.write_opaque(&verifier.body)?;
        encoder.write_fixed(&arguments);
        Ok(encoder.into_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompoundReplyHeader {
    pub status: u32,
    pub tag: Vec<u8>,
    pub result_count: usize,
    pub result_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusOnlyResult {
    pub operation: u32,
    pub status: u32,
}

pub fn decode_compound_reply_header(input: &[u8]) -> Result<CompoundReplyHeader, DecodeError> {
    let mut decoder = nfsembed::rpc::codec::Decoder::new(input);
    let status = decoder.read_u32()?;
    let tag = decoder.read_opaque("NFSv4 COMPOUND tag", MAX_COMPOUND_TAG_SIZE)?;
    let result_count = usize::try_from(decoder.read_u32()?).map_err(|_| DecodeError::Overflow)?;
    if result_count > MAX_COMPOUND_OPERATIONS {
        return Err(DecodeError::LimitExceeded {
            field: "NFSv4 COMPOUND results",
            actual: result_count,
            limit: MAX_COMPOUND_OPERATIONS,
        });
    }
    let result_bytes = input[decoder.position()..].to_vec();
    Ok(CompoundReplyHeader {
        status,
        tag,
        result_count,
        result_bytes,
    })
}

pub fn decode_status_only_reply(input: &[u8]) -> Result<(CompoundReplyHeader, Vec<StatusOnlyResult>), DecodeError> {
    let reply = decode_compound_reply_header(input)?;
    let mut decoder = nfsembed::rpc::codec::Decoder::new(&reply.result_bytes);
    let mut results = Vec::new();
    results
        .try_reserve_exact(reply.result_count)
        .map_err(|_| DecodeError::LimitExceeded {
            field: "NFSv4 COMPOUND results",
            actual: reply.result_count,
            limit: MAX_COMPOUND_OPERATIONS,
        })?;
    for _ in 0..reply.result_count {
        results.push(StatusOnlyResult {
            operation: decoder.read_u32()?,
            status: decoder.read_u32()?,
        });
    }
    decoder.finish()?;
    Ok((reply, results))
}

pub fn encode_status_only_reply(status: u32, tag: &[u8], results: &[StatusOnlyResult]) -> Result<Vec<u8>, EncodeError> {
    let result_count = u32::try_from(results.len()).map_err(|_| EncodeError::TooLarge(results.len()))?;
    let mut encoder = Encoder::new();
    encoder.write_u32(status);
    encoder.write_opaque(tag)?;
    encoder.write_u32(result_count);
    for result in results {
        encoder.write_u32(result.operation);
        encoder.write_u32(result.status);
    }
    Ok(encoder.into_bytes())
}

fn encode_bitmap(encoder: &mut Encoder, words: &[u32]) -> Result<(), EncodeError> {
    let word_count = u32::try_from(words.len()).map_err(|_| EncodeError::TooLarge(words.len()))?;
    encoder.write_u32(word_count);
    for word in words {
        encoder.write_u32(*word);
    }
    Ok(())
}
