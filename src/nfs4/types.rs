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

//! Strongly typed Rust representation of the RFC 7531 NFSv4.0 XDR.

pub const PROGRAM: u32 = 100_003;
pub const VERSION: u32 = 4;
pub const NULL_PROCEDURE: u32 = 0;
pub const COMPOUND_PROCEDURE: u32 = 1;
pub const NFS4_PROGRAM: u32 = PROGRAM;
pub const NFS_V4: u32 = VERSION;
pub const NFSPROC4_NULL: u32 = NULL_PROCEDURE;
pub const NFSPROC4_COMPOUND: u32 = COMPOUND_PROCEDURE;

/// RFC 7531 uses the start of the transient RPC program range as a
/// placeholder. A client chooses the actual callback program number.
pub const CALLBACK_PROGRAM_TRANSIENT_BASE: u32 = 0x4000_0000;
pub const CALLBACK_VERSION: u32 = 1;
pub const CALLBACK_NULL_PROCEDURE: u32 = 0;
pub const CALLBACK_COMPOUND_PROCEDURE: u32 = 1;
pub const NFS4_CALLBACK: u32 = CALLBACK_PROGRAM_TRANSIENT_BASE;
pub const NFS_CB: u32 = CALLBACK_VERSION;
pub const CB_NULL: u32 = CALLBACK_NULL_PROCEDURE;
pub const CB_COMPOUND: u32 = CALLBACK_COMPOUND_PROCEDURE;

pub const NFS4_FHSIZE: usize = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OTHER_SIZE: usize = 12;
pub const NFS4_OPAQUE_LIMIT: usize = 1024;

pub const ACCESS4_READ: u32 = 0x0000_0001;
pub const ACCESS4_LOOKUP: u32 = 0x0000_0002;
pub const ACCESS4_MODIFY: u32 = 0x0000_0004;
pub const ACCESS4_EXTEND: u32 = 0x0000_0008;
pub const ACCESS4_DELETE: u32 = 0x0000_0010;
pub const ACCESS4_EXECUTE: u32 = 0x0000_0020;

pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 0x0000_0002;
pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 0x0000_0003;
pub const OPEN4_SHARE_DENY_NONE: u32 = 0x0000_0000;
pub const OPEN4_SHARE_DENY_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_DENY_WRITE: u32 = 0x0000_0002;
pub const OPEN4_SHARE_DENY_BOTH: u32 = 0x0000_0003;
pub const OPEN4_RESULT_CONFIRM: u32 = 0x0000_0002;
pub const OPEN4_RESULT_LOCKTYPE_POSIX: u32 = 0x0000_0004;

pub const RPCSEC_GSS: u32 = 6;

pub const FATTR4_SUPPORTED_ATTRS: u32 = 0;
pub const FATTR4_TYPE: u32 = 1;
pub const FATTR4_FH_EXPIRE_TYPE: u32 = 2;
pub const FATTR4_CHANGE: u32 = 3;
pub const FATTR4_SIZE: u32 = 4;
pub const FATTR4_LINK_SUPPORT: u32 = 5;
pub const FATTR4_SYMLINK_SUPPORT: u32 = 6;
pub const FATTR4_NAMED_ATTR: u32 = 7;
pub const FATTR4_FSID: u32 = 8;
pub const FATTR4_UNIQUE_HANDLES: u32 = 9;
pub const FATTR4_LEASE_TIME: u32 = 10;
pub const FATTR4_RDATTR_ERROR: u32 = 11;
pub const FATTR4_ACL: u32 = 12;
pub const FATTR4_ACLSUPPORT: u32 = 13;
pub const FATTR4_ARCHIVE: u32 = 14;
pub const FATTR4_CANSETTIME: u32 = 15;
pub const FATTR4_CASE_INSENSITIVE: u32 = 16;
pub const FATTR4_CASE_PRESERVING: u32 = 17;
pub const FATTR4_CHOWN_RESTRICTED: u32 = 18;
pub const FATTR4_FILEHANDLE: u32 = 19;
pub const FATTR4_FILEID: u32 = 20;
pub const FATTR4_FILES_AVAIL: u32 = 21;
pub const FATTR4_FILES_FREE: u32 = 22;
pub const FATTR4_FILES_TOTAL: u32 = 23;
pub const FATTR4_FS_LOCATIONS: u32 = 24;
pub const FATTR4_HIDDEN: u32 = 25;
pub const FATTR4_HOMOGENEOUS: u32 = 26;
pub const FATTR4_MAXFILESIZE: u32 = 27;
pub const FATTR4_MAXLINK: u32 = 28;
pub const FATTR4_MAXNAME: u32 = 29;
pub const FATTR4_MAXREAD: u32 = 30;
pub const FATTR4_MAXWRITE: u32 = 31;
pub const FATTR4_MIMETYPE: u32 = 32;
pub const FATTR4_MODE: u32 = 33;
pub const FATTR4_NO_TRUNC: u32 = 34;
pub const FATTR4_NUMLINKS: u32 = 35;
pub const FATTR4_OWNER: u32 = 36;
pub const FATTR4_OWNER_GROUP: u32 = 37;
pub const FATTR4_QUOTA_AVAIL_HARD: u32 = 38;
pub const FATTR4_QUOTA_AVAIL_SOFT: u32 = 39;
pub const FATTR4_QUOTA_USED: u32 = 40;
pub const FATTR4_RAWDEV: u32 = 41;
pub const FATTR4_SPACE_AVAIL: u32 = 42;
pub const FATTR4_SPACE_FREE: u32 = 43;
pub const FATTR4_SPACE_TOTAL: u32 = 44;
pub const FATTR4_SPACE_USED: u32 = 45;
pub const FATTR4_SYSTEM: u32 = 46;
pub const FATTR4_TIME_ACCESS: u32 = 47;
pub const FATTR4_TIME_ACCESS_SET: u32 = 48;
pub const FATTR4_TIME_BACKUP: u32 = 49;
pub const FATTR4_TIME_CREATE: u32 = 50;
pub const FATTR4_TIME_DELTA: u32 = 51;
pub const FATTR4_TIME_METADATA: u32 = 52;
pub const FATTR4_TIME_MODIFY: u32 = 53;
pub const FATTR4_TIME_MODIFY_SET: u32 = 54;
pub const FATTR4_MOUNTED_ON_FILEID: u32 = 55;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Procedure {
    Null = NULL_PROCEDURE,
    Compound = COMPOUND_PROCEDURE,
}

impl Procedure {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            NULL_PROCEDURE => Some(Self::Null),
            COMPOUND_PROCEDURE => Some(Self::Compound),
            _ => None,
        }
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CallbackProcedure {
    Null = CALLBACK_NULL_PROCEDURE,
    Compound = CALLBACK_COMPOUND_PROCEDURE,
}

impl CallbackProcedure {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            CALLBACK_NULL_PROCEDURE => Some(Self::Null),
            CALLBACK_COMPOUND_PROCEDURE => Some(Self::Compound),
            _ => None,
        }
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NfsFileType {
    Regular = 1,
    Directory = 2,
    Block = 3,
    Character = 4,
    Symlink = 5,
    Socket = 6,
    Fifo = 7,
    AttributeDirectory = 8,
    NamedAttribute = 9,
}

impl NfsFileType {
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::Regular,
            2 => Self::Directory,
            3 => Self::Block,
            4 => Self::Character,
            5 => Self::Symlink,
            6 => Self::Socket,
            7 => Self::Fifo,
            8 => Self::AttributeDirectory,
            9 => Self::NamedAttribute,
            _ => return None,
        })
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NfsStatus {
    Ok = 0,
    Permission = 1,
    NotFound = 2,
    Io = 5,
    NoDeviceOrAddress = 6,
    Access = 13,
    Exists = 17,
    CrossDevice = 18,
    NotDirectory = 20,
    IsDirectory = 21,
    Invalid = 22,
    FileTooLarge = 27,
    NoSpace = 28,
    ReadOnly = 30,
    TooManyLinks = 31,
    NameTooLong = 63,
    NotEmpty = 66,
    Quota = 69,
    Stale = 70,
    BadHandle = 10001,
    BadCookie = 10003,
    NotSupported = 10004,
    TooSmall = 10005,
    ServerFault = 10006,
    BadType = 10007,
    Delay = 10008,
    Same = 10009,
    Denied = 10010,
    Expired = 10011,
    Locked = 10012,
    Grace = 10013,
    FileHandleExpired = 10014,
    ShareDenied = 10015,
    WrongSecurity = 10016,
    ClientIdInUse = 10017,
    Resource = 10018,
    Moved = 10019,
    NoFileHandle = 10020,
    MinorVersionMismatch = 10021,
    StaleClientId = 10022,
    StaleStateId = 10023,
    OldStateId = 10024,
    BadStateId = 10025,
    BadSequenceId = 10026,
    NotSame = 10027,
    LockRange = 10028,
    Symlink = 10029,
    RestoreFileHandle = 10030,
    LeaseMoved = 10031,
    AttributeNotSupported = 10032,
    NoGrace = 10033,
    ReclaimBad = 10034,
    ReclaimConflict = 10035,
    BadXdr = 10036,
    LocksHeld = 10037,
    OpenMode = 10038,
    BadOwner = 10039,
    BadCharacter = 10040,
    BadName = 10041,
    BadRange = 10042,
    LockNotSupported = 10043,
    OperationIllegal = 10044,
    Deadlock = 10045,
    FileOpen = 10046,
    AdminRevoked = 10047,
    CallbackPathDown = 10048,
}

impl NfsStatus {
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::Permission,
            2 => Self::NotFound,
            5 => Self::Io,
            6 => Self::NoDeviceOrAddress,
            13 => Self::Access,
            17 => Self::Exists,
            18 => Self::CrossDevice,
            20 => Self::NotDirectory,
            21 => Self::IsDirectory,
            22 => Self::Invalid,
            27 => Self::FileTooLarge,
            28 => Self::NoSpace,
            30 => Self::ReadOnly,
            31 => Self::TooManyLinks,
            63 => Self::NameTooLong,
            66 => Self::NotEmpty,
            69 => Self::Quota,
            70 => Self::Stale,
            10001 => Self::BadHandle,
            10003 => Self::BadCookie,
            10004 => Self::NotSupported,
            10005 => Self::TooSmall,
            10006 => Self::ServerFault,
            10007 => Self::BadType,
            10008 => Self::Delay,
            10009 => Self::Same,
            10010 => Self::Denied,
            10011 => Self::Expired,
            10012 => Self::Locked,
            10013 => Self::Grace,
            10014 => Self::FileHandleExpired,
            10015 => Self::ShareDenied,
            10016 => Self::WrongSecurity,
            10017 => Self::ClientIdInUse,
            10018 => Self::Resource,
            10019 => Self::Moved,
            10020 => Self::NoFileHandle,
            10021 => Self::MinorVersionMismatch,
            10022 => Self::StaleClientId,
            10023 => Self::StaleStateId,
            10024 => Self::OldStateId,
            10025 => Self::BadStateId,
            10026 => Self::BadSequenceId,
            10027 => Self::NotSame,
            10028 => Self::LockRange,
            10029 => Self::Symlink,
            10030 => Self::RestoreFileHandle,
            10031 => Self::LeaseMoved,
            10032 => Self::AttributeNotSupported,
            10033 => Self::NoGrace,
            10034 => Self::ReclaimBad,
            10035 => Self::ReclaimConflict,
            10036 => Self::BadXdr,
            10037 => Self::LocksHeld,
            10038 => Self::OpenMode,
            10039 => Self::BadOwner,
            10040 => Self::BadCharacter,
            10041 => Self::BadName,
            10042 => Self::BadRange,
            10043 => Self::LockNotSupported,
            10044 => Self::OperationIllegal,
            10045 => Self::Deadlock,
            10046 => Self::FileOpen,
            10047 => Self::AdminRevoked,
            10048 => Self::CallbackPathDown,
            _ => return None,
        })
    }

    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OpNum {
    Access = 3,
    Close = 4,
    Commit = 5,
    Create = 6,
    DelegPurge = 7,
    DelegReturn = 8,
    GetAttr = 9,
    GetFh = 10,
    Link = 11,
    Lock = 12,
    LockTest = 13,
    LockUnlock = 14,
    Lookup = 15,
    LookupParent = 16,
    NotVerify = 17,
    Open = 18,
    OpenAttr = 19,
    OpenConfirm = 20,
    OpenDowngrade = 21,
    PutFh = 22,
    PutPublicFh = 23,
    PutRootFh = 24,
    Read = 25,
    ReadDir = 26,
    ReadLink = 27,
    Remove = 28,
    Rename = 29,
    Renew = 30,
    RestoreFh = 31,
    SaveFh = 32,
    SecInfo = 33,
    SetAttr = 34,
    SetClientId = 35,
    SetClientIdConfirm = 36,
    Verify = 37,
    Write = 38,
    ReleaseLockOwner = 39,
    Illegal = 10044,
}

impl OpNum {
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            3 => Self::Access,
            4 => Self::Close,
            5 => Self::Commit,
            6 => Self::Create,
            7 => Self::DelegPurge,
            8 => Self::DelegReturn,
            9 => Self::GetAttr,
            10 => Self::GetFh,
            11 => Self::Link,
            12 => Self::Lock,
            13 => Self::LockTest,
            14 => Self::LockUnlock,
            15 => Self::Lookup,
            16 => Self::LookupParent,
            17 => Self::NotVerify,
            18 => Self::Open,
            19 => Self::OpenAttr,
            20 => Self::OpenConfirm,
            21 => Self::OpenDowngrade,
            22 => Self::PutFh,
            23 => Self::PutPublicFh,
            24 => Self::PutRootFh,
            25 => Self::Read,
            26 => Self::ReadDir,
            27 => Self::ReadLink,
            28 => Self::Remove,
            29 => Self::Rename,
            30 => Self::Renew,
            31 => Self::RestoreFh,
            32 => Self::SaveFh,
            33 => Self::SecInfo,
            34 => Self::SetAttr,
            35 => Self::SetClientId,
            36 => Self::SetClientIdConfirm,
            37 => Self::Verify,
            38 => Self::Write,
            39 => Self::ReleaseLockOwner,
            10044 => Self::Illegal,
            _ => return None,
        })
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CallbackOpNum {
    GetAttr = 3,
    Recall = 4,
    Illegal = 10044,
}

impl CallbackOpNum {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            3 => Some(Self::GetAttr),
            4 => Some(Self::Recall),
            10044 => Some(Self::Illegal),
            _ => None,
        }
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

pub type Bitmap = Vec<u32>;
pub type Utf8String = Vec<u8>;
pub type Component = Vec<u8>;
pub type LinkText = Vec<u8>;
pub type Verifier = [u8; NFS4_VERIFIER_SIZE];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsFileHandle(pub Vec<u8>);

impl NfsFileHandle {
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() <= NFS4_FHSIZE).then_some(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NfsTime {
    pub seconds: i64,
    pub nanoseconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetTime {
    Server,
    Client(NfsTime),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpecData {
    pub major: u32,
    pub minor: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsId {
    pub major: u64,
    pub minor: u64,
}

pub type PathName = Vec<Component>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsLocation {
    pub servers: Vec<Utf8String>,
    pub root_path: PathName,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsLocations {
    pub file_system_root: PathName,
    pub locations: Vec<FsLocation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAttributes {
    pub mask: Bitmap,
    /// Concatenated XDR attribute values in ascending attribute-number order.
    pub values: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeInfo {
    pub atomic: bool,
    pub before: u64,
    pub after: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAddress {
    pub netid: Vec<u8>,
    pub address: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackClient {
    pub program: u32,
    pub location: ClientAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateId {
    pub sequence_id: u32,
    pub other: [u8; NFS4_OTHER_SIZE],
}

pub const ANONYMOUS_STATE_ID: StateId = StateId {
    sequence_id: 0,
    other: [0; NFS4_OTHER_SIZE],
};
pub const READ_BYPASS_STATE_ID: StateId = StateId {
    sequence_id: u32::MAX,
    other: [u8::MAX; NFS4_OTHER_SIZE],
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsClientId {
    pub verifier: Verifier,
    pub id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenOwner {
    pub client_id: u64,
    pub owner: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockOwner {
    pub client_id: u64,
    pub owner: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LockType {
    Read = 1,
    Write = 2,
    BlockingRead = 3,
    BlockingWrite = 4,
}

impl LockType {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::BlockingRead),
            4 => Some(Self::BlockingWrite),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenToLockOwner {
    pub open_sequence_id: u32,
    pub open_state_id: StateId,
    pub lock_sequence_id: u32,
    pub lock_owner: LockOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingLockOwner {
    pub lock_state_id: StateId,
    pub lock_sequence_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Locker {
    New(OpenToLockOwner),
    Existing(ExistingLockOwner),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockDenied {
    pub offset: u64,
    pub length: u64,
    pub lock_type: LockType,
    pub owner: LockOwner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfsAce {
    pub ace_type: u32,
    pub flags: u32,
    pub access_mask: u32,
    pub who: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CreateMode {
    Unchecked = 0,
    Guarded = 1,
    Exclusive = 2,
}

impl CreateMode {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Unchecked),
            1 => Some(Self::Guarded),
            2 => Some(Self::Exclusive),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateHow {
    Unchecked(FileAttributes),
    Guarded(FileAttributes),
    Exclusive(Verifier),
}

impl CreateHow {
    pub const fn mode(&self) -> CreateMode {
        match self {
            Self::Unchecked(_) => CreateMode::Unchecked,
            Self::Guarded(_) => CreateMode::Guarded,
            Self::Exclusive(_) => CreateMode::Exclusive,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenHow {
    NoCreate,
    Create(CreateHow),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OpenDelegationType {
    None = 0,
    Read = 1,
    Write = 2,
}

impl OpenDelegationType {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenClaim {
    Null(Component),
    Previous(OpenDelegationType),
    DelegateCurrent {
        delegate_state_id: StateId,
        file: Component,
    },
    DelegatePrevious(Component),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaceLimit {
    Size(u64),
    Blocks { block_count: u32, bytes_per_block: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenReadDelegation {
    pub state_id: StateId,
    pub recall: bool,
    pub permissions: NfsAce,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenWriteDelegation {
    pub state_id: StateId,
    pub recall: bool,
    pub space_limit: SpaceLimit,
    pub permissions: NfsAce,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenDelegation {
    None,
    Read(OpenReadDelegation),
    Write(OpenWriteDelegation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StableHow {
    Unstable = 0,
    DataSync = 1,
    FileSync = 2,
}

impl StableHow {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Unstable),
            1 => Some(Self::DataSync),
            2 => Some(Self::FileSync),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RpcGssService {
    None = 1,
    Integrity = 2,
    Privacy = 3,
    /// RPCSEC_GSSv2 lower-layer channel protection (RFC 5403).
    ChannelProtection = 4,
}

impl RpcGssService {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::None),
            2 => Some(Self::Integrity),
            3 => Some(Self::Privacy),
            4 => Some(Self::ChannelProtection),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcSecGssInfo {
    pub oid: Vec<u8>,
    pub qop: u32,
    pub service: RpcGssService,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityInfo {
    RpcSecGss(RpcSecGssInfo),
    Other(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateType {
    Symlink(LinkText),
    Block(SpecData),
    Character(SpecData),
    Socket,
    Fifo,
    Directory,
    /// XDR's default void arm. Servers normally answer `NFS4ERR_BADTYPE`.
    Other(NfsFileType),
}

impl CreateType {
    pub const fn file_type(&self) -> NfsFileType {
        match self {
            Self::Symlink(_) => NfsFileType::Symlink,
            Self::Block(_) => NfsFileType::Block,
            Self::Character(_) => NfsFileType::Character,
            Self::Socket => NfsFileType::Socket,
            Self::Fifo => NfsFileType::Fifo,
            Self::Directory => NfsFileType::Directory,
            Self::Other(file_type) => *file_type,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessArgs {
    pub access: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseArgs {
    pub sequence_id: u32,
    pub open_state_id: StateId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitArgs {
    pub offset: u64,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateArgs {
    pub object_type: CreateType,
    pub name: Component,
    pub attributes: FileAttributes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegPurgeArgs {
    pub client_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegReturnArgs {
    pub delegation_state_id: StateId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAttrArgs {
    pub requested_attributes: Bitmap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkArgs {
    pub new_name: Component,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockArgs {
    pub lock_type: LockType,
    pub reclaim: bool,
    pub offset: u64,
    pub length: u64,
    pub locker: Locker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockTestArgs {
    pub lock_type: LockType,
    pub offset: u64,
    pub length: u64,
    pub owner: LockOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockUnlockArgs {
    pub lock_type: LockType,
    pub sequence_id: u32,
    pub lock_state_id: StateId,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupArgs {
    pub name: Component,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotVerifyArgs {
    pub attributes: FileAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenArgs {
    pub sequence_id: u32,
    pub share_access: u32,
    pub share_deny: u32,
    pub owner: OpenOwner,
    pub how: OpenHow,
    pub claim: OpenClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenAttrArgs {
    pub create_directory: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenConfirmArgs {
    pub open_state_id: StateId,
    pub sequence_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenDowngradeArgs {
    pub open_state_id: StateId,
    pub sequence_id: u32,
    pub share_access: u32,
    pub share_deny: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutFhArgs {
    pub object: NfsFileHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadArgs {
    pub state_id: StateId,
    pub offset: u64,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadDirArgs {
    pub cookie: u64,
    pub cookie_verifier: Verifier,
    pub directory_count: u32,
    pub max_count: u32,
    pub requested_attributes: Bitmap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoveArgs {
    pub target: Component,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameArgs {
    pub old_name: Component,
    pub new_name: Component,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewArgs {
    pub client_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecInfoArgs {
    pub name: Component,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetAttrArgs {
    pub state_id: StateId,
    pub attributes: FileAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetClientIdArgs {
    pub client: NfsClientId,
    pub callback: CallbackClient,
    pub callback_identifier: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetClientIdConfirmArgs {
    pub client_id: u64,
    pub confirmation: Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyArgs {
    pub attributes: FileAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteArgs {
    pub state_id: StateId,
    pub offset: u64,
    pub stability: StableHow,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseLockOwnerArgs {
    pub lock_owner: LockOwner,
}

/// One fully decoded `nfs_argop4` value.
///
/// Unknown operation numbers have no known payload and are retained in
/// `Illegal`, allowing the server to produce an `OP_ILLEGAL` result instead of
/// rejecting the entire RPC record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgOp {
    Access(AccessArgs),
    Close(CloseArgs),
    Commit(CommitArgs),
    Create(CreateArgs),
    DelegPurge(DelegPurgeArgs),
    DelegReturn(DelegReturnArgs),
    GetAttr(GetAttrArgs),
    GetFh,
    Link(LinkArgs),
    Lock(LockArgs),
    LockTest(LockTestArgs),
    LockUnlock(LockUnlockArgs),
    Lookup(LookupArgs),
    LookupParent,
    NotVerify(NotVerifyArgs),
    Open(OpenArgs),
    OpenAttr(OpenAttrArgs),
    OpenConfirm(OpenConfirmArgs),
    OpenDowngrade(OpenDowngradeArgs),
    PutFh(PutFhArgs),
    PutPublicFh,
    PutRootFh,
    Read(ReadArgs),
    ReadDir(ReadDirArgs),
    ReadLink,
    Remove(RemoveArgs),
    Rename(RenameArgs),
    Renew(RenewArgs),
    RestoreFh,
    SaveFh,
    SecInfo(SecInfoArgs),
    SetAttr(SetAttrArgs),
    SetClientId(SetClientIdArgs),
    SetClientIdConfirm(SetClientIdConfirmArgs),
    Verify(VerifyArgs),
    Write(WriteArgs),
    ReleaseLockOwner(ReleaseLockOwnerArgs),
    Illegal { requested_opcode: u32 },
}

impl ArgOp {
    pub const fn opcode(&self) -> u32 {
        match self {
            Self::Access(_) => OpNum::Access as u32,
            Self::Close(_) => OpNum::Close as u32,
            Self::Commit(_) => OpNum::Commit as u32,
            Self::Create(_) => OpNum::Create as u32,
            Self::DelegPurge(_) => OpNum::DelegPurge as u32,
            Self::DelegReturn(_) => OpNum::DelegReturn as u32,
            Self::GetAttr(_) => OpNum::GetAttr as u32,
            Self::GetFh => OpNum::GetFh as u32,
            Self::Link(_) => OpNum::Link as u32,
            Self::Lock(_) => OpNum::Lock as u32,
            Self::LockTest(_) => OpNum::LockTest as u32,
            Self::LockUnlock(_) => OpNum::LockUnlock as u32,
            Self::Lookup(_) => OpNum::Lookup as u32,
            Self::LookupParent => OpNum::LookupParent as u32,
            Self::NotVerify(_) => OpNum::NotVerify as u32,
            Self::Open(_) => OpNum::Open as u32,
            Self::OpenAttr(_) => OpNum::OpenAttr as u32,
            Self::OpenConfirm(_) => OpNum::OpenConfirm as u32,
            Self::OpenDowngrade(_) => OpNum::OpenDowngrade as u32,
            Self::PutFh(_) => OpNum::PutFh as u32,
            Self::PutPublicFh => OpNum::PutPublicFh as u32,
            Self::PutRootFh => OpNum::PutRootFh as u32,
            Self::Read(_) => OpNum::Read as u32,
            Self::ReadDir(_) => OpNum::ReadDir as u32,
            Self::ReadLink => OpNum::ReadLink as u32,
            Self::Remove(_) => OpNum::Remove as u32,
            Self::Rename(_) => OpNum::Rename as u32,
            Self::Renew(_) => OpNum::Renew as u32,
            Self::RestoreFh => OpNum::RestoreFh as u32,
            Self::SaveFh => OpNum::SaveFh as u32,
            Self::SecInfo(_) => OpNum::SecInfo as u32,
            Self::SetAttr(_) => OpNum::SetAttr as u32,
            Self::SetClientId(_) => OpNum::SetClientId as u32,
            Self::SetClientIdConfirm(_) => OpNum::SetClientIdConfirm as u32,
            Self::Verify(_) => OpNum::Verify as u32,
            Self::Write(_) => OpNum::Write as u32,
            Self::ReleaseLockOwner(_) => OpNum::ReleaseLockOwner as u32,
            Self::Illegal { requested_opcode } => *requested_opcode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompoundArgs {
    pub tag: Utf8String,
    pub minor_version: u32,
    pub operations: Vec<ArgOp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NfsResult<T> {
    Ok(T),
    Err(NfsStatus),
}

impl<T> NfsResult<T> {
    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::Ok(_) => NfsStatus::Ok,
            Self::Err(status) => *status,
        }
    }

    pub fn as_ref(&self) -> NfsResult<&T> {
        match self {
            Self::Ok(value) => NfsResult::Ok(value),
            Self::Err(status) => NfsResult::Err(*status),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessOk {
    pub supported: u32,
    pub access: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitOk {
    pub write_verifier: Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOk {
    pub change_info: ChangeInfo,
    pub attributes_set: Bitmap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkOk {
    pub change_info: ChangeInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockResult {
    Ok(StateId),
    Denied(LockDenied),
    Err(NfsStatus),
}

impl LockResult {
    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::Ok(_) => NfsStatus::Ok,
            Self::Denied(_) => NfsStatus::Denied,
            Self::Err(status) => *status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockTestResult {
    Ok,
    Denied(LockDenied),
    Err(NfsStatus),
}

impl LockTestResult {
    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::Ok => NfsStatus::Ok,
            Self::Denied(_) => NfsStatus::Denied,
            Self::Err(status) => *status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenOk {
    pub state_id: StateId,
    pub change_info: ChangeInfo,
    pub result_flags: u32,
    pub attributes_set: Bitmap,
    pub delegation: OpenDelegation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOk {
    pub eof: bool,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub cookie: u64,
    pub name: Component,
    pub attributes: FileAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadDirOk {
    pub cookie_verifier: Verifier,
    pub entries: Vec<DirectoryEntry>,
    pub eof: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadLinkOk {
    pub link: LinkText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoveOk {
    pub change_info: ChangeInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenameOk {
    pub source_change_info: ChangeInfo,
    pub target_change_info: ChangeInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetAttrResult {
    pub status: NfsStatus,
    pub attributes_set: Bitmap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetClientIdOk {
    pub client_id: u64,
    pub confirmation: Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetClientIdResult {
    Ok(SetClientIdOk),
    ClientIdInUse(ClientAddress),
    Err(NfsStatus),
}

impl SetClientIdResult {
    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::Ok(_) => NfsStatus::Ok,
            Self::ClientIdInUse(_) => NfsStatus::ClientIdInUse,
            Self::Err(status) => *status,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteOk {
    pub count: u32,
    pub committed: StableHow,
    pub write_verifier: Verifier,
}

/// One `nfs_resop4` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResOp {
    Access(NfsResult<AccessOk>),
    Close(NfsResult<StateId>),
    Commit(NfsResult<CommitOk>),
    Create(NfsResult<CreateOk>),
    DelegPurge(NfsStatus),
    DelegReturn(NfsStatus),
    GetAttr(NfsResult<FileAttributes>),
    GetFh(NfsResult<NfsFileHandle>),
    Link(NfsResult<LinkOk>),
    Lock(LockResult),
    LockTest(LockTestResult),
    LockUnlock(NfsResult<StateId>),
    Lookup(NfsStatus),
    LookupParent(NfsStatus),
    NotVerify(NfsStatus),
    Open(NfsResult<OpenOk>),
    OpenAttr(NfsStatus),
    OpenConfirm(NfsResult<StateId>),
    OpenDowngrade(NfsResult<StateId>),
    PutFh(NfsStatus),
    PutPublicFh(NfsStatus),
    PutRootFh(NfsStatus),
    Read(NfsResult<ReadOk>),
    ReadDir(NfsResult<ReadDirOk>),
    ReadLink(NfsResult<ReadLinkOk>),
    Remove(NfsResult<RemoveOk>),
    Rename(NfsResult<RenameOk>),
    Renew(NfsStatus),
    RestoreFh(NfsStatus),
    SaveFh(NfsStatus),
    SecInfo(NfsResult<Vec<SecurityInfo>>),
    SetAttr(SetAttrResult),
    SetClientId(SetClientIdResult),
    SetClientIdConfirm(NfsStatus),
    Verify(NfsStatus),
    Write(NfsResult<WriteOk>),
    ReleaseLockOwner(NfsStatus),
    Illegal(NfsStatus),
}

impl ResOp {
    pub const fn opnum(&self) -> OpNum {
        match self {
            Self::Access(_) => OpNum::Access,
            Self::Close(_) => OpNum::Close,
            Self::Commit(_) => OpNum::Commit,
            Self::Create(_) => OpNum::Create,
            Self::DelegPurge(_) => OpNum::DelegPurge,
            Self::DelegReturn(_) => OpNum::DelegReturn,
            Self::GetAttr(_) => OpNum::GetAttr,
            Self::GetFh(_) => OpNum::GetFh,
            Self::Link(_) => OpNum::Link,
            Self::Lock(_) => OpNum::Lock,
            Self::LockTest(_) => OpNum::LockTest,
            Self::LockUnlock(_) => OpNum::LockUnlock,
            Self::Lookup(_) => OpNum::Lookup,
            Self::LookupParent(_) => OpNum::LookupParent,
            Self::NotVerify(_) => OpNum::NotVerify,
            Self::Open(_) => OpNum::Open,
            Self::OpenAttr(_) => OpNum::OpenAttr,
            Self::OpenConfirm(_) => OpNum::OpenConfirm,
            Self::OpenDowngrade(_) => OpNum::OpenDowngrade,
            Self::PutFh(_) => OpNum::PutFh,
            Self::PutPublicFh(_) => OpNum::PutPublicFh,
            Self::PutRootFh(_) => OpNum::PutRootFh,
            Self::Read(_) => OpNum::Read,
            Self::ReadDir(_) => OpNum::ReadDir,
            Self::ReadLink(_) => OpNum::ReadLink,
            Self::Remove(_) => OpNum::Remove,
            Self::Rename(_) => OpNum::Rename,
            Self::Renew(_) => OpNum::Renew,
            Self::RestoreFh(_) => OpNum::RestoreFh,
            Self::SaveFh(_) => OpNum::SaveFh,
            Self::SecInfo(_) => OpNum::SecInfo,
            Self::SetAttr(_) => OpNum::SetAttr,
            Self::SetClientId(_) => OpNum::SetClientId,
            Self::SetClientIdConfirm(_) => OpNum::SetClientIdConfirm,
            Self::Verify(_) => OpNum::Verify,
            Self::Write(_) => OpNum::Write,
            Self::ReleaseLockOwner(_) => OpNum::ReleaseLockOwner,
            Self::Illegal(_) => OpNum::Illegal,
        }
    }

    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::Access(result) => result.status(),
            Self::Close(result) => result.status(),
            Self::Commit(result) => result.status(),
            Self::Create(result) => result.status(),
            Self::DelegPurge(status) => *status,
            Self::DelegReturn(status) => *status,
            Self::GetAttr(result) => result.status(),
            Self::GetFh(result) => result.status(),
            Self::Link(result) => result.status(),
            Self::Lock(result) => result.status(),
            Self::LockTest(result) => result.status(),
            Self::LockUnlock(result) => result.status(),
            Self::Lookup(status) => *status,
            Self::LookupParent(status) => *status,
            Self::NotVerify(status) => *status,
            Self::Open(result) => result.status(),
            Self::OpenAttr(status) => *status,
            Self::OpenConfirm(result) => result.status(),
            Self::OpenDowngrade(result) => result.status(),
            Self::PutFh(status) => *status,
            Self::PutPublicFh(status) => *status,
            Self::PutRootFh(status) => *status,
            Self::Read(result) => result.status(),
            Self::ReadDir(result) => result.status(),
            Self::ReadLink(result) => result.status(),
            Self::Remove(result) => result.status(),
            Self::Rename(result) => result.status(),
            Self::Renew(status) => *status,
            Self::RestoreFh(status) => *status,
            Self::SaveFh(status) => *status,
            Self::SecInfo(result) => result.status(),
            Self::SetAttr(result) => result.status,
            Self::SetClientId(result) => result.status(),
            Self::SetClientIdConfirm(status) => *status,
            Self::Verify(status) => *status,
            Self::Write(result) => result.status(),
            Self::ReleaseLockOwner(status) => *status,
            Self::Illegal(status) => *status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompoundRes {
    pub status: NfsStatus,
    pub tag: Utf8String,
    pub operations: Vec<ResOp>,
}

impl CompoundRes {
    /// Builds a result whose top-level status follows RFC 7530 section 15.2:
    /// it is the final operation status, or `NFS4_OK` for an empty result.
    pub fn from_operations(tag: Utf8String, operations: Vec<ResOp>) -> Self {
        let status = operations.last().map_or(NfsStatus::Ok, ResOp::status);
        Self {
            status,
            tag,
            operations,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackGetAttrArgs {
    pub file_handle: NfsFileHandle,
    pub requested_attributes: Bitmap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackRecallArgs {
    pub state_id: StateId,
    pub truncate: bool,
    pub file_handle: NfsFileHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallbackArgOp {
    GetAttr(CallbackGetAttrArgs),
    Recall(CallbackRecallArgs),
    Illegal { requested_opcode: u32 },
}

impl CallbackArgOp {
    pub const fn opcode(&self) -> u32 {
        match self {
            Self::GetAttr(_) => CallbackOpNum::GetAttr as u32,
            Self::Recall(_) => CallbackOpNum::Recall as u32,
            Self::Illegal { requested_opcode } => *requested_opcode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackCompoundArgs {
    pub tag: Utf8String,
    pub minor_version: u32,
    pub callback_identifier: u32,
    pub operations: Vec<CallbackArgOp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallbackResOp {
    GetAttr(NfsResult<FileAttributes>),
    Recall(NfsStatus),
    Illegal(NfsStatus),
}

impl CallbackResOp {
    pub const fn opnum(&self) -> CallbackOpNum {
        match self {
            Self::GetAttr(_) => CallbackOpNum::GetAttr,
            Self::Recall(_) => CallbackOpNum::Recall,
            Self::Illegal(_) => CallbackOpNum::Illegal,
        }
    }

    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::GetAttr(result) => result.status(),
            Self::Recall(status) | Self::Illegal(status) => *status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackCompoundRes {
    pub status: NfsStatus,
    pub tag: Utf8String,
    pub operations: Vec<CallbackResOp>,
}

impl CallbackCompoundRes {
    pub fn from_operations(tag: Utf8String, operations: Vec<CallbackResOp>) -> Self {
        let status = operations.last().map_or(NfsStatus::Ok, CallbackResOp::status);
        Self {
            status,
            tag,
            operations,
        }
    }
}
