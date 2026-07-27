use std::fmt;

use bytes::Bytes;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObjectKey {
    pub file_id: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NfsName(Vec<u8>);

impl NfsName {
    pub const MAX_LEN: usize = 255;

    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, NfsError> {
        let value = value.into();
        if value.len() > Self::MAX_LEN {
            return Err(NfsError::NameTooLong);
        }
        if value.is_empty() || value.contains(&b'/') || value.contains(&0) {
            return Err(NfsError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the name and returns its validated storage without copying.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for NfsName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    BlockDevice,
    CharacterDevice,
    Symlink,
    Socket,
    Fifo,
    /// The virtual directory returned by NFSv4 OPENATTR.
    AttributeDirectory,
    /// A byte-stream object stored in an NFSv4 named-attribute directory.
    NamedAttribute,
}

impl FileType {
    /// Whether NFSv4 defines this object as a directory.
    pub const fn is_directory(self) -> bool {
        matches!(self, Self::Directory | Self::AttributeDirectory)
    }

    /// Whether NFSv4 defines this object as a regular byte-stream file.
    pub const fn is_regular(self) -> bool {
        matches!(self, Self::Regular | Self::NamedAttribute)
    }

    /// Whether this object belongs to the NFSv4 named-attribute namespace.
    pub const fn is_named_attribute(self) -> bool {
        matches!(self, Self::AttributeDirectory | Self::NamedAttribute)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceNumber {
    pub major: u32,
    pub minor: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NfsTime {
    /// Seconds relative to the Unix epoch.
    ///
    /// NFSv4 uses a signed 64-bit value here. NFSv3 only has an unsigned
    /// 32-bit seconds field; the v3 encoder rejects values outside that wire
    /// range.
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// An authoritative, monotonically changing value for one filesystem object.
///
/// Backends may use an inode generation, metadata transaction number, or
/// another opaque value. The server compares change IDs for equality and does
/// not assign ordering semantics to them.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChangeId(pub u64);

impl From<u64> for ChangeId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ChangeId> for u64 {
    fn from(value: ChangeId) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAttributes {
    pub file_type: FileType,
    pub mode: u32,
    pub links: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    /// Device identity for block and character nodes. Ignored for other
    /// object types.
    pub device: Option<DeviceNumber>,
    pub fs_id: u64,
    pub file_id: u64,
    /// Authoritative value for the NFSv4 `change` attribute.
    pub change_id: ChangeId,
    pub access_time: NfsTime,
    pub modify_time: NfsTime,
    pub change_time: NfsTime,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SetAttributes {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub access_time: Option<SetTime>,
    pub modify_time: Option<SetTime>,
    /// Canonical NFSv4 ACL to apply atomically with mode inheritance and
    /// synchronization. NFSv3 decoders always leave this unset.
    pub acl: Option<Nfs4Acl>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetTime {
    ServerTime,
    ClientTime(NfsTime),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Nfs4AceType {
    Allow,
    Deny,
    Audit,
    Alarm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nfs4Ace {
    pub ace_type: Nfs4AceType,
    pub flags: u32,
    pub mask: u32,
    pub who: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Nfs4Acl {
    pub entries: Vec<Nfs4Ace>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WccAttributes {
    pub size: u64,
    /// Authoritative value captured with the weak-cache-consistency data.
    pub change_id: ChangeId,
    pub modify_time: NfsTime,
    pub change_time: NfsTime,
}

/// Before/after change values returned by directory-modifying NFSv4
/// operations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChangeInfo {
    pub atomic: bool,
    pub before: ChangeId,
    pub after: ChangeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult<T> {
    pub value: T,
    /// Protocol-neutral change information for the object whose namespace
    /// was modified. NFSv4 namespace operations require this field; it is
    /// deliberately independent of the optional NFSv3 WCC snapshots below.
    pub change_info: Option<ChangeInfo>,
    /// Optional NFSv3 weak-cache-consistency state captured before the
    /// mutation.
    pub before: Option<WccAttributes>,
    /// Optional NFSv3 weak-cache-consistency state captured after the
    /// mutation.
    pub after: Option<FileAttributes>,
}

impl<T> MutationResult<T> {
    /// Constructs a result without protocol-specific cache-consistency
    /// metadata.
    pub fn without_metadata(value: T) -> Self {
        Self {
            value,
            change_info: None,
            before: None,
            after: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateMode {
    Unchecked,
    Guarded,
    Exclusive { verifier: [u8; 8] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedObject {
    pub object: ObjectKey,
    pub attributes: Option<FileAttributes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteStability {
    Unstable,
    DataSync,
    FileSync,
}

impl WriteStability {
    /// Returns whether this achieved durability satisfies `requested`.
    pub const fn satisfies(self, requested: Self) -> bool {
        use WriteStability::{DataSync, FileSync, Unstable};
        matches!((self, requested), (FileSync, _) | (DataSync, DataSync | Unstable) | (Unstable, Unstable))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteResult {
    pub count: u32,
    pub committed: WriteStability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub eof: bool,
    pub attributes: Option<FileAttributes>,
}

/// A read result whose payload can share storage with a backend cache, mmap,
/// or other immutable byte owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadBytesResult {
    pub data: Bytes,
    pub eof: bool,
    pub attributes: Option<FileAttributes>,
}

impl From<ReadResult> for ReadBytesResult {
    fn from(result: ReadResult) -> Self {
        Self {
            data: Bytes::from(result.data),
            eof: result.eof,
            attributes: result.attributes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub object: ObjectKey,
    pub file_id: u64,
    pub name: NfsName,
    pub cookie: u64,
    pub attributes: Option<FileAttributes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadDirectoryPage {
    pub verifier: [u8; 8],
    pub entries: Vec<DirectoryEntry>,
    pub eof: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub available_files: u64,
    pub invariant_seconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsInfo {
    pub max_read: u32,
    pub preferred_read: u32,
    pub read_multiple: u32,
    pub max_write: u32,
    pub preferred_write: u32,
    pub write_multiple: u32,
    pub preferred_readdir: u32,
    pub max_file_size: u64,
    pub time_granularity: NfsTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathConf {
    pub max_links: u32,
    pub max_name_length: u32,
    pub no_truncation: bool,
    pub chown_restricted: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeType {
    BlockDevice { major: u32, minor: u32 },
    CharacterDevice { major: u32, minor: u32 },
    Socket,
    Fifo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NfsError {
    #[error("operation not permitted")]
    Permission,
    #[error("object does not exist")]
    NotFound,
    #[error("I/O error")]
    Io,
    #[error("no such device or address")]
    NoDeviceOrAddress,
    #[error("permission denied")]
    Access,
    #[error("object already exists")]
    Exists,
    #[error("cross-device operation")]
    CrossDevice,
    #[error("no such device")]
    NoDevice,
    #[error("not a directory")]
    NotDirectory,
    #[error("is a directory")]
    IsDirectory,
    #[error("invalid argument")]
    Invalid,
    #[error("file is too large")]
    FileTooLarge,
    #[error("filesystem has no free space")]
    NoSpace,
    #[error("read-only filesystem")]
    ReadOnly,
    #[error("too many links")]
    TooManyLinks,
    #[error("name is too long")]
    NameTooLong,
    #[error("directory not empty")]
    NotEmpty,
    #[error("quota exceeded")]
    Quota,
    #[error("stale object")]
    Stale,
    #[error("object is remote")]
    Remote,
    #[error("object was not synchronized")]
    NotSynchronized,
    #[error("stale directory cookie")]
    BadCookie,
    #[error("operation is not supported")]
    NotSupported,
    #[error("response buffer is too small")]
    TooSmall,
    #[error("server failure")]
    ServerFault,
    #[error("object has the wrong type")]
    BadType,
    #[error("request should be retried later")]
    Jukebox,
}

impl fmt::Display for NfsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_read_result_converts_to_bytes_without_copying() {
        let data = vec![0x44; 1024];
        let pointer = data.as_ptr();
        let result = ReadBytesResult::from(ReadResult {
            data,
            eof: true,
            attributes: None,
        });
        assert_eq!(result.data.as_ptr(), pointer);
    }

    #[test]
    fn write_stability_orders_achieved_durability() {
        assert!(WriteStability::Unstable.satisfies(WriteStability::Unstable));
        assert!(!WriteStability::Unstable.satisfies(WriteStability::DataSync));
        assert!(!WriteStability::DataSync.satisfies(WriteStability::FileSync));
        assert!(WriteStability::DataSync.satisfies(WriteStability::Unstable));
        assert!(WriteStability::FileSync.satisfies(WriteStability::DataSync));
        assert!(WriteStability::FileSync.satisfies(WriteStability::FileSync));
    }
}
