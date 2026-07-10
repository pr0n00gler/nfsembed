use std::fmt;

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
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceNumber {
    pub major: u32,
    pub minor: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NfsTime {
    pub seconds: u64,
    pub nanoseconds: u32,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetTime {
    ServerTime,
    ClientTime(NfsTime),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WccAttributes {
    pub size: u64,
    pub modify_time: NfsTime,
    pub change_time: NfsTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult<T> {
    pub value: T,
    pub before: Option<WccAttributes>,
    pub after: Option<FileAttributes>,
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
