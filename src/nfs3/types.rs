//! Strongly typed backend-facing NFSv3 values.

pub use crate::vfs::{
    CreateMode, CreatedObject, DirectoryEntry, FileAttributes, FileType, FsInfo, FsStat, MutationResult, NfsError,
    NfsName, NfsTime, NodeType, ObjectKey, PathConf, ReadDirectoryPage, ReadResult, SetAttributes, SetTime,
    WccAttributes, WriteResult, WriteStability,
};

pub const PROGRAM: u32 = 100_003;
pub const VERSION: u32 = 3;
pub const PROCEDURE_COUNT: u32 = 22;

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
    NoDevice = 19,
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
    Remote = 71,
    BadHandle = 10001,
    NotSynchronized = 10002,
    BadCookie = 10003,
    NotSupported = 10004,
    TooSmall = 10005,
    ServerFault = 10006,
    BadType = 10007,
    Jukebox = 10008,
}

impl NfsStatus {
    pub fn from_code(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Ok,
            1 => Self::Permission,
            2 => Self::NotFound,
            5 => Self::Io,
            6 => Self::NoDeviceOrAddress,
            13 => Self::Access,
            17 => Self::Exists,
            18 => Self::CrossDevice,
            19 => Self::NoDevice,
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
            71 => Self::Remote,
            10001 => Self::BadHandle,
            10002 => Self::NotSynchronized,
            10003 => Self::BadCookie,
            10004 => Self::NotSupported,
            10005 => Self::TooSmall,
            10006 => Self::ServerFault,
            10007 => Self::BadType,
            10008 => Self::Jukebox,
            _ => return None,
        })
    }
}

impl From<NfsError> for NfsStatus {
    fn from(error: NfsError) -> Self {
        match error {
            NfsError::Permission => Self::Permission,
            NfsError::NotFound => Self::NotFound,
            NfsError::Io => Self::Io,
            NfsError::NoDeviceOrAddress => Self::NoDeviceOrAddress,
            NfsError::Access => Self::Access,
            NfsError::Exists => Self::Exists,
            NfsError::CrossDevice => Self::CrossDevice,
            NfsError::NoDevice => Self::NoDevice,
            NfsError::NotDirectory => Self::NotDirectory,
            NfsError::IsDirectory => Self::IsDirectory,
            NfsError::Invalid => Self::Invalid,
            NfsError::FileTooLarge => Self::FileTooLarge,
            NfsError::NoSpace => Self::NoSpace,
            NfsError::ReadOnly => Self::ReadOnly,
            NfsError::TooManyLinks => Self::TooManyLinks,
            NfsError::NameTooLong => Self::NameTooLong,
            NfsError::NotEmpty => Self::NotEmpty,
            NfsError::Quota => Self::Quota,
            NfsError::Stale => Self::Stale,
            NfsError::Remote => Self::Remote,
            NfsError::NotSynchronized => Self::NotSynchronized,
            NfsError::BadCookie => Self::BadCookie,
            NfsError::NotSupported => Self::NotSupported,
            NfsError::TooSmall => Self::TooSmall,
            NfsError::ServerFault => Self::ServerFault,
            NfsError::BadType => Self::BadType,
            NfsError::Jukebox => Self::Jukebox,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_backend_error_maps_to_its_exact_wire_status() {
        for (error, status) in [
            (NfsError::Permission, NfsStatus::Permission),
            (NfsError::NotFound, NfsStatus::NotFound),
            (NfsError::Io, NfsStatus::Io),
            (NfsError::NoDeviceOrAddress, NfsStatus::NoDeviceOrAddress),
            (NfsError::Access, NfsStatus::Access),
            (NfsError::Exists, NfsStatus::Exists),
            (NfsError::CrossDevice, NfsStatus::CrossDevice),
            (NfsError::NoDevice, NfsStatus::NoDevice),
            (NfsError::NotDirectory, NfsStatus::NotDirectory),
            (NfsError::IsDirectory, NfsStatus::IsDirectory),
            (NfsError::Invalid, NfsStatus::Invalid),
            (NfsError::FileTooLarge, NfsStatus::FileTooLarge),
            (NfsError::NoSpace, NfsStatus::NoSpace),
            (NfsError::ReadOnly, NfsStatus::ReadOnly),
            (NfsError::TooManyLinks, NfsStatus::TooManyLinks),
            (NfsError::NameTooLong, NfsStatus::NameTooLong),
            (NfsError::NotEmpty, NfsStatus::NotEmpty),
            (NfsError::Quota, NfsStatus::Quota),
            (NfsError::Stale, NfsStatus::Stale),
            (NfsError::Remote, NfsStatus::Remote),
            (NfsError::NotSynchronized, NfsStatus::NotSynchronized),
            (NfsError::BadCookie, NfsStatus::BadCookie),
            (NfsError::NotSupported, NfsStatus::NotSupported),
            (NfsError::TooSmall, NfsStatus::TooSmall),
            (NfsError::ServerFault, NfsStatus::ServerFault),
            (NfsError::BadType, NfsStatus::BadType),
            (NfsError::Jukebox, NfsStatus::Jukebox),
        ] {
            assert_eq!(NfsStatus::from(error), status);
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WccData {
    pub before: Option<WccAttributes>,
    pub after: Option<FileAttributes>,
}
