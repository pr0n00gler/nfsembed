pub const PROGRAM: u32 = 100_005;
pub const VERSION: u32 = 3;
pub const MAX_PATH: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MountStatus {
    Ok = 0,
    Permission = 1,
    NotFound = 2,
    Io = 5,
    Access = 13,
    NotDirectory = 20,
    Invalid = 22,
    NameTooLong = 63,
    NotSupported = 10004,
    ServerFault = 10006,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MountResult {
    Ok {
        file_handle: Vec<u8>,
        auth_flavors: Vec<u32>,
    },
    Err(MountStatus),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEntry {
    pub host: Vec<u8>,
    pub path: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DumpResult {
    pub mounts: Vec<MountEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportEntry {
    pub path: Vec<u8>,
    pub groups: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExportResult {
    pub exports: Vec<ExportEntry>,
}
