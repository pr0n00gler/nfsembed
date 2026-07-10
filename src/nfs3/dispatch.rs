#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Procedure {
    Null = 0,
    GetAttr = 1,
    SetAttr = 2,
    Lookup = 3,
    Access = 4,
    ReadLink = 5,
    Read = 6,
    Write = 7,
    Create = 8,
    Mkdir = 9,
    Symlink = 10,
    Mknod = 11,
    Remove = 12,
    Rmdir = 13,
    Rename = 14,
    Link = 15,
    ReadDir = 16,
    ReadDirPlus = 17,
    FsStat = 18,
    FsInfo = 19,
    PathConf = 20,
    Commit = 21,
}

impl Procedure {
    pub fn from_wire(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Null,
            1 => Self::GetAttr,
            2 => Self::SetAttr,
            3 => Self::Lookup,
            4 => Self::Access,
            5 => Self::ReadLink,
            6 => Self::Read,
            7 => Self::Write,
            8 => Self::Create,
            9 => Self::Mkdir,
            10 => Self::Symlink,
            11 => Self::Mknod,
            12 => Self::Remove,
            13 => Self::Rmdir,
            14 => Self::Rename,
            15 => Self::Link,
            16 => Self::ReadDir,
            17 => Self::ReadDirPlus,
            18 => Self::FsStat,
            19 => Self::FsInfo,
            20 => Self::PathConf,
            21 => Self::Commit,
            _ => return None,
        })
    }
}
