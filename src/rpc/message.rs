#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallHeader {
    pub xid: u32,
    pub rpc_version: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AcceptStatus {
    Success = 0,
    ProgramUnavailable = 1,
    ProgramMismatch = 2,
    ProcedureUnavailable = 3,
    GarbageArguments = 4,
    SystemError = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRange {
    pub low: u32,
    pub high: u32,
}

impl VersionRange {
    pub fn exact(version: u32) -> Self {
        Self {
            low: version,
            high: version,
        }
    }
}
