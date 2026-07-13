//! Complete procedure arguments and result unions. Every request is decoded
//! and finished as one typed value before semantic handle/name validation,
//! and every result is constructed before it is encoded.

use bytes::Bytes;

use crate::nfs3::types::{FileAttributes, FsInfo, FsStat, NfsStatus, PathConf, WccData, WriteStability};
use crate::rpc::codec::{DecodeError, Decoder};
use crate::vfs::{CreateMode, NfsTime, NodeType, SetAttributes, SetTime};

pub type FileHandle = Vec<u8>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectArgs {
    pub object: FileHandle,
}

pub type GetAttrArgs = ObjectArgs;
pub type ReadLinkArgs = ObjectArgs;
pub type FsStatArgs = ObjectArgs;
pub type FsInfoArgs = ObjectArgs;
pub type PathConfArgs = ObjectArgs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryOperationArgs {
    pub directory: FileHandle,
    pub name: Vec<u8>,
}

pub type LookupArgs = DirectoryOperationArgs;
pub type RemoveArgs = DirectoryOperationArgs;
pub type RmdirArgs = DirectoryOperationArgs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetAttrArgs {
    pub object: FileHandle,
    pub attributes: SetAttributes,
    pub guard: Option<NfsTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessArgs {
    pub object: FileHandle,
    pub requested: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadArgs {
    pub object: FileHandle,
    pub offset: u64,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteArgs {
    pub object: FileHandle,
    pub offset: u64,
    pub count: u32,
    pub requested: WriteStability,
    pub data: Vec<u8>,
}

impl WriteArgs {
    pub fn validate(&self) -> Result<(), NfsStatus> {
        validate_write_count(self.count, self.data.len())
    }
}

/// Server-oriented WRITE arguments whose data is a zero-copy slice of the
/// retained RPC record. `WriteArgs` remains available for callers decoding
/// from a borrowed byte slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteRequest {
    pub object: FileHandle,
    pub offset: u64,
    pub count: u32,
    pub requested: WriteStability,
    pub data: Bytes,
}

impl WriteRequest {
    pub fn decode(input: Bytes, max_variable_size: usize) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(&input);
        let object = decode_handle(&mut decoder)?;
        let offset = decoder.read_u64()?;
        let count = decoder.read_u32()?;
        let requested = decode_stability(&mut decoder)?;
        let data_prefix = decoder.position();
        let data_len = decoder.read_opaque_slice("WRITE data", max_variable_size)?.len();
        decoder.finish()?;
        // `read_opaque_slice` validates the length, padding, and trailing
        // bytes. Reconstructing that validated range as a `Bytes` slice keeps
        // the RPC record alive across the asynchronous VFS call without a
        // payload copy.
        let data_start = data_prefix.checked_add(4).ok_or(DecodeError::Overflow)?;
        let data_end = data_start.checked_add(data_len).ok_or(DecodeError::Overflow)?;
        Ok(Self {
            object,
            offset,
            count,
            requested,
            data: input.slice(data_start..data_end),
        })
    }

    pub fn validate(&self) -> Result<(), NfsStatus> {
        validate_write_count(self.count, self.data.len())
    }
}

impl From<WriteArgs> for WriteRequest {
    fn from(arguments: WriteArgs) -> Self {
        Self {
            object: arguments.object,
            offset: arguments.offset,
            count: arguments.count,
            requested: arguments.requested,
            data: Bytes::from(arguments.data),
        }
    }
}

fn validate_write_count(count: u32, data_len: usize) -> Result<(), NfsStatus> {
    if usize::try_from(count).ok() != Some(data_len) {
        Err(NfsStatus::Invalid)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateArgs {
    pub target: DirectoryOperationArgs,
    pub mode: CreateMode,
    pub attributes: SetAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MkdirArgs {
    pub target: DirectoryOperationArgs,
    pub attributes: SetAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkArgs {
    pub target: DirectoryOperationArgs,
    pub attributes: SetAttributes,
    pub path: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MknodArgs {
    pub target: DirectoryOperationArgs,
    pub node_type: NodeType,
    pub attributes: SetAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameArgs {
    pub from: DirectoryOperationArgs,
    pub to: DirectoryOperationArgs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkArgs {
    pub object: FileHandle,
    pub target: DirectoryOperationArgs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadDirArgs {
    pub directory: FileHandle,
    pub cookie: u64,
    pub verifier: [u8; 8],
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadDirPlusArgs {
    pub directory: FileHandle,
    pub cookie: u64,
    pub verifier: [u8; 8],
    pub directory_count: u32,
    pub max_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitArgs {
    pub object: FileHandle,
    pub offset: u64,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NfsArguments {
    Null,
    GetAttr(GetAttrArgs),
    SetAttr(SetAttrArgs),
    Lookup(LookupArgs),
    Access(AccessArgs),
    ReadLink(ReadLinkArgs),
    Read(ReadArgs),
    Write(WriteArgs),
    Create(CreateArgs),
    Mkdir(MkdirArgs),
    Symlink(SymlinkArgs),
    Mknod(MknodArgs),
    Remove(RemoveArgs),
    Rmdir(RmdirArgs),
    Rename(RenameArgs),
    Link(LinkArgs),
    ReadDir(ReadDirArgs),
    ReadDirPlus(ReadDirPlusArgs),
    FsStat(FsStatArgs),
    FsInfo(FsInfoArgs),
    PathConf(PathConfArgs),
    Commit(CommitArgs),
}

impl NfsArguments {
    pub fn decode(procedure: u32, input: &[u8], max_variable_size: usize) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let arguments = match procedure {
            0 => Self::Null,
            1 => Self::GetAttr(decode_object_args(&mut decoder)?),
            2 => Self::SetAttr(SetAttrArgs {
                object: decode_handle(&mut decoder)?,
                attributes: decode_set_attributes(&mut decoder)?,
                guard: decoder.read_bool()?.then(|| decode_time(&mut decoder)).transpose()?,
            }),
            3 => Self::Lookup(decode_directory_operation(&mut decoder)?),
            4 => Self::Access(AccessArgs {
                object: decode_handle(&mut decoder)?,
                requested: decoder.read_u32()?,
            }),
            5 => Self::ReadLink(decode_object_args(&mut decoder)?),
            6 => Self::Read(ReadArgs {
                object: decode_handle(&mut decoder)?,
                offset: decoder.read_u64()?,
                count: decoder.read_u32()?,
            }),
            7 => Self::Write(WriteArgs {
                object: decode_handle(&mut decoder)?,
                offset: decoder.read_u64()?,
                count: decoder.read_u32()?,
                requested: decode_stability(&mut decoder)?,
                data: decoder.read_opaque("WRITE data", max_variable_size)?,
            }),
            8 => {
                let target = decode_directory_operation(&mut decoder)?;
                let mode = match decoder.read_u32()? {
                    0 => CreateMode::Unchecked,
                    1 => CreateMode::Guarded,
                    2 => CreateMode::Exclusive {
                        verifier: decoder.read_fixed()?,
                    },
                    value => {
                        return Err(DecodeError::InvalidDiscriminant {
                            kind: "CREATE mode",
                            value,
                        })
                    },
                };
                let attributes = if matches!(mode, CreateMode::Exclusive { .. }) {
                    SetAttributes::default()
                } else {
                    decode_set_attributes(&mut decoder)?
                };
                Self::Create(CreateArgs {
                    target,
                    mode,
                    attributes,
                })
            },
            9 => Self::Mkdir(MkdirArgs {
                target: decode_directory_operation(&mut decoder)?,
                attributes: decode_set_attributes(&mut decoder)?,
            }),
            10 => Self::Symlink(SymlinkArgs {
                target: decode_directory_operation(&mut decoder)?,
                attributes: decode_set_attributes(&mut decoder)?,
                path: decoder.read_string("symlink target", max_variable_size)?,
            }),
            11 => {
                let target = decode_directory_operation(&mut decoder)?;
                let kind = decoder.read_u32()?;
                let attributes = decode_set_attributes(&mut decoder)?;
                let node_type = match kind {
                    3 => NodeType::BlockDevice {
                        major: decoder.read_u32()?,
                        minor: decoder.read_u32()?,
                    },
                    4 => NodeType::CharacterDevice {
                        major: decoder.read_u32()?,
                        minor: decoder.read_u32()?,
                    },
                    6 => NodeType::Socket,
                    7 => NodeType::Fifo,
                    value => {
                        return Err(DecodeError::InvalidDiscriminant {
                            kind: "MKNOD type",
                            value,
                        })
                    },
                };
                Self::Mknod(MknodArgs {
                    target,
                    node_type,
                    attributes,
                })
            },
            12 => Self::Remove(decode_directory_operation(&mut decoder)?),
            13 => Self::Rmdir(decode_directory_operation(&mut decoder)?),
            14 => Self::Rename(RenameArgs {
                from: decode_directory_operation(&mut decoder)?,
                to: decode_directory_operation(&mut decoder)?,
            }),
            15 => Self::Link(LinkArgs {
                object: decode_handle(&mut decoder)?,
                target: decode_directory_operation(&mut decoder)?,
            }),
            16 => Self::ReadDir(ReadDirArgs {
                directory: decode_handle(&mut decoder)?,
                cookie: decoder.read_u64()?,
                verifier: decoder.read_fixed()?,
                count: decoder.read_u32()?,
            }),
            17 => Self::ReadDirPlus(ReadDirPlusArgs {
                directory: decode_handle(&mut decoder)?,
                cookie: decoder.read_u64()?,
                verifier: decoder.read_fixed()?,
                directory_count: decoder.read_u32()?,
                max_count: decoder.read_u32()?,
            }),
            18 => Self::FsStat(decode_object_args(&mut decoder)?),
            19 => Self::FsInfo(decode_object_args(&mut decoder)?),
            20 => Self::PathConf(decode_object_args(&mut decoder)?),
            21 => Self::Commit(CommitArgs {
                object: decode_handle(&mut decoder)?,
                offset: decoder.read_u64()?,
                count: decoder.read_u32()?,
            }),
            value => {
                return Err(DecodeError::InvalidDiscriminant {
                    kind: "NFS procedure",
                    value,
                })
            },
        };
        decoder.finish()?;
        Ok(arguments)
    }
}

fn decode_handle(decoder: &mut Decoder<'_>) -> Result<FileHandle, DecodeError> {
    decoder.read_opaque("NFS file handle", 64)
}

fn decode_object_args(decoder: &mut Decoder<'_>) -> Result<ObjectArgs, DecodeError> {
    Ok(ObjectArgs {
        object: decode_handle(decoder)?,
    })
}

fn decode_directory_operation(decoder: &mut Decoder<'_>) -> Result<DirectoryOperationArgs, DecodeError> {
    Ok(DirectoryOperationArgs {
        directory: decode_handle(decoder)?,
        // Length and component semantics are reported as NFS errors after the
        // complete argument value has been decoded.
        name: decoder.read_string("NFS filename", 1024)?,
    })
}

fn decode_time(decoder: &mut Decoder<'_>) -> Result<NfsTime, DecodeError> {
    let seconds = u64::from(decoder.read_u32()?);
    let nanoseconds = decoder.read_u32()?;
    if nanoseconds > 999_999_999 {
        return Err(DecodeError::InvalidDiscriminant {
            kind: "nanoseconds",
            value: nanoseconds,
        });
    }
    Ok(NfsTime { seconds, nanoseconds })
}

fn decode_set_attributes(decoder: &mut Decoder<'_>) -> Result<SetAttributes, DecodeError> {
    Ok(SetAttributes {
        mode: decoder.read_bool()?.then(|| decoder.read_u32()).transpose()?,
        uid: decoder.read_bool()?.then(|| decoder.read_u32()).transpose()?,
        gid: decoder.read_bool()?.then(|| decoder.read_u32()).transpose()?,
        size: decoder.read_bool()?.then(|| decoder.read_u64()).transpose()?,
        access_time: decode_set_time(decoder)?,
        modify_time: decode_set_time(decoder)?,
    })
}

fn decode_set_time(decoder: &mut Decoder<'_>) -> Result<Option<SetTime>, DecodeError> {
    match decoder.read_u32()? {
        0 => Ok(None),
        1 => Ok(Some(SetTime::ServerTime)),
        2 => Ok(Some(SetTime::ClientTime(decode_time(decoder)?))),
        value => Err(DecodeError::InvalidDiscriminant {
            kind: "set time",
            value,
        }),
    }
}

fn decode_stability(decoder: &mut Decoder<'_>) -> Result<WriteStability, DecodeError> {
    match decoder.read_u32()? {
        0 => Ok(WriteStability::Unstable),
        1 => Ok(WriteStability::DataSync),
        2 => Ok(WriteStability::FileSync),
        value => Err(DecodeError::InvalidDiscriminant {
            kind: "write stability",
            value,
        }),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GetAttrResult {
    Ok { attributes: FileAttributes },
    Err { status: NfsStatus },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetAttrResult {
    Ok { object_wcc: WccData },
    Err { status: NfsStatus, object_wcc: WccData },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenameResult {
    Ok {
        from_directory_wcc: WccData,
        to_directory_wcc: WccData,
    },
    Err {
        status: NfsStatus,
        from_directory_wcc: WccData,
        to_directory_wcc: WccData,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadLinkResult {
    Ok {
        attributes: Option<FileAttributes>,
        path: Vec<u8>,
    },
    Err {
        status: NfsStatus,
        attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LookupResult {
    Ok {
        object_handle: Vec<u8>,
        object_attributes: Option<FileAttributes>,
        directory_attributes: Option<FileAttributes>,
    },
    Err {
        status: NfsStatus,
        directory_attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessResult {
    Ok {
        attributes: Option<FileAttributes>,
        access: u32,
    },
    Err {
        status: NfsStatus,
        attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadResult {
    Ok {
        attributes: Option<FileAttributes>,
        data: Vec<u8>,
        eof: bool,
    },
    Err {
        status: NfsStatus,
        attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteResult {
    Ok {
        file_wcc: WccData,
        count: u32,
        committed: WriteStability,
        verifier: [u8; 8],
    },
    Err {
        status: NfsStatus,
        file_wcc: WccData,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateResult {
    Ok {
        object_handle: Option<Vec<u8>>,
        object_attributes: Option<FileAttributes>,
        directory_wcc: WccData,
    },
    Err {
        status: NfsStatus,
        directory_wcc: WccData,
    },
}

pub type MkdirResult = CreateResult;
pub type SymlinkResult = CreateResult;
pub type MknodResult = CreateResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WccResult {
    Ok { object_wcc: WccData },
    Err { status: NfsStatus, object_wcc: WccData },
}

pub type RemoveResult = WccResult;
pub type RmdirResult = WccResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkResult {
    Ok {
        object_attributes: Option<FileAttributes>,
        directory_wcc: WccData,
    },
    Err {
        status: NfsStatus,
        object_attributes: Option<FileAttributes>,
        directory_wcc: WccData,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadDirEntryExtension {
    Basic,
    Plus {
        attributes: Option<FileAttributes>,
        handle: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadDirEntry {
    pub file_id: u64,
    pub name: Vec<u8>,
    pub cookie: u64,
    pub extension: ReadDirEntryExtension,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadDirResult {
    Ok {
        directory_attributes: Option<FileAttributes>,
        verifier: [u8; 8],
        entries: Vec<ReadDirEntry>,
        eof: bool,
    },
    Err {
        status: NfsStatus,
        directory_attributes: Option<FileAttributes>,
    },
}

pub type ReadDirPlusResult = ReadDirResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsStatResult {
    Ok {
        attributes: Option<FileAttributes>,
        info: FsStat,
    },
    Err {
        status: NfsStatus,
        attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsInfoResult {
    Ok {
        attributes: Option<FileAttributes>,
        info: FsInfo,
        properties: u32,
    },
    Err {
        status: NfsStatus,
        attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathConfResult {
    Ok {
        attributes: Option<FileAttributes>,
        info: PathConf,
    },
    Err {
        status: NfsStatus,
        attributes: Option<FileAttributes>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitResult {
    Ok { file_wcc: WccData, verifier: [u8; 8] },
    Err { status: NfsStatus, file_wcc: WccData },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::codec::Encoder;

    #[test]
    fn write_request_data_shares_the_rpc_record() {
        let payload = vec![0x5a; 1024];
        let mut encoder = Encoder::new();
        encoder.write_opaque(&[0x11; 45]).unwrap();
        encoder.write_u64(7);
        encoder.write_u32(payload.len() as u32);
        encoder.write_u32(2);
        encoder.write_opaque(&payload).unwrap();
        let record = Bytes::from(encoder.into_bytes());
        let arguments = WriteRequest::decode(record.clone(), payload.len()).unwrap();
        assert_eq!(arguments.data, payload);
        let record_start = record.as_ptr() as usize;
        let record_end = record_start + record.len();
        let data_start = arguments.data.as_ptr() as usize;
        assert!((record_start..record_end).contains(&data_start));
        arguments.validate().unwrap();
    }
}
