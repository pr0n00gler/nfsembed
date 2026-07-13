use crate::nfs3::procedures::{
    AccessResult, CommitResult, CreateResult, FsInfoResult, FsStatResult, GetAttrResult, LinkResult, LookupResult,
    PathConfResult, ReadDirEntry, ReadDirEntryExtension, ReadDirResult, ReadLinkResult, ReadResult, RenameResult,
    SetAttrResult, WccResult, WriteResult,
};
use crate::nfs3::types::{FileAttributes, FileType, NfsStatus, NfsTime, WccData, WriteStability};
pub use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};
use crate::vfs::DeviceNumber;

pub trait EncodeNfsResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;
}

impl EncodeNfsResult for GetAttrResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_attributes(encoder, attributes)?;
            },
            Self::Err { status } => encoder.write_u32(*status as u32),
        }
        Ok(())
    }
}

impl EncodeNfsResult for LookupResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                object_handle,
                object_attributes,
                directory_attributes,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encoder.write_opaque(object_handle)?;
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
            },
            Self::Err {
                status,
                directory_attributes,
            } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for AccessResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, access } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(*access);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for ReadResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, data, eof } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(u32::try_from(data.len()).map_err(|_| EncodeError::TooLarge(data.len()))?);
                encoder.write_bool(*eof);
                encoder.write_opaque(data)?;
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for WriteResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                file_wcc,
                count,
                committed,
                verifier,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, file_wcc)?;
                encoder.write_u32(*count);
                encoder.write_u32(encode_stability(*committed));
                encoder.write_fixed(verifier);
            },
            Self::Err { status, file_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, file_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for CreateResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                object_handle,
                object_attributes,
                directory_wcc,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encoder.write_bool(object_handle.is_some());
                if let Some(handle) = object_handle {
                    encoder.write_opaque(handle)?;
                }
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_wcc(encoder, directory_wcc)?;
            },
            Self::Err { status, directory_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, directory_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for WccResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { object_wcc } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, object_wcc)?;
            },
            Self::Err { status, object_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, object_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for LinkResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                object_attributes,
                directory_wcc,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_wcc(encoder, directory_wcc)?;
            },
            Self::Err {
                status,
                object_attributes,
                directory_wcc,
            } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, object_attributes.as_ref())?;
                encode_wcc(encoder, directory_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for ReadDirResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                directory_attributes,
                verifier,
                entries,
                eof,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
                encoder.write_fixed(verifier);
                for entry in entries {
                    encode_readdir_entry(encoder, entry)?;
                }
                encoder.write_bool(false);
                encoder.write_bool(*eof);
            },
            Self::Err {
                status,
                directory_attributes,
            } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, directory_attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for FsStatResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, info } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u64(info.total_bytes);
                encoder.write_u64(info.free_bytes);
                encoder.write_u64(info.available_bytes);
                encoder.write_u64(info.total_files);
                encoder.write_u64(info.free_files);
                encoder.write_u64(info.available_files);
                encoder.write_u32(info.invariant_seconds);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for PathConfResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, info } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(info.max_links);
                encoder.write_u32(info.max_name_length);
                encoder.write_bool(info.no_truncation);
                encoder.write_bool(info.chown_restricted);
                encoder.write_bool(info.case_insensitive);
                encoder.write_bool(info.case_preserving);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for CommitResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { file_wcc, verifier } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, file_wcc)?;
                encoder.write_fixed(verifier);
            },
            Self::Err { status, file_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, file_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for SetAttrResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { object_wcc } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, object_wcc)?;
            },
            Self::Err { status, object_wcc } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, object_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for RenameResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                from_directory_wcc,
                to_directory_wcc,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_wcc(encoder, from_directory_wcc)?;
                encode_wcc(encoder, to_directory_wcc)?;
            },
            Self::Err {
                status,
                from_directory_wcc,
                to_directory_wcc,
            } => {
                encoder.write_u32(*status as u32);
                encode_wcc(encoder, from_directory_wcc)?;
                encode_wcc(encoder, to_directory_wcc)?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for ReadLinkResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok { attributes, path } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_opaque(path)?;
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

impl EncodeNfsResult for FsInfoResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                attributes,
                info,
                properties,
            } => {
                encoder.write_u32(NfsStatus::Ok as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
                encoder.write_u32(info.max_read);
                encoder.write_u32(info.preferred_read);
                encoder.write_u32(info.read_multiple);
                encoder.write_u32(info.max_write);
                encoder.write_u32(info.preferred_write);
                encoder.write_u32(info.write_multiple);
                encoder.write_u32(info.preferred_readdir);
                encoder.write_u64(info.max_file_size);
                encode_time(encoder, info.time_granularity)?;
                encoder.write_u32(*properties);
            },
            Self::Err { status, attributes } => {
                encoder.write_u32(*status as u32);
                encode_post_attributes(encoder, attributes.as_ref())?;
            },
        }
        Ok(())
    }
}

pub fn encode_readdir_entry(encoder: &mut Encoder, entry: &ReadDirEntry) -> Result<(), EncodeError> {
    encoder.write_bool(true);
    encoder.write_u64(entry.file_id);
    encoder.write_opaque(&entry.name)?;
    encoder.write_u64(entry.cookie);
    match &entry.extension {
        ReadDirEntryExtension::Basic => {},
        ReadDirEntryExtension::Plus { attributes, handle } => {
            encode_post_attributes(encoder, attributes.as_ref())?;
            encoder.write_bool(handle.is_some());
            if let Some(handle) = handle {
                encoder.write_opaque(handle)?;
            }
        },
    }
    Ok(())
}

/// Applies the production READDIR wire-size policy to a complete typed
/// result. `max_size` applies to the successful result arm, excluding the
/// status discriminant as required by RFC 1813. Returns `false` when even the
/// empty success shape cannot fit.
pub fn truncate_readdir_result(result: &mut ReadDirResult, max_size: usize) -> Result<bool, EncodeError> {
    // Encode the complete result once, then subtract each removed entry's
    // independent XDR representation. This preserves the old truncation
    // policy without repeatedly encoding the entire remaining directory.
    let mut encoder = Encoder::new();
    result.encode_result(&mut encoder)?;
    let mut encoded_size = encoder.len().saturating_sub(4);
    if encoded_size <= max_size {
        return Ok(true);
    }
    let ReadDirResult::Ok { entries, eof, .. } = result else {
        return Ok(false);
    };
    while encoded_size > max_size {
        let Some(removed) = entries.pop() else {
            return Ok(false);
        };
        let mut removed_encoder = Encoder::new();
        encode_readdir_entry(&mut removed_encoder, &removed)?;
        encoded_size = encoded_size.saturating_sub(removed_encoder.len());
        *eof = false;
    }
    Ok(true)
}

#[cfg(test)]
fn truncate_readdir_result_reference(result: &mut ReadDirResult, max_size: usize) -> Result<bool, EncodeError> {
    loop {
        let mut encoder = Encoder::new();
        result.encode_result(&mut encoder)?;
        if encoder.len().saturating_sub(4) <= max_size {
            return Ok(true);
        }
        match result {
            ReadDirResult::Ok { entries, eof, .. } if !entries.is_empty() => {
                entries.pop();
                *eof = false;
            },
            _ => return Ok(false),
        }
    }
}

fn encode_stability(stability: WriteStability) -> u32 {
    match stability {
        WriteStability::Unstable => 0,
        WriteStability::DataSync => 1,
        WriteStability::FileSync => 2,
    }
}

pub fn encode_attributes(encoder: &mut Encoder, attributes: &FileAttributes) -> Result<(), EncodeError> {
    encoder.write_u32(match attributes.file_type {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::BlockDevice => 3,
        FileType::CharacterDevice => 4,
        FileType::Symlink => 5,
        FileType::Socket => 6,
        FileType::Fifo => 7,
    });
    encoder.write_u32(attributes.mode);
    encoder.write_u32(attributes.links);
    encoder.write_u32(attributes.uid);
    encoder.write_u32(attributes.gid);
    encoder.write_u64(attributes.size);
    encoder.write_u64(attributes.used);
    let device = if matches!(attributes.file_type, FileType::BlockDevice | FileType::CharacterDevice) {
        attributes.device.unwrap_or_default()
    } else {
        DeviceNumber::default()
    };
    encoder.write_u32(device.major);
    encoder.write_u32(device.minor);
    encoder.write_u64(attributes.fs_id);
    encoder.write_u64(attributes.file_id);
    encode_time(encoder, attributes.access_time)?;
    encode_time(encoder, attributes.modify_time)?;
    encode_time(encoder, attributes.change_time)?;
    Ok(())
}

pub fn encode_post_attributes(encoder: &mut Encoder, attributes: Option<&FileAttributes>) -> Result<(), EncodeError> {
    encoder.write_bool(attributes.is_some());
    if let Some(attributes) = attributes {
        encode_attributes(encoder, attributes)?;
    }
    Ok(())
}

pub fn encode_wcc(encoder: &mut Encoder, wcc: &WccData) -> Result<(), EncodeError> {
    encoder.write_bool(wcc.before.is_some());
    if let Some(attributes) = &wcc.before {
        encoder.write_u64(attributes.size);
        encode_time(encoder, attributes.modify_time)?;
        encode_time(encoder, attributes.change_time)?;
    }
    encode_post_attributes(encoder, wcc.after.as_ref())?;
    Ok(())
}

pub fn encode_time(encoder: &mut Encoder, time: NfsTime) -> Result<(), EncodeError> {
    let seconds = u32::try_from(time.seconds).map_err(|_| EncodeError::InvalidTime {
        seconds: time.seconds,
        nanoseconds: time.nanoseconds,
    })?;
    if time.nanoseconds > 999_999_999 {
        return Err(EncodeError::InvalidTime {
            seconds: time.seconds,
            nanoseconds: time.nanoseconds,
        });
    }
    encoder.write_u32(seconds);
    encoder.write_u32(time.nanoseconds);
    Ok(())
}

#[cfg(test)]
fn encode_getattr_for_test(result: &GetAttrResult) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    result.encode_result(&mut encoder)?;
    Ok(encoder.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::DeviceNumber;

    #[test]
    fn setattr_failure_is_one_complete_wcc_result() {
        let result = SetAttrResult::Err {
            status: NfsStatus::NotSynchronized,
            object_wcc: WccData::default(),
        };
        let mut encoder = Encoder::new();
        result.encode_result(&mut encoder).unwrap();
        assert_eq!(encoder.into_bytes(), [10002u32.to_be_bytes(), 0u32.to_be_bytes(), 0u32.to_be_bytes()].concat());
    }

    #[test]
    fn rename_failure_contains_both_wcc_arms() {
        let result = RenameResult::Err {
            status: NfsStatus::Access,
            from_directory_wcc: WccData::default(),
            to_directory_wcc: WccData::default(),
        };
        let mut encoder = Encoder::new();
        result.encode_result(&mut encoder).unwrap();
        assert_eq!(encoder.len(), 20);
    }

    #[test]
    fn device_numbers_are_preserved_in_file_attributes() {
        let attributes = FileAttributes {
            file_type: FileType::BlockDevice,
            mode: 0o600,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: Some(DeviceNumber { major: 12, minor: 34 }),
            fs_id: 1,
            file_id: 2,
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        };
        let mut encoder = Encoder::new();
        encode_attributes(&mut encoder, &attributes).unwrap();
        let bytes = encoder.into_bytes();
        assert_eq!(u32::from_be_bytes(bytes[36..40].try_into().unwrap()), 12);
        assert_eq!(u32::from_be_bytes(bytes[40..44].try_into().unwrap()), 34);
    }

    #[test]
    fn device_numbers_are_zeroed_for_non_device_file_types() {
        let attributes = FileAttributes {
            file_type: FileType::Regular,
            mode: 0o600,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: Some(DeviceNumber { major: 12, minor: 34 }),
            fs_id: 1,
            file_id: 2,
            access_time: NfsTime::default(),
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        };
        let mut encoder = Encoder::new();
        encode_attributes(&mut encoder, &attributes).unwrap();
        let bytes = encoder.into_bytes();
        assert_eq!(u32::from_be_bytes(bytes[36..40].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(bytes[40..44].try_into().unwrap()), 0);
    }

    #[test]
    fn out_of_range_backend_times_are_rejected_instead_of_clamped() {
        let attributes = FileAttributes {
            file_type: FileType::Regular,
            mode: 0o600,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: None,
            fs_id: 1,
            file_id: 2,
            access_time: NfsTime {
                seconds: u64::from(u32::MAX) + 1,
                nanoseconds: 0,
            },
            modify_time: NfsTime::default(),
            change_time: NfsTime::default(),
        };
        assert!(matches!(
            encode_getattr_for_test(&GetAttrResult::Ok { attributes }),
            Err(EncodeError::InvalidTime { .. })
        ));
    }

    #[test]
    fn linear_readdir_truncation_matches_reference_policy() {
        let template = ReadDirResult::Ok {
            directory_attributes: None,
            verifier: [3; 8],
            entries: (0..32)
                .map(|index| ReadDirEntry {
                    file_id: index,
                    name: vec![b'x'; index as usize % 13 + 1],
                    cookie: index + 1,
                    extension: ReadDirEntryExtension::Basic,
                })
                .collect(),
            eof: true,
        };
        for limit in (0..=1400).step_by(7) {
            let mut actual = template.clone();
            let mut expected = template.clone();
            assert_eq!(
                truncate_readdir_result(&mut actual, limit).unwrap(),
                truncate_readdir_result_reference(&mut expected, limit).unwrap()
            );
            assert_eq!(actual, expected);
        }
    }
}
