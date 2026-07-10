use crate::mount3::types::{DumpResult, ExportResult, MountResult};
use crate::rpc::codec::{EncodeError, Encoder};

pub trait EncodeMountResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;
}

impl EncodeMountResult for MountResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok {
                file_handle,
                auth_flavors,
            } => {
                encoder.write_u32(0);
                encoder.write_opaque(file_handle)?;
                encoder.write_u32(
                    u32::try_from(auth_flavors.len()).map_err(|_| EncodeError::TooLarge(auth_flavors.len()))?,
                );
                for flavor in auth_flavors {
                    encoder.write_u32(*flavor);
                }
            },
            Self::Err(status) => encoder.write_u32(*status as u32),
        }
        Ok(())
    }
}

impl EncodeMountResult for DumpResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        for mount in &self.mounts {
            encoder.write_bool(true);
            encoder.write_opaque(&mount.host)?;
            encoder.write_opaque(&mount.path)?;
        }
        encoder.write_bool(false);
        Ok(())
    }
}

impl EncodeMountResult for ExportResult {
    fn encode_result(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        for export in &self.exports {
            encoder.write_bool(true);
            encoder.write_opaque(&export.path)?;
            for group in &export.groups {
                encoder.write_bool(true);
                encoder.write_opaque(group)?;
            }
            encoder.write_bool(false);
        }
        encoder.write_bool(false);
        Ok(())
    }
}
