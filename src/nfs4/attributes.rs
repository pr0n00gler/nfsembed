//! Helpers for constructing the ordered `attrlist4` payload in `fattr4`.

use super::types::{
    Bitmap, FileAttributes, FsId, NfsFileHandle, NfsFileType, NfsStatus, NfsTime, SetTime, NFS4_FHSIZE,
};
use crate::rpc::codec::{EncodeError, Encoder};

pub fn bitmap_contains(bitmap: &[u32], attribute: u32) -> bool {
    let Ok(word) = usize::try_from(attribute / 32) else {
        return false;
    };
    bitmap.get(word).is_some_and(|value| value & (1 << (attribute % 32)) != 0)
}

pub fn bitmap_from_attributes(attributes: impl IntoIterator<Item = u32>) -> Result<Bitmap, AttributeEncodeError> {
    let mut bitmap = Vec::new();
    for attribute in attributes {
        insert_attribute(&mut bitmap, attribute)?;
    }
    Ok(bitmap)
}

/// Builds `fattr4.attr_vals` in the ascending attribute-number order required
/// by RFC 7530 while maintaining the matching bitmap.
#[derive(Default)]
pub struct AttributeEncoder {
    mask: Bitmap,
    values: Encoder,
    last_attribute: Option<u32>,
}

impl AttributeEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mask(&self) -> &[u32] {
        &self.mask
    }

    pub fn values_len(&self) -> usize {
        self.values.len()
    }

    /// Encodes one value. Attributes must be supplied in strictly ascending
    /// numeric order.
    pub fn push(
        &mut self,
        attribute: u32,
        encode: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
    ) -> Result<(), AttributeEncodeError> {
        self.check_order(attribute)?;
        encode(&mut self.values)?;
        insert_attribute(&mut self.mask, attribute)?;
        self.last_attribute = Some(attribute);
        Ok(())
    }

    pub fn push_raw_xdr(&mut self, attribute: u32, encoded_value: &[u8]) -> Result<(), AttributeEncodeError> {
        if !encoded_value.len().is_multiple_of(4) {
            return Err(AttributeEncodeError::UnalignedRawValue(encoded_value.len()));
        }
        self.push(attribute, |encoder| {
            encoder.write_fixed(encoded_value);
            Ok(())
        })
    }

    pub fn push_u32(&mut self, attribute: u32, value: u32) -> Result<(), AttributeEncodeError> {
        self.push(attribute, |encoder| {
            encoder.write_u32(value);
            Ok(())
        })
    }

    pub fn push_u64(&mut self, attribute: u32, value: u64) -> Result<(), AttributeEncodeError> {
        self.push(attribute, |encoder| {
            encoder.write_u64(value);
            Ok(())
        })
    }

    pub fn push_bool(&mut self, attribute: u32, value: bool) -> Result<(), AttributeEncodeError> {
        self.push(attribute, |encoder| {
            encoder.write_bool(value);
            Ok(())
        })
    }

    pub fn push_opaque(&mut self, attribute: u32, value: &[u8]) -> Result<(), AttributeEncodeError> {
        self.push(attribute, |encoder| encoder.write_opaque(value))
    }

    pub fn push_bitmap(&mut self, attribute: u32, value: &[u32]) -> Result<(), AttributeEncodeError> {
        self.push(attribute, |encoder| {
            encoder.write_u32(u32::try_from(value.len()).map_err(|_| EncodeError::TooLarge(value.len()))?);
            for word in value {
                encoder.write_u32(*word);
            }
            Ok(())
        })
    }

    pub fn push_file_type(&mut self, attribute: u32, value: NfsFileType) -> Result<(), AttributeEncodeError> {
        self.push_u32(attribute, value as u32)
    }

    pub fn push_status(&mut self, attribute: u32, value: NfsStatus) -> Result<(), AttributeEncodeError> {
        self.push_u32(attribute, value as u32)
    }

    pub fn push_fsid(&mut self, attribute: u32, value: FsId) -> Result<(), AttributeEncodeError> {
        self.push(attribute, |encoder| {
            encoder.write_u64(value.major);
            encoder.write_u64(value.minor);
            Ok(())
        })
    }

    pub fn push_file_handle(&mut self, attribute: u32, value: &NfsFileHandle) -> Result<(), AttributeEncodeError> {
        if value.as_bytes().len() > NFS4_FHSIZE {
            return Err(AttributeEncodeError::Xdr(EncodeError::TooLarge(value.as_bytes().len())));
        }
        self.push_opaque(attribute, value.as_bytes())
    }

    pub fn push_time(&mut self, attribute: u32, value: NfsTime) -> Result<(), AttributeEncodeError> {
        validate_nanoseconds(value)?;
        self.push(attribute, |encoder| {
            encoder.write_u64(value.seconds as u64);
            encoder.write_u32(value.nanoseconds);
            Ok(())
        })
    }

    pub fn push_set_time(&mut self, attribute: u32, value: SetTime) -> Result<(), AttributeEncodeError> {
        if let SetTime::Client(time) = value {
            validate_nanoseconds(time)?;
        }
        self.push(attribute, |encoder| {
            match value {
                SetTime::Server => encoder.write_u32(0),
                SetTime::Client(time) => {
                    encoder.write_u32(1);
                    encoder.write_u64(time.seconds as u64);
                    encoder.write_u32(time.nanoseconds);
                },
            }
            Ok(())
        })
    }

    pub fn finish(self) -> FileAttributes {
        FileAttributes {
            mask: self.mask,
            values: self.values.into_bytes(),
        }
    }

    fn check_order(&self, attribute: u32) -> Result<(), AttributeEncodeError> {
        if let Some(previous) = self.last_attribute {
            if attribute <= previous {
                return Err(AttributeEncodeError::NotStrictlyAscending {
                    previous,
                    next: attribute,
                });
            }
        }
        Ok(())
    }
}

fn insert_attribute(bitmap: &mut Bitmap, attribute: u32) -> Result<(), AttributeEncodeError> {
    let word = usize::try_from(attribute / 32).map_err(|_| AttributeEncodeError::BitmapTooLarge)?;
    let needed = word.checked_add(1).ok_or(AttributeEncodeError::BitmapTooLarge)?;
    if needed > bitmap.len() {
        bitmap
            .try_reserve_exact(needed - bitmap.len())
            .map_err(|_| AttributeEncodeError::BitmapTooLarge)?;
        bitmap.resize(needed, 0);
    }
    bitmap[word] |= 1 << (attribute % 32);
    Ok(())
}

fn validate_nanoseconds(value: NfsTime) -> Result<(), AttributeEncodeError> {
    if value.nanoseconds > 999_999_999 {
        Err(AttributeEncodeError::InvalidNanoseconds(value.nanoseconds))
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AttributeEncodeError {
    #[error("attribute {next} does not follow attribute {previous} in strictly ascending order")]
    NotStrictlyAscending { previous: u32, next: u32 },
    #[error("attribute bitmap is too large to represent")]
    BitmapTooLarge,
    #[error("raw XDR attribute value has non-aligned length {0}")]
    UnalignedRawValue(usize),
    #[error("NFS time nanoseconds value {0} is greater than 999999999")]
    InvalidNanoseconds(u32),
    #[error(transparent)]
    Xdr(#[from] EncodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs4::types::{FATTR4_FILEHANDLE, FATTR4_SIZE, FATTR4_SUPPORTED_ATTRS};

    #[test]
    fn builds_matching_bitmap_and_ordered_values() {
        let mut attributes = AttributeEncoder::new();
        attributes.push_bitmap(FATTR4_SUPPORTED_ATTRS, &[0x8000_0001]).unwrap();
        attributes.push_u64(FATTR4_SIZE, 0x0102_0304_0506_0708).unwrap();
        attributes
            .push_file_handle(FATTR4_FILEHANDLE, &NfsFileHandle(vec![1, 2, 3]))
            .unwrap();
        let attributes = attributes.finish();

        assert!(bitmap_contains(&attributes.mask, FATTR4_SUPPORTED_ATTRS));
        assert!(bitmap_contains(&attributes.mask, FATTR4_SIZE));
        assert!(bitmap_contains(&attributes.mask, FATTR4_FILEHANDLE));
        assert_eq!(
            attributes.values,
            vec![
                0, 0, 0, 1, 0x80, 0, 0, 1, // supported_attrs
                1, 2, 3, 4, 5, 6, 7, 8, // size
                0, 0, 0, 3, 1, 2, 3, 0, // filehandle
            ]
        );
    }

    #[test]
    fn rejects_duplicate_or_descending_attributes() {
        let mut attributes = AttributeEncoder::new();
        attributes.push_u32(4, 1).unwrap();
        assert!(matches!(
            attributes.push_u32(4, 2),
            Err(AttributeEncodeError::NotStrictlyAscending { previous: 4, next: 4 })
        ));
        assert!(matches!(
            attributes.push_u32(3, 2),
            Err(AttributeEncodeError::NotStrictlyAscending { previous: 4, next: 3 })
        ));
    }
}
