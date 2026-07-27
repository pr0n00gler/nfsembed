//! Table-driven NFSv4.0 attribute policy and canonical `fattr4` handling.
//!
//! Attribute values are kept separate from policy so callers can assemble a
//! view from backend metadata, identity mapping, quota, migration, and ACL
//! providers without teaching the XDR layer about those services.

use super::attributes::{bitmap_contains, bitmap_from_attributes, AttributeEncodeError, AttributeEncoder};
use super::types::{
    Bitmap, FileAttributes, FsId, FsLocation, FsLocations, NfsAce, NfsFileHandle, NfsFileType, NfsStatus, NfsTime,
    SetTime, SpecData, FATTR4_ACL, FATTR4_ARCHIVE, FATTR4_CANSETTIME, FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING,
    FATTR4_CHANGE, FATTR4_CHOWN_RESTRICTED, FATTR4_FH_EXPIRE_TYPE, FATTR4_FILEHANDLE, FATTR4_FILEID,
    FATTR4_FILES_AVAIL, FATTR4_FILES_FREE, FATTR4_FILES_TOTAL, FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_HIDDEN,
    FATTR4_HOMOGENEOUS, FATTR4_LEASE_TIME, FATTR4_LINK_SUPPORT, FATTR4_MAXFILESIZE, FATTR4_MAXLINK, FATTR4_MAXNAME,
    FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_MIMETYPE, FATTR4_MODE, FATTR4_MOUNTED_ON_FILEID, FATTR4_NAMED_ATTR,
    FATTR4_NO_TRUNC, FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_QUOTA_AVAIL_HARD,
    FATTR4_QUOTA_AVAIL_SOFT, FATTR4_QUOTA_USED, FATTR4_RAWDEV, FATTR4_RDATTR_ERROR, FATTR4_SIZE, FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE, FATTR4_SPACE_TOTAL, FATTR4_SPACE_USED, FATTR4_SUPPORTED_ATTRS, FATTR4_SYMLINK_SUPPORT,
    FATTR4_SYSTEM, FATTR4_TIME_ACCESS, FATTR4_TIME_ACCESS_SET, FATTR4_TIME_BACKUP, FATTR4_TIME_CREATE,
    FATTR4_TIME_DELTA, FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY, FATTR4_TIME_MODIFY_SET, FATTR4_TYPE,
    FATTR4_UNIQUE_HANDLES, NFS4_FHSIZE, NFS4_OPAQUE_LIMIT,
};
use crate::rpc::codec::{DecodeError, EncodeError, Encoder};
use crate::vfs::{
    FileAttributes as VfsFileAttributes, FileType, FsInfo, FsStat, Nfs4FsLocations, PathConf,
    SetAttributes as VfsSetAttributes, SetTime as VfsSetTime, VfsCapabilities,
};

pub const ATTRIBUTE_COUNT: usize = 56;
pub const LAST_ATTRIBUTE_ID: u32 = FATTR4_MOUNTED_ON_FILEID;
pub const MODE4_MASK: u32 = 0x0fff;

const ATTRIBUTE_BITMAP_WORDS: usize = 2;
const MAX_REQUEST_BITMAP_WORDS: usize = 64;
const MAX_COLLECTION_ITEMS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeRequirement {
    Required,
    Recommended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeScope {
    Server,
    FileSystem,
    Object,
    Quota,
    SetOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl AttributeAccess {
    pub const fn is_readable(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    pub const fn is_writable(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeWireType {
    Bitmap,
    FileType,
    U32,
    U64,
    Boolean,
    FsId,
    Status,
    FileHandle,
    Acl,
    FsLocations,
    String,
    SpecData,
    Time,
    SetTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeDefinition {
    pub id: u32,
    pub name: &'static str,
    pub requirement: AttributeRequirement,
    pub scope: AttributeScope,
    pub access: AttributeAccess,
    pub wire_type: AttributeWireType,
}

macro_rules! definition {
    ($id:expr, $name:literal, $requirement:ident, $scope:ident, $access:ident, $wire:ident) => {
        AttributeDefinition {
            id: $id,
            name: $name,
            requirement: AttributeRequirement::$requirement,
            scope: AttributeScope::$scope,
            access: AttributeAccess::$access,
            wire_type: AttributeWireType::$wire,
        }
    };
}

/// RFC 7530 Tables 3 and 4, plus the attribute classification in section 5.4.
pub const ATTRIBUTE_DEFINITIONS: [AttributeDefinition; ATTRIBUTE_COUNT] = [
    definition!(0, "supported_attrs", Required, FileSystem, ReadOnly, Bitmap),
    definition!(1, "type", Required, Object, ReadOnly, FileType),
    definition!(2, "fh_expire_type", Required, FileSystem, ReadOnly, U32),
    definition!(3, "change", Required, Object, ReadOnly, U64),
    definition!(4, "size", Required, Object, ReadWrite, U64),
    definition!(5, "link_support", Required, FileSystem, ReadOnly, Boolean),
    definition!(6, "symlink_support", Required, FileSystem, ReadOnly, Boolean),
    definition!(7, "named_attr", Required, Object, ReadOnly, Boolean),
    definition!(8, "fsid", Required, Object, ReadOnly, FsId),
    definition!(9, "unique_handles", Required, FileSystem, ReadOnly, Boolean),
    definition!(10, "lease_time", Required, Server, ReadOnly, U32),
    definition!(11, "rdattr_error", Required, Object, ReadOnly, Status),
    definition!(12, "acl", Recommended, Object, ReadWrite, Acl),
    definition!(13, "aclsupport", Recommended, FileSystem, ReadOnly, U32),
    definition!(14, "archive", Recommended, Object, ReadWrite, Boolean),
    definition!(15, "cansettime", Recommended, FileSystem, ReadOnly, Boolean),
    definition!(16, "case_insensitive", Recommended, FileSystem, ReadOnly, Boolean),
    definition!(17, "case_preserving", Recommended, FileSystem, ReadOnly, Boolean),
    definition!(18, "chown_restricted", Recommended, FileSystem, ReadOnly, Boolean),
    definition!(19, "filehandle", Required, Object, ReadOnly, FileHandle),
    definition!(20, "fileid", Recommended, Object, ReadOnly, U64),
    definition!(21, "files_avail", Recommended, FileSystem, ReadOnly, U64),
    definition!(22, "files_free", Recommended, FileSystem, ReadOnly, U64),
    definition!(23, "files_total", Recommended, FileSystem, ReadOnly, U64),
    definition!(24, "fs_locations", Recommended, FileSystem, ReadOnly, FsLocations),
    definition!(25, "hidden", Recommended, Object, ReadWrite, Boolean),
    definition!(26, "homogeneous", Recommended, FileSystem, ReadOnly, Boolean),
    definition!(27, "maxfilesize", Recommended, FileSystem, ReadOnly, U64),
    definition!(28, "maxlink", Recommended, Object, ReadOnly, U32),
    definition!(29, "maxname", Recommended, FileSystem, ReadOnly, U32),
    definition!(30, "maxread", Recommended, FileSystem, ReadOnly, U64),
    definition!(31, "maxwrite", Recommended, FileSystem, ReadOnly, U64),
    definition!(32, "mimetype", Recommended, Object, ReadWrite, String),
    definition!(33, "mode", Recommended, Object, ReadWrite, U32),
    definition!(34, "no_trunc", Recommended, FileSystem, ReadOnly, Boolean),
    definition!(35, "numlinks", Recommended, Object, ReadOnly, U32),
    definition!(36, "owner", Recommended, Object, ReadWrite, String),
    definition!(37, "owner_group", Recommended, Object, ReadWrite, String),
    definition!(38, "quota_avail_hard", Recommended, Quota, ReadOnly, U64),
    definition!(39, "quota_avail_soft", Recommended, Quota, ReadOnly, U64),
    definition!(40, "quota_used", Recommended, Quota, ReadOnly, U64),
    definition!(41, "rawdev", Recommended, Object, ReadOnly, SpecData),
    definition!(42, "space_avail", Recommended, FileSystem, ReadOnly, U64),
    definition!(43, "space_free", Recommended, FileSystem, ReadOnly, U64),
    definition!(44, "space_total", Recommended, FileSystem, ReadOnly, U64),
    definition!(45, "space_used", Recommended, Object, ReadOnly, U64),
    definition!(46, "system", Recommended, Object, ReadWrite, Boolean),
    definition!(47, "time_access", Recommended, Object, ReadOnly, Time),
    definition!(48, "time_access_set", Recommended, SetOnly, WriteOnly, SetTime),
    definition!(49, "time_backup", Recommended, Object, ReadWrite, Time),
    definition!(50, "time_create", Recommended, Object, ReadWrite, Time),
    definition!(51, "time_delta", Recommended, FileSystem, ReadOnly, Time),
    definition!(52, "time_metadata", Recommended, Object, ReadOnly, Time),
    definition!(53, "time_modify", Recommended, Object, ReadOnly, Time),
    definition!(54, "time_modify_set", Recommended, SetOnly, WriteOnly, SetTime),
    definition!(55, "mounted_on_fileid", Recommended, Object, ReadOnly, U64),
];

pub fn attribute_definition(id: u32) -> Option<&'static AttributeDefinition> {
    ATTRIBUTE_DEFINITIONS
        .get(usize::try_from(id).ok()?)
        .filter(|definition| definition.id == id)
}

pub fn required_attribute_bitmap() -> Bitmap {
    bitmap_from_attributes(
        ATTRIBUTE_DEFINITIONS
            .iter()
            .filter(|definition| definition.requirement == AttributeRequirement::Required)
            .map(|definition| definition.id),
    )
    .expect("the fixed NFSv4.0 required-attribute bitmap is representable")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttributeValue {
    Bitmap(Bitmap),
    FileType(NfsFileType),
    U32(u32),
    U64(u64),
    Boolean(bool),
    FsId(FsId),
    Status(NfsStatus),
    FileHandle(NfsFileHandle),
    Acl(Vec<NfsAce>),
    FsLocations(FsLocations),
    String(Vec<u8>),
    SpecData(SpecData),
    Time(NfsTime),
    SetTime(SetTime),
}

impl AttributeValue {
    pub const fn wire_type(&self) -> AttributeWireType {
        match self {
            Self::Bitmap(_) => AttributeWireType::Bitmap,
            Self::FileType(_) => AttributeWireType::FileType,
            Self::U32(_) => AttributeWireType::U32,
            Self::U64(_) => AttributeWireType::U64,
            Self::Boolean(_) => AttributeWireType::Boolean,
            Self::FsId(_) => AttributeWireType::FsId,
            Self::Status(_) => AttributeWireType::Status,
            Self::FileHandle(_) => AttributeWireType::FileHandle,
            Self::Acl(_) => AttributeWireType::Acl,
            Self::FsLocations(_) => AttributeWireType::FsLocations,
            Self::String(_) => AttributeWireType::String,
            Self::SpecData(_) => AttributeWireType::SpecData,
            Self::Time(_) => AttributeWireType::Time,
            Self::SetTime(_) => AttributeWireType::SetTime,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeValues {
    values: [Option<AttributeValue>; ATTRIBUTE_COUNT],
}

impl Default for AttributeValues {
    fn default() -> Self {
        Self::new()
    }
}

impl AttributeValues {
    pub fn new() -> Self {
        Self {
            values: std::array::from_fn(|_| None),
        }
    }

    pub fn get(&self, attribute: u32) -> Option<&AttributeValue> {
        self.values.get(usize::try_from(attribute).ok()?)?.as_ref()
    }

    pub fn contains(&self, attribute: u32) -> bool {
        self.get(attribute).is_some()
    }

    pub fn insert(&mut self, attribute: u32, value: AttributeValue) -> Result<Option<AttributeValue>, AttributeError> {
        let definition = attribute_definition(attribute).ok_or(AttributeError::UnknownAttribute(attribute))?;
        validate_value(definition, &value)?;
        Ok(self.values[attribute as usize].replace(value))
    }

    pub fn remove(&mut self, attribute: u32) -> Option<AttributeValue> {
        self.values.get_mut(usize::try_from(attribute).ok()?)?.take()
    }

    /// Builds all REQUIRED values plus the object attributes directly
    /// representable by the VFS contract.
    pub fn from_vfs(
        attributes: &VfsFileAttributes,
        file_handle: NfsFileHandle,
        fsid: FsId,
        capabilities: VfsCapabilities,
        lease_time: u32,
    ) -> Result<Self, AttributeError> {
        let mut values = Self::new();
        values.insert(FATTR4_TYPE, AttributeValue::FileType(map_file_type(attributes.file_type)))?;
        values.insert(FATTR4_FH_EXPIRE_TYPE, AttributeValue::U32(0))?;
        values.insert(FATTR4_CHANGE, AttributeValue::U64(attributes.change_id.0))?;
        values.insert(FATTR4_SIZE, AttributeValue::U64(attributes.size))?;
        values.insert(FATTR4_LINK_SUPPORT, AttributeValue::Boolean(capabilities.hard_links))?;
        values.insert(FATTR4_SYMLINK_SUPPORT, AttributeValue::Boolean(capabilities.symbolic_links))?;
        values.insert(FATTR4_NAMED_ATTR, AttributeValue::Boolean(false))?;
        values.insert(FATTR4_FSID, AttributeValue::FsId(fsid))?;
        values.insert(FATTR4_UNIQUE_HANDLES, AttributeValue::Boolean(true))?;
        values.insert(FATTR4_LEASE_TIME, AttributeValue::U32(lease_time))?;
        values.insert(FATTR4_RDATTR_ERROR, AttributeValue::Status(NfsStatus::Ok))?;
        values.insert(FATTR4_FILEHANDLE, AttributeValue::FileHandle(file_handle))?;

        values.insert(FATTR4_CANSETTIME, AttributeValue::Boolean(capabilities.can_set_time))?;
        values.insert(FATTR4_FILEID, AttributeValue::U64(attributes.file_id))?;
        values.insert(FATTR4_HOMOGENEOUS, AttributeValue::Boolean(capabilities.homogeneous))?;
        values.insert(FATTR4_MODE, AttributeValue::U32(attributes.mode))?;
        values.insert(FATTR4_NUMLINKS, AttributeValue::U32(attributes.links))?;
        let device = attributes.device.unwrap_or_default();
        values.insert(
            FATTR4_RAWDEV,
            AttributeValue::SpecData(SpecData {
                major: device.major,
                minor: device.minor,
            }),
        )?;
        values.insert(FATTR4_SPACE_USED, AttributeValue::U64(attributes.used))?;
        values.insert(FATTR4_TIME_ACCESS, AttributeValue::Time(map_time(attributes.access_time)))?;
        values.insert(FATTR4_TIME_METADATA, AttributeValue::Time(map_time(attributes.change_time)))?;
        values.insert(FATTR4_TIME_MODIFY, AttributeValue::Time(map_time(attributes.modify_time)))?;
        values.insert(FATTR4_MOUNTED_ON_FILEID, AttributeValue::U64(attributes.file_id))?;
        Ok(values)
    }

    pub fn apply_fs_stat(&mut self, stat: &FsStat) -> Result<(), AttributeError> {
        self.insert(FATTR4_FILES_AVAIL, AttributeValue::U64(stat.available_files))?;
        self.insert(FATTR4_FILES_FREE, AttributeValue::U64(stat.free_files))?;
        self.insert(FATTR4_FILES_TOTAL, AttributeValue::U64(stat.total_files))?;
        self.insert(FATTR4_SPACE_AVAIL, AttributeValue::U64(stat.available_bytes))?;
        self.insert(FATTR4_SPACE_FREE, AttributeValue::U64(stat.free_bytes))?;
        self.insert(FATTR4_SPACE_TOTAL, AttributeValue::U64(stat.total_bytes))?;
        Ok(())
    }

    pub fn apply_fs_info(&mut self, info: &FsInfo) -> Result<(), AttributeError> {
        self.insert(FATTR4_MAXFILESIZE, AttributeValue::U64(info.max_file_size))?;
        self.insert(FATTR4_MAXREAD, AttributeValue::U64(u64::from(info.max_read)))?;
        self.insert(FATTR4_MAXWRITE, AttributeValue::U64(u64::from(info.max_write)))?;
        self.insert(FATTR4_TIME_DELTA, AttributeValue::Time(map_time(info.time_granularity)))?;
        Ok(())
    }

    pub fn apply_path_conf(&mut self, path_conf: &PathConf) -> Result<(), AttributeError> {
        self.insert(FATTR4_CASE_INSENSITIVE, AttributeValue::Boolean(path_conf.case_insensitive))?;
        self.insert(FATTR4_CASE_PRESERVING, AttributeValue::Boolean(path_conf.case_preserving))?;
        self.insert(FATTR4_CHOWN_RESTRICTED, AttributeValue::Boolean(path_conf.chown_restricted))?;
        self.insert(FATTR4_MAXLINK, AttributeValue::U32(path_conf.max_links))?;
        self.insert(FATTR4_MAXNAME, AttributeValue::U32(path_conf.max_name_length))?;
        self.insert(FATTR4_NO_TRUNC, AttributeValue::Boolean(path_conf.no_truncation))?;
        Ok(())
    }

    pub fn apply_quota(&mut self, quota: QuotaAttributes) -> Result<(), AttributeError> {
        self.insert(FATTR4_QUOTA_AVAIL_HARD, AttributeValue::U64(quota.available_hard))?;
        self.insert(FATTR4_QUOTA_AVAIL_SOFT, AttributeValue::U64(quota.available_soft))?;
        self.insert(FATTR4_QUOTA_USED, AttributeValue::U64(quota.used))?;
        Ok(())
    }

    pub fn apply_fs_locations(&mut self, locations: &Nfs4FsLocations) -> Result<(), AttributeError> {
        self.insert(FATTR4_FS_LOCATIONS, AttributeValue::FsLocations(fs_locations_from_vfs(locations)))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaAttributes {
    pub available_hard: u64,
    pub available_soft: u64,
    pub used: u64,
}

pub fn fs_locations_from_vfs(locations: &Nfs4FsLocations) -> FsLocations {
    FsLocations {
        file_system_root: locations
            .fs_root
            .iter()
            .map(|component| component.as_bytes().to_vec())
            .collect(),
        locations: locations
            .locations
            .iter()
            .map(|location| FsLocation {
                servers: location.servers.iter().map(|server| server.as_bytes().to_vec()).collect(),
                root_path: location
                    .root_path
                    .iter()
                    .map(|component| component.as_bytes().to_vec())
                    .collect(),
            })
            .collect(),
    }
}

#[derive(Clone, Debug)]
pub struct AttributeEngine {
    supported: Bitmap,
}

impl AttributeEngine {
    pub fn new(mut supported: Bitmap) -> Result<Self, AttributeError> {
        canonicalize_bitmap(&mut supported);
        if supported.len() > ATTRIBUTE_BITMAP_WORDS {
            let attribute = first_unknown_attribute(&supported).unwrap_or(LAST_ATTRIBUTE_ID + 1);
            return Err(AttributeError::UnknownAttribute(attribute));
        }
        if let Some(attribute) = first_unknown_attribute(&supported) {
            return Err(AttributeError::UnknownAttribute(attribute));
        }
        for definition in ATTRIBUTE_DEFINITIONS
            .iter()
            .filter(|definition| definition.requirement == AttributeRequirement::Required)
        {
            if !bitmap_contains(&supported, definition.id) {
                return Err(AttributeError::MissingRequiredSupport(definition.id));
            }
        }
        Ok(Self { supported })
    }

    pub fn from_attributes(attributes: impl IntoIterator<Item = u32>) -> Result<Self, AttributeError> {
        Self::new(bitmap_from_attributes(attributes)?)
    }

    pub fn supported_attributes(&self) -> &[u32] {
        &self.supported
    }

    /// Returns the per-object advertised bitmap. Readable RECOMMENDED
    /// attributes without a value are omitted; write-only attributes stay
    /// advertised because no GET value exists for them.
    pub fn effective_supported_attributes(&self, values: &AttributeValues) -> Result<Bitmap, AttributeError> {
        self.validate_required_values(values)?;
        let mut effective = self.supported.clone();
        for definition in &ATTRIBUTE_DEFINITIONS {
            if definition.requirement == AttributeRequirement::Recommended
                && definition.access.is_readable()
                && bitmap_contains(&effective, definition.id)
                && !values.contains(definition.id)
            {
                clear_bitmap_attribute(&mut effective, definition.id);
            }
        }
        canonicalize_bitmap(&mut effective);
        Ok(effective)
    }

    /// Encodes GETATTR values in attribute-number order. Unsupported
    /// RECOMMENDED (and unknown future) attributes are deliberately omitted.
    pub fn encode_getattr(
        &self,
        requested: &[u32],
        values: &AttributeValues,
    ) -> Result<FileAttributes, AttributeError> {
        validate_request_bitmap(requested)?;
        for attribute in attribute_numbers(requested) {
            if let Some(definition) = attribute_definition(attribute) {
                if !definition.access.is_readable() {
                    return Err(AttributeError::InvalidAccess {
                        attribute,
                        operation: AttributeOperation::Get,
                    });
                }
            }
        }

        let effective = self.effective_supported_attributes(values)?;
        let mut result = AttributeEncoder::new();
        for attribute in attribute_numbers(requested) {
            let Some(definition) = attribute_definition(attribute) else {
                continue;
            };
            if !bitmap_contains(&effective, attribute) {
                continue;
            }
            let automatic;
            let value = if attribute == FATTR4_SUPPORTED_ATTRS {
                automatic = AttributeValue::Bitmap(effective.clone());
                &automatic
            } else {
                values.get(attribute).ok_or(AttributeError::MissingValue(attribute))?
            };
            validate_value(definition, value)?;
            let encoded = encode_value(value)?;
            result.push_raw_xdr(attribute, &encoded)?;
        }
        Ok(result.finish())
    }

    /// Encodes the special per-entry READDIR failure form. RFC 7530 permits
    /// this single attribute even when the other REQUIRED values could not be
    /// fetched.
    pub fn encode_rdattr_error(&self, status: NfsStatus) -> Result<FileAttributes, AttributeError> {
        let mut result = AttributeEncoder::new();
        result.push_status(FATTR4_RDATTR_ERROR, status)?;
        Ok(result.finish())
    }

    /// Decodes and validates SETATTR values, retaining protocol-only fields
    /// alongside the subset directly accepted by the VFS.
    pub fn decode_setattr(&self, attributes: &FileAttributes) -> Result<DecodedSetAttributes, AttributeError> {
        validate_request_bitmap(&attributes.mask)?;
        let mut decoder = crate::rpc::codec::Decoder::new(&attributes.values);
        let mut result = DecodedSetAttributes {
            requested: canonical_bitmap(&attributes.mask),
            ..DecodedSetAttributes::default()
        };

        for attribute in attribute_numbers(&attributes.mask) {
            let definition = attribute_definition(attribute).ok_or(AttributeError::UnsupportedAttribute(attribute))?;
            if !definition.access.is_writable() {
                return Err(AttributeError::InvalidAccess {
                    attribute,
                    operation: AttributeOperation::Set,
                });
            }
            if !bitmap_contains(&self.supported, attribute) {
                return Err(AttributeError::UnsupportedAttribute(attribute));
            }
            let value = decode_value(definition, &mut decoder)?;
            result.apply(attribute, value)?;
        }
        decoder.finish()?;
        Ok(result)
    }

    /// Compares a canonical decoded VERIFY/NVERIFY `fattr4` against current
    /// values. Unsupported attributes are errors rather than omissions.
    pub fn compare(&self, expected: &FileAttributes, current: &AttributeValues) -> Result<bool, AttributeError> {
        validate_request_bitmap(&expected.mask)?;
        let effective = self.effective_supported_attributes(current)?;
        let mut decoder = crate::rpc::codec::Decoder::new(&expected.values);
        let mut matches = true;

        for attribute in attribute_numbers(&expected.mask) {
            let definition = attribute_definition(attribute).ok_or(AttributeError::UnsupportedAttribute(attribute))?;
            if !definition.access.is_readable() || attribute == FATTR4_RDATTR_ERROR {
                return Err(AttributeError::InvalidAccess {
                    attribute,
                    operation: AttributeOperation::Verify,
                });
            }
            if !bitmap_contains(&effective, attribute) {
                return Err(AttributeError::UnsupportedAttribute(attribute));
            }
            let expected_value = decode_value(definition, &mut decoder)?;
            let automatic;
            let current_value = if attribute == FATTR4_SUPPORTED_ATTRS {
                automatic = AttributeValue::Bitmap(effective.clone());
                &automatic
            } else {
                current.get(attribute).ok_or(AttributeError::MissingValue(attribute))?
            };
            matches &= expected_value == *current_value;
        }
        decoder.finish()?;
        Ok(matches)
    }

    pub fn verify_status(&self, expected: &FileAttributes, current: &AttributeValues) -> NfsStatus {
        match self.compare(expected, current) {
            Ok(true) => NfsStatus::Ok,
            Ok(false) => NfsStatus::NotSame,
            Err(error) => error.status(),
        }
    }

    pub fn nverify_status(&self, expected: &FileAttributes, current: &AttributeValues) -> NfsStatus {
        match self.compare(expected, current) {
            Ok(true) => NfsStatus::Same,
            Ok(false) => NfsStatus::Ok,
            Err(error) => error.status(),
        }
    }

    fn validate_required_values(&self, values: &AttributeValues) -> Result<(), AttributeError> {
        for definition in ATTRIBUTE_DEFINITIONS
            .iter()
            .filter(|definition| definition.requirement == AttributeRequirement::Required)
        {
            if definition.id != FATTR4_SUPPORTED_ATTRS && !values.contains(definition.id) {
                return Err(AttributeError::MissingValue(definition.id));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DecodedSetAttributes {
    pub requested: Bitmap,
    pub vfs: VfsSetAttributes,
    pub acl: Option<Vec<NfsAce>>,
    pub archive: Option<bool>,
    pub hidden: Option<bool>,
    pub mimetype: Option<Vec<u8>>,
    pub owner: Option<Vec<u8>>,
    pub owner_group: Option<Vec<u8>>,
    pub system: Option<bool>,
    pub backup_time: Option<NfsTime>,
    pub create_time: Option<NfsTime>,
}

impl DecodedSetAttributes {
    fn apply(&mut self, attribute: u32, value: AttributeValue) -> Result<(), AttributeError> {
        match (attribute, value) {
            (FATTR4_SIZE, AttributeValue::U64(value)) => self.vfs.size = Some(value),
            (FATTR4_ACL, AttributeValue::Acl(value)) => self.acl = Some(value),
            (FATTR4_ARCHIVE, AttributeValue::Boolean(value)) => self.archive = Some(value),
            (FATTR4_HIDDEN, AttributeValue::Boolean(value)) => self.hidden = Some(value),
            (FATTR4_MIMETYPE, AttributeValue::String(value)) => self.mimetype = Some(value),
            (FATTR4_MODE, AttributeValue::U32(value)) => self.vfs.mode = Some(value),
            (FATTR4_OWNER, AttributeValue::String(value)) => self.owner = Some(value),
            (FATTR4_OWNER_GROUP, AttributeValue::String(value)) => self.owner_group = Some(value),
            (FATTR4_SYSTEM, AttributeValue::Boolean(value)) => self.system = Some(value),
            (FATTR4_TIME_ACCESS_SET, AttributeValue::SetTime(value)) => {
                self.vfs.access_time = Some(map_set_time(value));
            },
            (FATTR4_TIME_BACKUP, AttributeValue::Time(value)) => self.backup_time = Some(value),
            (FATTR4_TIME_CREATE, AttributeValue::Time(value)) => self.create_time = Some(value),
            (FATTR4_TIME_MODIFY_SET, AttributeValue::SetTime(value)) => {
                self.vfs.modify_time = Some(map_set_time(value));
            },
            (attribute, _) => return Err(AttributeError::ValueTypeMismatch(attribute)),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeOperation {
    Get,
    Set,
    Verify,
}

#[derive(Debug, thiserror::Error)]
pub enum AttributeError {
    #[error("unknown NFSv4.0 attribute {0}")]
    UnknownAttribute(u32),
    #[error("REQUIRED attribute {0} is not advertised")]
    MissingRequiredSupport(u32),
    #[error("attribute {0} is not supported for this object")]
    UnsupportedAttribute(u32),
    #[error("attribute {attribute} is not valid for {operation:?}")]
    InvalidAccess {
        attribute: u32,
        operation: AttributeOperation,
    },
    #[error("no value was supplied for advertised attribute {0}")]
    MissingValue(u32),
    #[error("attribute {0} has the wrong value representation")]
    ValueTypeMismatch(u32),
    #[error("mode attribute contains bits outside 0x0fff: {0:#x}")]
    InvalidMode(u32),
    #[error("NFS time nanoseconds value {0} is greater than 999999999")]
    InvalidNanoseconds(u32),
    #[error("ACL entry has unknown ACE type {0}")]
    InvalidAceType(u32),
    #[error("attribute {0} contains invalid UTF-8")]
    InvalidUtf8(u32),
    #[error("attribute {0} contains non-ASCII MIME data")]
    InvalidAscii(u32),
    #[error("attribute bitmap contains {actual} words; limit is {limit}")]
    BitmapTooLarge { actual: usize, limit: usize },
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] AttributeEncodeError),
}

impl AttributeError {
    pub const fn status(&self) -> NfsStatus {
        match self {
            Self::UnknownAttribute(_) | Self::UnsupportedAttribute(_) => NfsStatus::AttributeNotSupported,
            Self::InvalidAccess { .. }
            | Self::InvalidMode(_)
            | Self::InvalidNanoseconds(_)
            | Self::InvalidAceType(_)
            | Self::InvalidAscii(_) => NfsStatus::Invalid,
            Self::InvalidUtf8(_) => NfsStatus::BadCharacter,
            Self::Decode(_) | Self::BitmapTooLarge { .. } => NfsStatus::BadXdr,
            Self::MissingRequiredSupport(_) | Self::MissingValue(_) | Self::ValueTypeMismatch(_) | Self::Encode(_) => {
                NfsStatus::ServerFault
            },
        }
    }
}

fn validate_request_bitmap(bitmap: &[u32]) -> Result<(), AttributeError> {
    if bitmap.len() > MAX_REQUEST_BITMAP_WORDS {
        Err(AttributeError::BitmapTooLarge {
            actual: bitmap.len(),
            limit: MAX_REQUEST_BITMAP_WORDS,
        })
    } else {
        Ok(())
    }
}

fn validate_value(definition: &AttributeDefinition, value: &AttributeValue) -> Result<(), AttributeError> {
    if definition.wire_type != value.wire_type() {
        return Err(AttributeError::ValueTypeMismatch(definition.id));
    }
    match value {
        AttributeValue::Bitmap(bitmap) => validate_request_bitmap(bitmap)?,
        AttributeValue::U32(mode) if definition.id == FATTR4_MODE && mode & !MODE4_MASK != 0 => {
            return Err(AttributeError::InvalidMode(*mode));
        },
        AttributeValue::FileHandle(handle) if handle.as_bytes().len() > NFS4_FHSIZE => {
            return Err(AttributeError::Decode(DecodeError::LimitExceeded {
                field: "NFSv4 filehandle",
                actual: handle.as_bytes().len(),
                limit: NFS4_FHSIZE,
            }));
        },
        AttributeValue::Acl(acl) => validate_acl(definition.id, acl)?,
        AttributeValue::FsLocations(locations) => validate_fs_locations(definition.id, locations)?,
        AttributeValue::String(value) => validate_string(definition.id, value)?,
        AttributeValue::Time(time) => validate_time(*time)?,
        AttributeValue::SetTime(SetTime::Client(time)) => validate_time(*time)?,
        _ => {},
    }
    Ok(())
}

fn validate_acl(attribute: u32, acl: &[NfsAce]) -> Result<(), AttributeError> {
    if acl.len() > MAX_COLLECTION_ITEMS {
        return Err(AttributeError::Decode(DecodeError::LimitExceeded {
            field: "NFSv4 ACL",
            actual: acl.len(),
            limit: MAX_COLLECTION_ITEMS,
        }));
    }
    for ace in acl {
        if ace.ace_type > 3 {
            return Err(AttributeError::InvalidAceType(ace.ace_type));
        }
        validate_bounded_utf8(attribute, "NFSv4 ACE who", &ace.who)?;
    }
    Ok(())
}

fn validate_fs_locations(attribute: u32, locations: &FsLocations) -> Result<(), AttributeError> {
    validate_path(attribute, &locations.file_system_root)?;
    if locations.locations.len() > MAX_COLLECTION_ITEMS {
        return Err(AttributeError::Decode(DecodeError::LimitExceeded {
            field: "NFSv4 filesystem locations",
            actual: locations.locations.len(),
            limit: MAX_COLLECTION_ITEMS,
        }));
    }
    for location in &locations.locations {
        if location.servers.len() > MAX_COLLECTION_ITEMS {
            return Err(AttributeError::Decode(DecodeError::LimitExceeded {
                field: "NFSv4 filesystem-location servers",
                actual: location.servers.len(),
                limit: MAX_COLLECTION_ITEMS,
            }));
        }
        for server in &location.servers {
            validate_bounded_utf8(attribute, "NFSv4 filesystem-location server", server)?;
        }
        validate_path(attribute, &location.root_path)?;
    }
    Ok(())
}

fn validate_path(attribute: u32, path: &[Vec<u8>]) -> Result<(), AttributeError> {
    if path.len() > MAX_COLLECTION_ITEMS {
        return Err(AttributeError::Decode(DecodeError::LimitExceeded {
            field: "NFSv4 pathname",
            actual: path.len(),
            limit: MAX_COLLECTION_ITEMS,
        }));
    }
    for component in path {
        validate_bounded_utf8(attribute, "NFSv4 pathname component", component)?;
    }
    Ok(())
}

fn validate_string(attribute: u32, value: &[u8]) -> Result<(), AttributeError> {
    if value.len() > NFS4_OPAQUE_LIMIT {
        return Err(AttributeError::Decode(DecodeError::LimitExceeded {
            field: "NFSv4 attribute string",
            actual: value.len(),
            limit: NFS4_OPAQUE_LIMIT,
        }));
    }
    if attribute == FATTR4_MIMETYPE {
        if !value.is_ascii() {
            return Err(AttributeError::InvalidAscii(attribute));
        }
    } else {
        validate_utf8(attribute, value)?;
    }
    Ok(())
}

fn validate_bounded_utf8(attribute: u32, field: &'static str, value: &[u8]) -> Result<(), AttributeError> {
    if value.len() > NFS4_OPAQUE_LIMIT {
        return Err(AttributeError::Decode(DecodeError::LimitExceeded {
            field,
            actual: value.len(),
            limit: NFS4_OPAQUE_LIMIT,
        }));
    }
    validate_utf8(attribute, value)
}

fn validate_utf8(attribute: u32, value: &[u8]) -> Result<(), AttributeError> {
    std::str::from_utf8(value)
        .map(|_| ())
        .map_err(|_| AttributeError::InvalidUtf8(attribute))
}

fn validate_time(time: NfsTime) -> Result<(), AttributeError> {
    if time.nanoseconds > 999_999_999 {
        Err(AttributeError::InvalidNanoseconds(time.nanoseconds))
    } else {
        Ok(())
    }
}

fn encode_value(value: &AttributeValue) -> Result<Vec<u8>, AttributeError> {
    let mut encoder = Encoder::new();
    match value {
        AttributeValue::Bitmap(bitmap) => {
            let bitmap = canonical_bitmap(bitmap);
            write_count(&mut encoder, bitmap.len())?;
            for word in bitmap {
                encoder.write_u32(word);
            }
        },
        AttributeValue::FileType(value) => encoder.write_u32(value.code()),
        AttributeValue::U32(value) => encoder.write_u32(*value),
        AttributeValue::U64(value) => encoder.write_u64(*value),
        AttributeValue::Boolean(value) => encoder.write_bool(*value),
        AttributeValue::FsId(value) => {
            encoder.write_u64(value.major);
            encoder.write_u64(value.minor);
        },
        AttributeValue::Status(value) => encoder.write_u32(value.code()),
        AttributeValue::FileHandle(value) => {
            encoder.write_opaque(value.as_bytes()).map_err(AttributeEncodeError::from)?
        },
        AttributeValue::Acl(value) => {
            write_count(&mut encoder, value.len())?;
            for ace in value {
                encoder.write_u32(ace.ace_type);
                encoder.write_u32(ace.flags);
                encoder.write_u32(ace.access_mask);
                encoder.write_opaque(&ace.who).map_err(AttributeEncodeError::from)?;
            }
        },
        AttributeValue::FsLocations(value) => encode_fs_locations(&mut encoder, value)?,
        AttributeValue::String(value) => encoder.write_opaque(value).map_err(AttributeEncodeError::from)?,
        AttributeValue::SpecData(value) => {
            encoder.write_u32(value.major);
            encoder.write_u32(value.minor);
        },
        AttributeValue::Time(value) => encode_time(&mut encoder, *value),
        AttributeValue::SetTime(value) => match value {
            SetTime::Server => encoder.write_u32(0),
            SetTime::Client(time) => {
                encoder.write_u32(1);
                encode_time(&mut encoder, *time);
            },
        },
    }
    Ok(encoder.into_bytes())
}

fn write_count(encoder: &mut Encoder, count: usize) -> Result<(), AttributeError> {
    let count = u32::try_from(count)
        .map_err(|_| AttributeError::Encode(AttributeEncodeError::Xdr(EncodeError::TooLarge(count))))?;
    encoder.write_u32(count);
    Ok(())
}

fn encode_time(encoder: &mut Encoder, time: NfsTime) {
    encoder.write_u64(time.seconds as u64);
    encoder.write_u32(time.nanoseconds);
}

fn encode_path(encoder: &mut Encoder, path: &[Vec<u8>]) -> Result<(), AttributeError> {
    write_count(encoder, path.len())?;
    for component in path {
        encoder.write_opaque(component).map_err(AttributeEncodeError::from)?;
    }
    Ok(())
}

fn encode_fs_locations(encoder: &mut Encoder, locations: &FsLocations) -> Result<(), AttributeError> {
    encode_path(encoder, &locations.file_system_root)?;
    write_count(encoder, locations.locations.len())?;
    for location in &locations.locations {
        write_count(encoder, location.servers.len())?;
        for server in &location.servers {
            encoder.write_opaque(server).map_err(AttributeEncodeError::from)?;
        }
        encode_path(encoder, &location.root_path)?;
    }
    Ok(())
}

fn decode_value(
    definition: &AttributeDefinition,
    decoder: &mut crate::rpc::codec::Decoder<'_>,
) -> Result<AttributeValue, AttributeError> {
    let value = match definition.wire_type {
        AttributeWireType::Bitmap => {
            let mut bitmap =
                decoder.read_array("NFSv4 attribute bitmap", MAX_REQUEST_BITMAP_WORDS, |decoder| decoder.read_u32())?;
            canonicalize_bitmap(&mut bitmap);
            AttributeValue::Bitmap(bitmap)
        },
        AttributeWireType::FileType => {
            AttributeValue::FileType(decoder.read_enum("NFSv4 file type", NfsFileType::from_code)?)
        },
        AttributeWireType::U32 => AttributeValue::U32(decoder.read_u32()?),
        AttributeWireType::U64 => AttributeValue::U64(decoder.read_u64()?),
        AttributeWireType::Boolean => AttributeValue::Boolean(decoder.read_bool()?),
        AttributeWireType::FsId => AttributeValue::FsId(FsId {
            major: decoder.read_u64()?,
            minor: decoder.read_u64()?,
        }),
        AttributeWireType::Status => AttributeValue::Status(decoder.read_enum("NFSv4 status", NfsStatus::from_code)?),
        AttributeWireType::FileHandle => {
            AttributeValue::FileHandle(NfsFileHandle(decoder.read_opaque("NFSv4 filehandle", NFS4_FHSIZE)?))
        },
        AttributeWireType::Acl => {
            AttributeValue::Acl(decoder.read_array("NFSv4 ACL", MAX_COLLECTION_ITEMS, |decoder| {
                Ok(NfsAce {
                    ace_type: decoder.read_u32()?,
                    flags: decoder.read_u32()?,
                    access_mask: decoder.read_u32()?,
                    who: decoder.read_string("NFSv4 ACE who", NFS4_OPAQUE_LIMIT)?,
                })
            })?)
        },
        AttributeWireType::FsLocations => AttributeValue::FsLocations(decode_fs_locations(decoder)?),
        AttributeWireType::String => {
            AttributeValue::String(decoder.read_string("NFSv4 attribute string", NFS4_OPAQUE_LIMIT)?)
        },
        AttributeWireType::SpecData => AttributeValue::SpecData(SpecData {
            major: decoder.read_u32()?,
            minor: decoder.read_u32()?,
        }),
        AttributeWireType::Time => AttributeValue::Time(decode_time(decoder)?),
        AttributeWireType::SetTime => {
            let set_time = match decoder.read_u32()? {
                0 => SetTime::Server,
                1 => SetTime::Client(decode_time(decoder)?),
                value => {
                    return Err(AttributeError::Decode(DecodeError::InvalidDiscriminant {
                        kind: "NFSv4 set-time mode",
                        value,
                    }));
                },
            };
            AttributeValue::SetTime(set_time)
        },
    };
    validate_value(definition, &value)?;
    Ok(value)
}

fn decode_time(decoder: &mut crate::rpc::codec::Decoder<'_>) -> Result<NfsTime, DecodeError> {
    Ok(NfsTime {
        seconds: decoder.read_u64()? as i64,
        nanoseconds: decoder.read_u32()?,
    })
}

fn decode_path(decoder: &mut crate::rpc::codec::Decoder<'_>) -> Result<Vec<Vec<u8>>, DecodeError> {
    decoder.read_array("NFSv4 pathname", MAX_COLLECTION_ITEMS, |decoder| {
        decoder.read_string("NFSv4 pathname component", NFS4_OPAQUE_LIMIT)
    })
}

fn decode_fs_locations(decoder: &mut crate::rpc::codec::Decoder<'_>) -> Result<FsLocations, DecodeError> {
    let file_system_root = decode_path(decoder)?;
    let locations = decoder.read_array("NFSv4 filesystem locations", MAX_COLLECTION_ITEMS, |decoder| {
        let servers = decoder.read_array("NFSv4 filesystem-location servers", MAX_COLLECTION_ITEMS, |decoder| {
            decoder.read_string("NFSv4 filesystem-location server", NFS4_OPAQUE_LIMIT)
        })?;
        Ok(FsLocation {
            servers,
            root_path: decode_path(decoder)?,
        })
    })?;
    Ok(FsLocations {
        file_system_root,
        locations,
    })
}

fn attribute_numbers(bitmap: &[u32]) -> impl Iterator<Item = u32> + '_ {
    bitmap.iter().enumerate().flat_map(|(word_index, word)| {
        let base = u32::try_from(word_index).unwrap_or(u32::MAX).saturating_mul(32);
        (0..32).filter_map(move |bit| (word & (1 << bit) != 0).then_some(base.saturating_add(bit)))
    })
}

fn first_unknown_attribute(bitmap: &[u32]) -> Option<u32> {
    attribute_numbers(bitmap).find(|attribute| attribute_definition(*attribute).is_none())
}

fn canonical_bitmap(bitmap: &[u32]) -> Bitmap {
    let mut result = bitmap.to_vec();
    canonicalize_bitmap(&mut result);
    result
}

fn canonicalize_bitmap(bitmap: &mut Bitmap) {
    while bitmap.last() == Some(&0) {
        bitmap.pop();
    }
}

fn clear_bitmap_attribute(bitmap: &mut Bitmap, attribute: u32) {
    if let Some(word) = bitmap.get_mut((attribute / 32) as usize) {
        *word &= !(1 << (attribute % 32));
    }
}

fn map_file_type(file_type: FileType) -> NfsFileType {
    match file_type {
        FileType::Regular => NfsFileType::Regular,
        FileType::Directory => NfsFileType::Directory,
        FileType::BlockDevice => NfsFileType::Block,
        FileType::CharacterDevice => NfsFileType::Character,
        FileType::Symlink => NfsFileType::Symlink,
        FileType::Socket => NfsFileType::Socket,
        FileType::Fifo => NfsFileType::Fifo,
        FileType::AttributeDirectory => NfsFileType::AttributeDirectory,
        FileType::NamedAttribute => NfsFileType::NamedAttribute,
    }
}

fn map_time(time: crate::vfs::NfsTime) -> NfsTime {
    NfsTime {
        seconds: time.seconds,
        nanoseconds: time.nanoseconds,
    }
}

fn map_set_time(time: SetTime) -> VfsSetTime {
    match time {
        SetTime::Server => VfsSetTime::ServerTime,
        SetTime::Client(time) => VfsSetTime::ClientTime(crate::vfs::NfsTime {
            seconds: time.seconds,
            nanoseconds: time.nanoseconds,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{ChangeId, DeviceNumber, Nfs4FsLocation};

    fn support_with(optional: &[u32]) -> AttributeEngine {
        AttributeEngine::from_attributes(
            ATTRIBUTE_DEFINITIONS
                .iter()
                .filter(|definition| definition.requirement == AttributeRequirement::Required)
                .map(|definition| definition.id)
                .chain(optional.iter().copied()),
        )
        .unwrap()
    }

    fn backend_values() -> AttributeValues {
        AttributeValues::from_vfs(
            &VfsFileAttributes {
                file_type: FileType::Regular,
                mode: 0o640,
                links: 2,
                uid: 1000,
                gid: 100,
                size: 0x0102_0304_0506_0708,
                used: 8192,
                device: Some(DeviceNumber { major: 8, minor: 1 }),
                fs_id: 7,
                file_id: 99,
                change_id: ChangeId(44),
                access_time: crate::vfs::NfsTime {
                    seconds: -2,
                    nanoseconds: 3,
                },
                modify_time: crate::vfs::NfsTime {
                    seconds: 4,
                    nanoseconds: 5,
                },
                change_time: crate::vfs::NfsTime {
                    seconds: 6,
                    nanoseconds: 7,
                },
            },
            NfsFileHandle(vec![0xaa, 0xbb]),
            FsId { major: 9, minor: 7 },
            VfsCapabilities::READ_WRITE,
            90,
        )
        .unwrap()
    }

    #[test]
    fn metadata_covers_every_v4_0_attribute_once() {
        assert_eq!(ATTRIBUTE_DEFINITIONS.len(), 56);
        for (id, definition) in ATTRIBUTE_DEFINITIONS.iter().enumerate() {
            assert_eq!(definition.id, id as u32);
        }
        let required: Vec<_> = ATTRIBUTE_DEFINITIONS
            .iter()
            .filter(|definition| definition.requirement == AttributeRequirement::Required)
            .map(|definition| definition.id)
            .collect();
        assert_eq!(required, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 19]);
        assert_eq!(attribute_definition(48).unwrap().access, AttributeAccess::WriteOnly);
        assert_eq!(attribute_definition(54).unwrap().scope, AttributeScope::SetOnly);
        assert!(attribute_definition(56).is_none());
    }

    #[test]
    fn support_bitmap_requires_every_mandatory_attribute() {
        let mut required = required_attribute_bitmap();
        clear_bitmap_attribute(&mut required, FATTR4_FILEHANDLE);
        assert!(matches!(
            AttributeEngine::new(required),
            Err(AttributeError::MissingRequiredSupport(FATTR4_FILEHANDLE))
        ));

        let mut unknown = required_attribute_bitmap();
        unknown.resize(2, 0);
        unknown[1] |= 1 << 31;
        assert!(matches!(AttributeEngine::new(unknown), Err(AttributeError::UnknownAttribute(63))));
    }

    #[test]
    fn getattr_requires_values_for_every_mandatory_attribute() {
        let engine = support_with(&[]);
        let mut values = backend_values();
        values.remove(FATTR4_FILEHANDLE);
        let requested = bitmap_from_attributes([FATTR4_SIZE]).unwrap();
        assert!(matches!(
            engine.encode_getattr(&requested, &values),
            Err(AttributeError::MissingValue(FATTR4_FILEHANDLE))
        ));
    }

    #[test]
    fn getattr_is_ordered_exact_wire_and_omits_unsupported_recommended() {
        let engine = support_with(&[FATTR4_MODE, FATTR4_TIME_ACCESS, FATTR4_MOUNTED_ON_FILEID]);
        let values = backend_values();
        let requested = bitmap_from_attributes([
            FATTR4_SUPPORTED_ATTRS,
            FATTR4_TYPE,
            FATTR4_SIZE,
            FATTR4_HIDDEN,
            FATTR4_MODE,
            FATTR4_TIME_ACCESS,
            FATTR4_MOUNTED_ON_FILEID,
        ])
        .unwrap();
        let encoded = engine.encode_getattr(&requested, &values).unwrap();

        assert_eq!(encoded.mask, vec![0x0000_0013, 0x0080_8002]);
        assert_eq!(
            encoded.values,
            vec![
                0, 0, 0, 2, 0, 8, 15, 255, 0, 128, 128, 2, // supported_attrs
                0, 0, 0, 1, // type
                1, 2, 3, 4, 5, 6, 7, 8, // size
                0, 0, 1, 160, // mode
                255, 255, 255, 255, 255, 255, 255, 254, 0, 0, 0, 3, // signed access time
                0, 0, 0, 0, 0, 0, 0, 99, // mounted_on_fileid
            ]
        );
        assert!(!bitmap_contains(&encoded.mask, FATTR4_HIDDEN));
    }

    #[test]
    fn getattr_rejects_write_only_attribute() {
        let engine = support_with(&[FATTR4_TIME_ACCESS_SET]);
        let requested = bitmap_from_attributes([FATTR4_TIME_ACCESS_SET]).unwrap();
        let error = engine.encode_getattr(&requested, &backend_values()).unwrap_err();
        assert!(matches!(
            error,
            AttributeError::InvalidAccess {
                attribute: FATTR4_TIME_ACCESS_SET,
                operation: AttributeOperation::Get
            }
        ));
        assert_eq!(error.status(), NfsStatus::Invalid);
    }

    #[test]
    fn rdattr_error_can_be_encoded_without_other_mandatory_values() {
        let encoded = support_with(&[]).encode_rdattr_error(NfsStatus::Moved).unwrap();
        assert_eq!(encoded.mask, vec![1 << FATTR4_RDATTR_ERROR]);
        assert_eq!(encoded.values, 10019u32.to_be_bytes().to_vec());
    }

    #[test]
    fn setattr_decodes_writable_values_and_signed_client_time() {
        let engine = support_with(&[
            FATTR4_MODE,
            FATTR4_OWNER,
            FATTR4_TIME_ACCESS_SET,
            FATTR4_TIME_MODIFY_SET,
        ]);
        let mask = bitmap_from_attributes([
            FATTR4_SIZE,
            FATTR4_MODE,
            FATTR4_OWNER,
            FATTR4_TIME_ACCESS_SET,
            FATTR4_TIME_MODIFY_SET,
        ])
        .unwrap();
        let attributes = FileAttributes {
            mask: mask.clone(),
            values: vec![
                0, 0, 0, 0, 0, 0, 0, 12, // size
                0, 0, 1, 164, // mode 0644
                0, 0, 0, 3, b'b', b'o', b'b', 0, // owner
                0, 0, 0, 0, // access: server time
                0, 0, 0, 1, // modify: client time
                255, 255, 255, 255, 255, 255, 255, 255, // -1 second
                0, 0, 0, 9,
            ],
        };
        let decoded = engine.decode_setattr(&attributes).unwrap();
        assert_eq!(decoded.requested, mask);
        assert_eq!(decoded.vfs.size, Some(12));
        assert_eq!(decoded.vfs.mode, Some(0o644));
        assert_eq!(decoded.owner.as_deref(), Some(b"bob".as_slice()));
        assert_eq!(decoded.vfs.access_time, Some(VfsSetTime::ServerTime));
        assert_eq!(
            decoded.vfs.modify_time,
            Some(VfsSetTime::ClientTime(crate::vfs::NfsTime {
                seconds: -1,
                nanoseconds: 9
            }))
        );
    }

    #[test]
    fn setattr_rejects_read_only_and_illegal_mode() {
        let engine = support_with(&[FATTR4_MODE]);
        let read_only = FileAttributes {
            mask: bitmap_from_attributes([FATTR4_TYPE]).unwrap(),
            values: 1u32.to_be_bytes().to_vec(),
        };
        let error = engine.decode_setattr(&read_only).unwrap_err();
        assert_eq!(error.status(), NfsStatus::Invalid);

        let illegal_mode = FileAttributes {
            mask: bitmap_from_attributes([FATTR4_MODE]).unwrap(),
            values: 0x1000u32.to_be_bytes().to_vec(),
        };
        assert!(matches!(engine.decode_setattr(&illegal_mode), Err(AttributeError::InvalidMode(0x1000))));
    }

    #[test]
    fn canonical_decoder_rejects_bad_boolean_padding_and_trailing_data() {
        let engine = support_with(&[FATTR4_ARCHIVE, FATTR4_OWNER]);
        let bad_boolean = FileAttributes {
            mask: bitmap_from_attributes([FATTR4_ARCHIVE]).unwrap(),
            values: 2u32.to_be_bytes().to_vec(),
        };
        assert_eq!(engine.decode_setattr(&bad_boolean).unwrap_err().status(), NfsStatus::BadXdr);

        let bad_padding = FileAttributes {
            mask: bitmap_from_attributes([FATTR4_OWNER]).unwrap(),
            values: vec![0, 0, 0, 1, b'x', 0, 1, 0],
        };
        assert_eq!(engine.decode_setattr(&bad_padding).unwrap_err().status(), NfsStatus::BadXdr);

        let trailing = FileAttributes {
            mask: bitmap_from_attributes([FATTR4_SIZE]).unwrap(),
            values: vec![0; 12],
        };
        assert_eq!(engine.decode_setattr(&trailing).unwrap_err().status(), NfsStatus::BadXdr);
    }

    #[test]
    fn verify_and_nverify_compare_decoded_values() {
        let engine = support_with(&[FATTR4_MODE, FATTR4_TIME_ACCESS]);
        let values = backend_values();
        let mask = bitmap_from_attributes([FATTR4_MODE, FATTR4_TIME_ACCESS]).unwrap();
        let expected = engine.encode_getattr(&mask, &values).unwrap();
        assert_eq!(engine.verify_status(&expected, &values), NfsStatus::Ok);
        assert_eq!(engine.nverify_status(&expected, &values), NfsStatus::Same);

        let mut different = expected.clone();
        different.values[3] ^= 1;
        assert_eq!(engine.verify_status(&different, &values), NfsStatus::NotSame);
        assert_eq!(engine.nverify_status(&different, &values), NfsStatus::Ok);

        let rdattr = FileAttributes {
            mask: bitmap_from_attributes([FATTR4_RDATTR_ERROR]).unwrap(),
            values: 0u32.to_be_bytes().to_vec(),
        };
        assert_eq!(engine.verify_status(&rdattr, &values), NfsStatus::Invalid);
    }

    #[test]
    fn acl_locations_and_quota_have_canonical_representations() {
        let engine = support_with(&[
            FATTR4_ACL,
            FATTR4_FS_LOCATIONS,
            FATTR4_QUOTA_AVAIL_HARD,
            FATTR4_QUOTA_AVAIL_SOFT,
            FATTR4_QUOTA_USED,
        ]);
        let mut values = backend_values();
        values
            .insert(
                FATTR4_ACL,
                AttributeValue::Acl(vec![NfsAce {
                    ace_type: 0,
                    flags: 1,
                    access_mask: 0x0012_0089,
                    who: b"OWNER@".to_vec(),
                }]),
            )
            .unwrap();
        values
            .apply_fs_locations(&Nfs4FsLocations {
                fs_root: vec!["export".into()],
                locations: vec![Nfs4FsLocation {
                    servers: vec!["nfs.example".into()],
                    root_path: vec!["new".into(), "export".into()],
                }],
            })
            .unwrap();
        values
            .apply_quota(QuotaAttributes {
                available_hard: 100,
                available_soft: 80,
                used: 20,
            })
            .unwrap();

        let mask = bitmap_from_attributes([
            FATTR4_ACL,
            FATTR4_FS_LOCATIONS,
            FATTR4_QUOTA_AVAIL_HARD,
            FATTR4_QUOTA_AVAIL_SOFT,
            FATTR4_QUOTA_USED,
        ])
        .unwrap();
        let encoded = engine.encode_getattr(&mask, &values).unwrap();
        assert!(engine.compare(&encoded, &values).unwrap());
        assert_eq!(
            &encoded.values[..24],
            &[
                0, 0, 0, 1, // one ACE
                0, 0, 0, 0, // ALLOW
                0, 0, 0, 1, // flags
                0, 18, 0, 137, // mask
                0, 0, 0, 6, b'O', b'W', b'N', b'E',
            ]
        );
    }

    #[test]
    fn vfs_stat_info_and_pathconf_populate_matching_wire_types() {
        let mut values = backend_values();
        values
            .apply_fs_stat(&FsStat {
                total_bytes: 1000,
                free_bytes: 600,
                available_bytes: 500,
                total_files: 100,
                free_files: 60,
                available_files: 50,
                invariant_seconds: 1,
            })
            .unwrap();
        values
            .apply_fs_info(&FsInfo {
                max_read: 4096,
                preferred_read: 4096,
                read_multiple: 1,
                max_write: 8192,
                preferred_write: 8192,
                write_multiple: 1,
                preferred_readdir: 4096,
                max_file_size: u64::MAX,
                time_granularity: crate::vfs::NfsTime {
                    seconds: 0,
                    nanoseconds: 1,
                },
            })
            .unwrap();
        values
            .apply_path_conf(&PathConf {
                max_links: 32000,
                max_name_length: 255,
                no_truncation: true,
                chown_restricted: true,
                case_insensitive: false,
                case_preserving: true,
            })
            .unwrap();

        assert_eq!(values.get(FATTR4_SPACE_AVAIL), Some(&AttributeValue::U64(500)));
        assert_eq!(values.get(FATTR4_MAXREAD), Some(&AttributeValue::U64(4096)));
        assert_eq!(values.get(FATTR4_MAXLINK), Some(&AttributeValue::U32(32000)));
        assert_eq!(values.get(FATTR4_NO_TRUNC), Some(&AttributeValue::Boolean(true)));
    }
}
