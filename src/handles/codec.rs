use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use crate::vfs::{ExportId, ObjectKey};

type HmacSha256 = Hmac<Sha256>;

const V3_FORMAT_VERSION: u8 = 1;
const ROUTED_FORMAT_VERSION: u8 = 2;
const INSTANCE_SIZE: usize = 8;
const TAG_SIZE: usize = 16;
const V3_PAYLOAD_SIZE: usize = 1 + INSTANCE_SIZE + 4 + 8 + 8;
const ROUTED_PAYLOAD_SIZE: usize = 1 + INSTANCE_SIZE + 1 + 4 + 8 + 8 + 8;
pub const HANDLE_SIZE: usize = V3_PAYLOAD_SIZE + TAG_SIZE;
pub const ROUTED_HANDLE_SIZE: usize = ROUTED_PAYLOAD_SIZE + TAG_SIZE;
const _: () = assert!(HANDLE_SIZE <= 64);
const _: () = assert!(ROUTED_HANDLE_SIZE <= 64);

const TARGET_BACKEND: u8 = 0;
const TARGET_PSEUDO: u8 = 1;
const NO_NAMESPACE_NODE: u64 = u64::MAX;

#[derive(Clone)]
pub struct HandleCodec {
    instance_id: [u8; INSTANCE_SIZE],
    // Keep the keyed HMAC state initialized; cloning it is cheaper than
    // rebuilding the key schedule for every handle encode or verification.
    mac: HmacSha256,
}

/// Lifetime promised for backend handles belonging to one export.
///
/// This type deliberately lives below the public server configuration so the
/// wire codec can enforce lifetime separation without depending on the server
/// module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleLifetime {
    Volatile,
    Persistent,
}

/// Authenticated codecs for one logical server and its current boot.
///
/// Pseudo-filesystem handles use the logical-server codec. Backend handles use
/// that codec only for exports which promise persistent handles; volatile
/// exports use the independently generated boot codec. Decoding authenticates
/// with both codecs and then checks the configured lifetime for the encoded
/// export, preventing a correctly signed handle from being accepted under the
/// wrong lifetime policy.
#[derive(Clone)]
pub(crate) struct HandleCodecSet {
    logical: HandleCodec,
    volatile: HandleCodec,
    exports: BTreeMap<ExportId, HandleLifetime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HandleError {
    #[error("invalid file-handle length")]
    InvalidLength,
    #[error("unsupported file-handle format")]
    InvalidFormat,
    #[error("file handle belongs to a different server instance")]
    StaleInstance,
    #[error("file handle belongs to a different export")]
    WrongExport,
    #[error("file-handle integrity check failed")]
    InvalidTag,
    #[error("file handle target kind is invalid")]
    InvalidTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleTarget {
    Backend {
        export_id: ExportId,
        object: ObjectKey,
        /// Pseudo-namespace route used to preserve nested export overlays.
        namespace_node: Option<u64>,
    },
    Pseudo {
        namespace_node: u64,
    },
}

impl HandleCodec {
    pub fn random() -> Self {
        Self::try_random().expect("operating-system random source is unavailable")
    }

    pub fn try_random() -> Result<Self, rand::Error> {
        let mut instance_id = [0; INSTANCE_SIZE];
        let mut secret = [0; 32];
        OsRng.try_fill_bytes(&mut instance_id)?;
        OsRng.try_fill_bytes(&mut secret)?;
        Ok(Self::from_key(instance_id, secret))
    }

    /// Restores a codec from stable identity material. Persisting both values
    /// makes authenticated filehandles survive restart or migration.
    pub fn from_key(instance_id: [u8; INSTANCE_SIZE], secret: [u8; 32]) -> Self {
        let mac = HmacSha256::new_from_slice(&secret).expect("HMAC accepts any key size");
        Self { instance_id, mac }
    }

    pub fn encode(&self, export_id: ExportId, object: ObjectKey) -> [u8; HANDLE_SIZE] {
        let mut handle = [0; HANDLE_SIZE];
        handle[0] = V3_FORMAT_VERSION;
        handle[1..9].copy_from_slice(&self.instance_id);
        handle[9..13].copy_from_slice(&export_id.0.to_be_bytes());
        handle[13..21].copy_from_slice(&object.file_id.to_be_bytes());
        handle[21..29].copy_from_slice(&object.generation.to_be_bytes());
        let tag = self.tag(&handle[..V3_PAYLOAD_SIZE]);
        handle[V3_PAYLOAD_SIZE..].copy_from_slice(&tag);
        handle
    }

    pub fn encode_target(&self, target: HandleTarget) -> [u8; ROUTED_HANDLE_SIZE] {
        let mut handle = [0; ROUTED_HANDLE_SIZE];
        handle[0] = ROUTED_FORMAT_VERSION;
        handle[1..9].copy_from_slice(&self.instance_id);
        match target {
            HandleTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => {
                handle[9] = TARGET_BACKEND;
                handle[10..14].copy_from_slice(&export_id.0.to_be_bytes());
                handle[14..22].copy_from_slice(&namespace_node.unwrap_or(NO_NAMESPACE_NODE).to_be_bytes());
                handle[22..30].copy_from_slice(&object.file_id.to_be_bytes());
                handle[30..38].copy_from_slice(&object.generation.to_be_bytes());
            },
            HandleTarget::Pseudo { namespace_node } => {
                handle[9] = TARGET_PSEUDO;
                handle[14..22].copy_from_slice(&namespace_node.to_be_bytes());
            },
        }
        let tag = self.tag(&handle[..ROUTED_PAYLOAD_SIZE]);
        handle[ROUTED_PAYLOAD_SIZE..].copy_from_slice(&tag);
        handle
    }

    pub fn decode(&self, export_id: ExportId, handle: &[u8]) -> Result<ObjectKey, HandleError> {
        match self.decode_target(handle)? {
            HandleTarget::Backend {
                export_id: encoded_export,
                object,
                ..
            } if encoded_export == export_id => Ok(object),
            HandleTarget::Backend { .. } => Err(HandleError::WrongExport),
            HandleTarget::Pseudo { .. } => Err(HandleError::InvalidTarget),
        }
    }

    pub fn decode_any(&self, handle: &[u8]) -> Result<(ExportId, ObjectKey), HandleError> {
        match self.decode_target(handle)? {
            HandleTarget::Backend { export_id, object, .. } => Ok((export_id, object)),
            HandleTarget::Pseudo { .. } => Err(HandleError::InvalidTarget),
        }
    }

    pub fn decode_target(&self, handle: &[u8]) -> Result<HandleTarget, HandleError> {
        match handle.first().copied() {
            Some(V3_FORMAT_VERSION) => self.decode_v3_target(handle),
            Some(ROUTED_FORMAT_VERSION) => self.decode_routed_target(handle),
            Some(_) => Err(HandleError::InvalidFormat),
            None => Err(HandleError::InvalidLength),
        }
    }

    fn decode_v3_target(&self, handle: &[u8]) -> Result<HandleTarget, HandleError> {
        if handle.len() != HANDLE_SIZE {
            return Err(HandleError::InvalidLength);
        }
        if handle[1..9] != self.instance_id {
            return Err(HandleError::StaleInstance);
        }
        let encoded_export = u32::from_be_bytes(handle[9..13].try_into().map_err(|_| HandleError::InvalidLength)?);
        let mut mac = self.mac.clone();
        mac.update(&handle[..V3_PAYLOAD_SIZE]);
        mac.verify_truncated_left(&handle[V3_PAYLOAD_SIZE..])
            .map_err(|_| HandleError::InvalidTag)?;
        let file_id = u64::from_be_bytes(handle[13..21].try_into().map_err(|_| HandleError::InvalidLength)?);
        let generation = u64::from_be_bytes(handle[21..29].try_into().map_err(|_| HandleError::InvalidLength)?);
        Ok(HandleTarget::Backend {
            export_id: ExportId(encoded_export),
            object: ObjectKey { file_id, generation },
            namespace_node: None,
        })
    }

    fn decode_routed_target(&self, handle: &[u8]) -> Result<HandleTarget, HandleError> {
        if handle.len() != ROUTED_HANDLE_SIZE {
            return Err(HandleError::InvalidLength);
        }
        if handle[1..9] != self.instance_id {
            return Err(HandleError::StaleInstance);
        }
        let mut mac = self.mac.clone();
        mac.update(&handle[..ROUTED_PAYLOAD_SIZE]);
        mac.verify_truncated_left(&handle[ROUTED_PAYLOAD_SIZE..])
            .map_err(|_| HandleError::InvalidTag)?;
        let export = ExportId(u32::from_be_bytes(handle[10..14].try_into().map_err(|_| HandleError::InvalidLength)?));
        let namespace_node = u64::from_be_bytes(handle[14..22].try_into().map_err(|_| HandleError::InvalidLength)?);
        let file_id = u64::from_be_bytes(handle[22..30].try_into().map_err(|_| HandleError::InvalidLength)?);
        let generation = u64::from_be_bytes(handle[30..38].try_into().map_err(|_| HandleError::InvalidLength)?);
        match handle[9] {
            TARGET_BACKEND => Ok(HandleTarget::Backend {
                export_id: export,
                object: ObjectKey { file_id, generation },
                namespace_node: (namespace_node != NO_NAMESPACE_NODE).then_some(namespace_node),
            }),
            TARGET_PSEUDO if export == ExportId(0) && file_id == 0 && generation == 0 => {
                Ok(HandleTarget::Pseudo { namespace_node })
            },
            _ => Err(HandleError::InvalidTarget),
        }
    }

    pub fn instance_id(&self) -> [u8; INSTANCE_SIZE] {
        self.instance_id
    }

    fn tag(&self, payload: &[u8]) -> [u8; TAG_SIZE] {
        let mut mac = self.mac.clone();
        mac.update(payload);
        let bytes = mac.finalize().into_bytes();
        let mut tag = [0; TAG_SIZE];
        tag.copy_from_slice(&bytes[..TAG_SIZE]);
        tag
    }
}

impl HandleCodecSet {
    pub(crate) fn new(
        logical: HandleCodec,
        volatile: HandleCodec,
        exports: impl IntoIterator<Item = (ExportId, HandleLifetime)>,
    ) -> Self {
        Self {
            logical,
            volatile,
            exports: exports.into_iter().collect(),
        }
    }

    pub(crate) fn encode(&self, export_id: ExportId, object: ObjectKey) -> Result<[u8; HANDLE_SIZE], HandleError> {
        Ok(self.codec_for_export(export_id)?.encode(export_id, object))
    }

    pub(crate) fn encode_target(&self, target: HandleTarget) -> Result<[u8; ROUTED_HANDLE_SIZE], HandleError> {
        let codec = match target {
            HandleTarget::Pseudo { .. } => &self.logical,
            HandleTarget::Backend { export_id, .. } => self.codec_for_export(export_id)?,
        };
        Ok(codec.encode_target(target))
    }

    pub(crate) fn decode(&self, export_id: ExportId, handle: &[u8]) -> Result<ObjectKey, HandleError> {
        match self.decode_target(handle)? {
            HandleTarget::Backend {
                export_id: encoded_export,
                object,
                ..
            } if encoded_export == export_id => Ok(object),
            HandleTarget::Backend { .. } => Err(HandleError::WrongExport),
            HandleTarget::Pseudo { .. } => Err(HandleError::InvalidTarget),
        }
    }

    pub(crate) fn decode_any(&self, handle: &[u8]) -> Result<(ExportId, ObjectKey), HandleError> {
        match self.decode_target(handle)? {
            HandleTarget::Backend { export_id, object, .. } => Ok((export_id, object)),
            HandleTarget::Pseudo { .. } => Err(HandleError::InvalidTarget),
        }
    }

    pub(crate) fn decode_target(&self, handle: &[u8]) -> Result<HandleTarget, HandleError> {
        let logical = self
            .logical
            .decode_target(handle)
            .and_then(|target| self.validate_target_lifetime(target, HandleLifetime::Persistent));
        if logical.is_ok() {
            return logical;
        }
        let volatile = self
            .volatile
            .decode_target(handle)
            .and_then(|target| self.validate_target_lifetime(target, HandleLifetime::Volatile));
        match (logical, volatile) {
            (Err(logical), Err(volatile)) => Err(prefer_handle_error(logical, volatile)),
            (_, Ok(target)) => Ok(target),
            (Ok(target), _) => Ok(target),
        }
    }

    pub(crate) fn logical_instance_id(&self) -> [u8; INSTANCE_SIZE] {
        self.logical.instance_id()
    }

    fn codec_for_export(&self, export_id: ExportId) -> Result<&HandleCodec, HandleError> {
        match self.exports.get(&export_id) {
            Some(HandleLifetime::Persistent) => Ok(&self.logical),
            Some(HandleLifetime::Volatile) => Ok(&self.volatile),
            None => Err(HandleError::WrongExport),
        }
    }

    fn validate_target_lifetime(
        &self,
        target: HandleTarget,
        authenticated_lifetime: HandleLifetime,
    ) -> Result<HandleTarget, HandleError> {
        match target {
            HandleTarget::Pseudo { .. } if authenticated_lifetime == HandleLifetime::Persistent => Ok(target),
            HandleTarget::Pseudo { .. } => Err(HandleError::InvalidTarget),
            HandleTarget::Backend { export_id, .. }
                if self.exports.get(&export_id) == Some(&authenticated_lifetime) =>
            {
                Ok(target)
            },
            HandleTarget::Backend { export_id, .. } if self.exports.contains_key(&export_id) => {
                Err(HandleError::InvalidTarget)
            },
            HandleTarget::Backend { .. } => Err(HandleError::WrongExport),
        }
    }
}

fn prefer_handle_error(left: HandleError, right: HandleError) -> HandleError {
    if handle_error_rank(left) >= handle_error_rank(right) {
        left
    } else {
        right
    }
}

const fn handle_error_rank(error: HandleError) -> u8 {
    match error {
        HandleError::InvalidTarget => 6,
        HandleError::WrongExport => 5,
        HandleError::InvalidTag => 4,
        HandleError::InvalidFormat => 3,
        HandleError::InvalidLength => 2,
        HandleError::StaleInstance => 1,
    }
}

impl std::fmt::Debug for HandleCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleCodec")
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_scope_checks() {
        let codec = HandleCodec::random();
        let key = ObjectKey {
            file_id: 42,
            generation: 7,
        };
        let handle = codec.encode(ExportId(3), key);
        assert_eq!(codec.decode(ExportId(3), &handle), Ok(key));
        assert_eq!(codec.decode(ExportId(4), &handle), Err(HandleError::WrongExport));
        assert_eq!(HandleCodec::random().decode(ExportId(3), &handle), Err(HandleError::StaleInstance));
    }

    #[test]
    fn forged_handle_is_rejected() {
        let codec = HandleCodec::random();
        let mut handle = codec.encode(
            ExportId(1),
            ObjectKey {
                file_id: 1,
                generation: 1,
            },
        );
        handle[15] ^= 1;
        assert_eq!(codec.decode(ExportId(1), &handle), Err(HandleError::InvalidTag));
    }

    #[test]
    fn every_single_byte_forgery_is_rejected() {
        let codec = HandleCodec::random();
        let handle = codec.encode(
            ExportId(9),
            ObjectKey {
                file_id: 11,
                generation: 13,
            },
        );
        for index in 0..handle.len() {
            let mut forged = handle;
            forged[index] ^= 0x80;
            assert!(codec.decode(ExportId(9), &forged).is_err(), "byte {index} was not authenticated");
        }
    }

    #[test]
    fn routed_backend_and_pseudo_handles_round_trip() {
        let codec = HandleCodec::random();
        let backend = HandleTarget::Backend {
            export_id: ExportId(4),
            object: ObjectKey {
                file_id: 8,
                generation: 9,
            },
            namespace_node: Some(12),
        };
        assert_eq!(codec.decode_target(&codec.encode_target(backend)), Ok(backend));

        let pseudo = HandleTarget::Pseudo { namespace_node: 0 };
        assert_eq!(codec.decode_target(&codec.encode_target(pseudo)), Ok(pseudo));
    }

    #[test]
    fn stable_key_preserves_handles_across_codec_reconstruction() {
        let instance = [7; INSTANCE_SIZE];
        let secret = [9; 32];
        let first = HandleCodec::from_key(instance, secret);
        let handle = first.encode_target(HandleTarget::Pseudo { namespace_node: 42 });
        let restored = HandleCodec::from_key(instance, secret);
        assert_eq!(restored.decode_target(&handle), Ok(HandleTarget::Pseudo { namespace_node: 42 }));
    }

    #[test]
    fn codec_set_separates_persistent_and_volatile_exports() {
        let logical = HandleCodec::from_key([1; 8], [2; 32]);
        let boot = HandleCodec::from_key([3; 8], [4; 32]);
        let codecs = HandleCodecSet::new(
            logical.clone(),
            boot.clone(),
            [
                (ExportId(7), HandleLifetime::Persistent),
                (ExportId(8), HandleLifetime::Volatile),
            ],
        );
        let object = ObjectKey {
            file_id: 42,
            generation: 9,
        };

        let persistent = codecs.encode(ExportId(7), object).unwrap();
        let volatile = codecs.encode(ExportId(8), object).unwrap();
        assert_eq!(codecs.decode(ExportId(7), &persistent), Ok(object));
        assert_eq!(codecs.decode(ExportId(8), &volatile), Ok(object));

        let wrongly_logical = logical.encode(ExportId(8), object);
        let wrongly_volatile = boot.encode(ExportId(7), object);
        assert_eq!(codecs.decode(ExportId(8), &wrongly_logical), Err(HandleError::InvalidTarget));
        assert_eq!(codecs.decode(ExportId(7), &wrongly_volatile), Err(HandleError::InvalidTarget));
    }

    #[test]
    fn only_volatile_handles_expire_when_boot_codec_changes() {
        let logical = HandleCodec::from_key([1; 8], [2; 32]);
        let exports = [
            (ExportId(7), HandleLifetime::Persistent),
            (ExportId(8), HandleLifetime::Volatile),
        ];
        let before = HandleCodecSet::new(logical.clone(), HandleCodec::from_key([3; 8], [4; 32]), exports);
        let object = ObjectKey {
            file_id: 42,
            generation: 9,
        };
        let persistent = before.encode(ExportId(7), object).unwrap();
        let volatile = before.encode(ExportId(8), object).unwrap();
        let pseudo = before.encode_target(HandleTarget::Pseudo { namespace_node: 11 }).unwrap();

        let after = HandleCodecSet::new(logical, HandleCodec::from_key([5; 8], [6; 32]), exports);
        assert_eq!(after.decode(ExportId(7), &persistent), Ok(object));
        assert_eq!(after.decode(ExportId(8), &volatile), Err(HandleError::StaleInstance));
        assert_eq!(after.decode_target(&pseudo), Ok(HandleTarget::Pseudo { namespace_node: 11 }));
    }
}
