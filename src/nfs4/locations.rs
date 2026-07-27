//! Bounded multi-server namespace decisions for NFSv4.0.
//!
//! This module deliberately consumes configured location and identity data. It
//! does not resolve host names, probe endpoints, or otherwise claim that a
//! location discovered through `fs_locations` is trunkable.

use std::collections::BTreeMap;

use super::attributes::bitmap_contains;
use super::types::{
    Bitmap, NfsStatus, FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_MOUNTED_ON_FILEID, FATTR4_RDATTR_ERROR,
};
use crate::vfs::{ExportId, Nfs4FsLocation, Nfs4FsLocations, Nfs4LocationState};

const ABSENT_ATTRIBUTES: [u32; 3] = [FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_MOUNTED_ON_FILEID];
const ABSENT_READDIR_ATTRIBUTES: [u32; 4] = [
    FATTR4_FSID,
    FATTR4_RDATTR_ERROR,
    FATTR4_FS_LOCATIONS,
    FATTR4_MOUNTED_ON_FILEID,
];

/// Resource limits charged while accepting configured `fs_locations` data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocationRegistryLimits {
    pub max_filesystems: usize,
    pub max_locations_per_filesystem: usize,
    pub max_servers_per_location: usize,
    pub max_path_components: usize,
    pub max_component_bytes: usize,
    pub max_server_bytes: usize,
    pub max_advertised_bytes_per_filesystem: usize,
    pub max_total_advertised_bytes: usize,
}

impl Default for LocationRegistryLimits {
    fn default() -> Self {
        Self {
            max_filesystems: 1_024,
            max_locations_per_filesystem: 64,
            max_servers_per_location: 16,
            max_path_components: 128,
            max_component_bytes: 255,
            max_server_bytes: 1_024,
            max_advertised_bytes_per_filesystem: 64 * 1_024,
            max_total_advertised_bytes: 16 * 1_024 * 1_024,
        }
    }
}

impl LocationRegistryLimits {
    fn validate(self) -> Result<Self, LocationRegistryError> {
        if self.max_filesystems == 0
            || self.max_locations_per_filesystem == 0
            || self.max_servers_per_location == 0
            || self.max_path_components == 0
            || self.max_component_bytes == 0
            || self.max_server_bytes == 0
            || self.max_advertised_bytes_per_filesystem == 0
            || self.max_total_advertised_bytes == 0
        {
            return Err(LocationRegistryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Why a configured `fs_location4` entry is being advertised.
///
/// Current-server paths, candidate trunk paths, and migration targets must
/// precede replicas. This captures the ordering requirement added by RFC 8587.
/// A [`Self::CandidateTrunk`] entry is only a discovery candidate; it is not
/// confirmed trunkable until [`classify_trunking`] says so.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocationPurpose {
    CurrentServer,
    CandidateTrunk,
    MigrationTarget,
    ReferralTarget,
    Replica,
}

impl LocationPurpose {
    const fn is_replica(self) -> bool {
        matches!(self, Self::Replica)
    }
}

/// Source-side phase of a fenced migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceMigrationPhase {
    Preparing,
    Quiesced,
    Redirecting,
    Committed,
    Aborted,
}

/// Destination-side phase of a fenced migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationMigrationPhase {
    Importing,
    Ready,
    Active,
    Aborted,
}

/// Placement status associated with a single export on this server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementMigrationStatus {
    None,
    Source {
        generation: u64,
        phase: SourceMigrationPhase,
    },
    Destination {
        generation: u64,
        phase: DestinationMigrationPhase,
    },
}

/// The externally observable placement class of one export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSystemLocationKind {
    Present,
    Replicated,
    Absent,
    Moved,
}

/// Validated placement data for one export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSystemLocationRecord {
    state: Nfs4LocationState,
    purposes: Vec<LocationPurpose>,
    migration: PlacementMigrationStatus,
}

impl FileSystemLocationRecord {
    pub fn new(state: Nfs4LocationState, purposes: Vec<LocationPurpose>, migration: PlacementMigrationStatus) -> Self {
        Self {
            state,
            purposes,
            migration,
        }
    }

    pub fn state(&self) -> &Nfs4LocationState {
        &self.state
    }

    pub fn locations(&self) -> &Nfs4FsLocations {
        locations_for_state(&self.state)
    }

    pub fn purposes(&self) -> &[LocationPurpose] {
        &self.purposes
    }

    pub fn migration(&self) -> PlacementMigrationStatus {
        self.migration
    }

    pub fn kind(&self) -> FileSystemLocationKind {
        match &self.state {
            Nfs4LocationState::Present(_) if self.purposes.iter().any(|purpose| purpose.is_replica()) => {
                FileSystemLocationKind::Replicated
            },
            Nfs4LocationState::Present(_) => FileSystemLocationKind::Present,
            Nfs4LocationState::Absent(_) => FileSystemLocationKind::Absent,
            Nfs4LocationState::Moved(_) => FileSystemLocationKind::Moved,
        }
    }
}

/// Operation categories whose behavior depends on filesystem presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocationOperation<'a> {
    GetAttr(&'a Bitmap),
    Verify(&'a Bitmap),
    NVerify(&'a Bitmap),
    ReadDir(&'a Bitmap),
    ReadOnly,
    Mutating,
}

impl LocationOperation<'_> {
    const fn is_mutating(self) -> bool {
        matches!(self, Self::Mutating)
    }
}

/// Decision made before an operation starts with its current filehandle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocationOperationDecision {
    Proceed,
    /// GETATTR/VERIFY/NVERIFY may inspect this restricted attribute set on an
    /// absent filesystem. The executor still supplies the actual FSID and
    /// mounted-on file ID.
    RestrictedAttributes {
        available_attributes: Bitmap,
        locations: Nfs4FsLocations,
    },
    ReturnStatus(NfsStatus),
}

/// Per-entry decision when a READDIR on a present parent encounters the root
/// of an absent filesystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadDirEntryDecision {
    Proceed,
    RestrictedAttributes {
        available_attributes: Bitmap,
        rdattr_error: NfsStatus,
        locations: Nfs4FsLocations,
    },
    FailOperation(NfsStatus),
}

/// Bounded registry used by COMPOUND execution and the attribute engine.
///
/// Mutation requires `&mut self`; a server that changes placement at runtime
/// can put the registry behind its existing state lock.
///
/// Presence is defined relative to the network address handling the request.
/// When listeners do not share the same placement view, construct one registry
/// per local endpoint and select it using the accepted socket's local address.
#[derive(Clone, Debug)]
pub struct LocationRegistry {
    limits: LocationRegistryLimits,
    entries: BTreeMap<ExportId, FileSystemLocationRecord>,
    advertised_bytes: usize,
}

impl LocationRegistry {
    pub fn new(limits: LocationRegistryLimits) -> Result<Self, LocationRegistryError> {
        Ok(Self {
            limits: limits.validate()?,
            entries: BTreeMap::new(),
            advertised_bytes: 0,
        })
    }

    pub fn limits(&self) -> LocationRegistryLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, export_id: ExportId) -> Option<&FileSystemLocationRecord> {
        self.entries.get(&export_id)
    }

    pub fn insert(
        &mut self,
        export_id: ExportId,
        record: FileSystemLocationRecord,
    ) -> Result<(), LocationRegistryError> {
        if self.entries.contains_key(&export_id) {
            return Err(LocationRegistryError::DuplicateExport(export_id));
        }
        if self.entries.len() >= self.limits.max_filesystems {
            return Err(LocationRegistryError::FilesystemCapacity);
        }
        let charged = validate_record(&record, self.limits)?;
        let new_total = self
            .advertised_bytes
            .checked_add(charged)
            .ok_or(LocationRegistryError::AdvertisedBytesCapacity)?;
        if new_total > self.limits.max_total_advertised_bytes {
            return Err(LocationRegistryError::AdvertisedBytesCapacity);
        }
        self.entries.insert(export_id, record);
        self.advertised_bytes = new_total;
        Ok(())
    }

    /// Atomically replaces location and phase data after validating the
    /// migration transition and all configured bounds.
    pub fn replace(
        &mut self,
        export_id: ExportId,
        record: FileSystemLocationRecord,
    ) -> Result<(), LocationRegistryError> {
        let previous = self
            .entries
            .get(&export_id)
            .ok_or(LocationRegistryError::UnknownExport(export_id))?;
        validate_migration_transition(previous.migration, record.migration)?;
        let previous_charge = advertised_bytes(previous.locations())?;
        let replacement_charge = validate_record(&record, self.limits)?;
        let new_total = self
            .advertised_bytes
            .checked_sub(previous_charge)
            .and_then(|total| total.checked_add(replacement_charge))
            .ok_or(LocationRegistryError::AdvertisedBytesCapacity)?;
        if new_total > self.limits.max_total_advertised_bytes {
            return Err(LocationRegistryError::AdvertisedBytesCapacity);
        }
        self.entries.insert(export_id, record);
        self.advertised_bytes = new_total;
        Ok(())
    }

    pub fn remove(&mut self, export_id: ExportId) -> Option<FileSystemLocationRecord> {
        let record = self.entries.remove(&export_id)?;
        let charged = advertised_bytes(record.locations()).unwrap_or(0);
        self.advertised_bytes = self.advertised_bytes.saturating_sub(charged);
        Some(record)
    }

    /// Applies the RFC 7530 section 8.3 start-of-operation presence check.
    pub fn decide_operation(
        &self,
        export_id: ExportId,
        operation: LocationOperation<'_>,
    ) -> Result<LocationOperationDecision, LocationRegistryError> {
        let record = self
            .entries
            .get(&export_id)
            .ok_or(LocationRegistryError::UnknownExport(export_id))?;

        if migration_delays(record.migration, operation) {
            return Ok(LocationOperationDecision::ReturnStatus(NfsStatus::Delay));
        }
        if matches!(record.state, Nfs4LocationState::Present(_)) {
            return Ok(LocationOperationDecision::Proceed);
        }

        let locations = record.locations().clone();
        let decision = match operation {
            LocationOperation::GetAttr(requested) if bitmap_contains(requested, FATTR4_FS_LOCATIONS) => {
                LocationOperationDecision::RestrictedAttributes {
                    available_attributes: intersect_attributes(requested, &ABSENT_ATTRIBUTES),
                    locations,
                }
            },
            LocationOperation::Verify(requested) | LocationOperation::NVerify(requested)
                if bitmap_contains(requested, FATTR4_FS_LOCATIONS)
                    && bitmap_is_subset(requested, &ABSENT_ATTRIBUTES) =>
            {
                LocationOperationDecision::RestrictedAttributes {
                    available_attributes: intersect_attributes(requested, &ABSENT_ATTRIBUTES),
                    locations,
                }
            },
            _ => LocationOperationDecision::ReturnStatus(NfsStatus::Moved),
        };
        Ok(decision)
    }

    /// Applies the RFC 7530 section 8.3.2 decision for one child entry while
    /// READDIR itself is executing in a present parent filesystem.
    pub fn decide_readdir_entry(
        &self,
        child_export_id: ExportId,
        requested: &Bitmap,
    ) -> Result<ReadDirEntryDecision, LocationRegistryError> {
        let record = self
            .entries
            .get(&child_export_id)
            .ok_or(LocationRegistryError::UnknownExport(child_export_id))?;

        if migration_delays(record.migration, LocationOperation::ReadDir(requested)) {
            return Ok(ReadDirEntryDecision::FailOperation(NfsStatus::Delay));
        }
        if matches!(record.state, Nfs4LocationState::Present(_)) {
            return Ok(ReadDirEntryDecision::Proceed);
        }

        if bitmap_contains(requested, FATTR4_FS_LOCATIONS) {
            return Ok(ReadDirEntryDecision::RestrictedAttributes {
                available_attributes: intersect_attributes(requested, &ABSENT_READDIR_ATTRIBUTES),
                rdattr_error: NfsStatus::Ok,
                locations: record.locations().clone(),
            });
        }
        if bitmap_contains(requested, FATTR4_RDATTR_ERROR) {
            return Ok(ReadDirEntryDecision::RestrictedAttributes {
                available_attributes: intersect_attributes(requested, &ABSENT_READDIR_ATTRIBUTES),
                rdattr_error: NfsStatus::Moved,
                locations: record.locations().clone(),
            });
        }
        Ok(ReadDirEntryDecision::FailOperation(NfsStatus::Moved))
    }
}

fn migration_delays(status: PlacementMigrationStatus, operation: LocationOperation<'_>) -> bool {
    match status {
        PlacementMigrationStatus::Source {
            phase: SourceMigrationPhase::Preparing | SourceMigrationPhase::Quiesced,
            ..
        } => operation.is_mutating(),
        PlacementMigrationStatus::Destination {
            phase: DestinationMigrationPhase::Importing | DestinationMigrationPhase::Ready,
            ..
        } => true,
        _ => false,
    }
}

fn locations_for_state(state: &Nfs4LocationState) -> &Nfs4FsLocations {
    match state {
        Nfs4LocationState::Present(locations)
        | Nfs4LocationState::Absent(locations)
        | Nfs4LocationState::Moved(locations) => locations,
    }
}

fn validate_record(
    record: &FileSystemLocationRecord,
    limits: LocationRegistryLimits,
) -> Result<usize, LocationRegistryError> {
    let locations = record.locations();
    if locations.locations.len() > limits.max_locations_per_filesystem {
        return Err(LocationRegistryError::TooManyLocations);
    }
    if record.purposes.len() != locations.locations.len() {
        return Err(LocationRegistryError::PurposeCount);
    }
    if !matches!(record.state, Nfs4LocationState::Present(_)) && locations.locations.is_empty() {
        return Err(LocationRegistryError::AbsentWithoutLocations);
    }
    validate_path(&locations.fs_root, limits)?;

    let mut saw_replica = false;
    for (location, purpose) in locations.locations.iter().zip(&record.purposes) {
        if saw_replica && !purpose.is_replica() {
            return Err(LocationRegistryError::LocationOrdering);
        }
        saw_replica |= purpose.is_replica();
        validate_purpose(&record.state, *purpose)?;
        validate_location(location, limits)?;
    }
    validate_migration_consistency(&record.state, record.migration)?;

    let charged = advertised_bytes(locations)?;
    if charged > limits.max_advertised_bytes_per_filesystem {
        return Err(LocationRegistryError::AdvertisedBytesPerFilesystem);
    }
    Ok(charged)
}

fn validate_location(location: &Nfs4FsLocation, limits: LocationRegistryLimits) -> Result<(), LocationRegistryError> {
    if location.servers.is_empty() {
        return Err(LocationRegistryError::LocationWithoutServers);
    }
    if location.servers.len() > limits.max_servers_per_location {
        return Err(LocationRegistryError::TooManyServers);
    }
    for server in &location.servers {
        if server.len() > limits.max_server_bytes {
            return Err(LocationRegistryError::ServerNameTooLong);
        }
        if server.as_bytes().contains(&0) {
            return Err(LocationRegistryError::InvalidServerName);
        }
    }
    validate_path(&location.root_path, limits)
}

fn validate_path(path: &[String], limits: LocationRegistryLimits) -> Result<(), LocationRegistryError> {
    if path.len() > limits.max_path_components {
        return Err(LocationRegistryError::TooManyPathComponents);
    }
    for component in path {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > limits.max_component_bytes
            || component.as_bytes().contains(&0)
            || component.as_bytes().contains(&b'/')
        {
            return Err(LocationRegistryError::InvalidPathComponent);
        }
    }
    Ok(())
}

fn validate_purpose(state: &Nfs4LocationState, purpose: LocationPurpose) -> Result<(), LocationRegistryError> {
    let valid = match state {
        Nfs4LocationState::Present(_) => matches!(
            purpose,
            LocationPurpose::CurrentServer | LocationPurpose::CandidateTrunk | LocationPurpose::Replica
        ),
        Nfs4LocationState::Absent(_) => {
            matches!(purpose, LocationPurpose::ReferralTarget | LocationPurpose::Replica)
        },
        Nfs4LocationState::Moved(_) => matches!(
            purpose,
            LocationPurpose::CandidateTrunk | LocationPurpose::MigrationTarget | LocationPurpose::Replica
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(LocationRegistryError::PurposeInconsistentWithPresence)
    }
}

fn validate_migration_consistency(
    state: &Nfs4LocationState,
    migration: PlacementMigrationStatus,
) -> Result<(), LocationRegistryError> {
    let present = matches!(state, Nfs4LocationState::Present(_));
    let moved = matches!(state, Nfs4LocationState::Moved(_));
    let valid = match migration {
        PlacementMigrationStatus::None => true,
        PlacementMigrationStatus::Source {
            phase: SourceMigrationPhase::Preparing | SourceMigrationPhase::Quiesced | SourceMigrationPhase::Aborted,
            ..
        } => present,
        PlacementMigrationStatus::Source {
            phase: SourceMigrationPhase::Redirecting | SourceMigrationPhase::Committed,
            ..
        } => moved,
        PlacementMigrationStatus::Destination {
            phase:
                DestinationMigrationPhase::Importing | DestinationMigrationPhase::Ready | DestinationMigrationPhase::Aborted,
            ..
        } => !moved,
        PlacementMigrationStatus::Destination {
            phase: DestinationMigrationPhase::Active,
            ..
        } => present,
    };
    if valid {
        Ok(())
    } else {
        Err(LocationRegistryError::MigrationInconsistentWithPresence)
    }
}

fn validate_migration_transition(
    previous: PlacementMigrationStatus,
    next: PlacementMigrationStatus,
) -> Result<(), LocationRegistryError> {
    if previous == next {
        return Ok(());
    }
    let valid = match (previous, next) {
        (
            PlacementMigrationStatus::None,
            PlacementMigrationStatus::Source {
                phase: SourceMigrationPhase::Preparing,
                ..
            },
        )
        | (
            PlacementMigrationStatus::None,
            PlacementMigrationStatus::Destination {
                phase: DestinationMigrationPhase::Importing,
                ..
            },
        ) => true,
        (
            PlacementMigrationStatus::Source {
                generation,
                phase: SourceMigrationPhase::Preparing,
            },
            PlacementMigrationStatus::Source {
                generation: next_generation,
                phase: SourceMigrationPhase::Quiesced | SourceMigrationPhase::Aborted,
            },
        )
        | (
            PlacementMigrationStatus::Source {
                generation,
                phase: SourceMigrationPhase::Quiesced,
            },
            PlacementMigrationStatus::Source {
                generation: next_generation,
                phase: SourceMigrationPhase::Redirecting | SourceMigrationPhase::Aborted,
            },
        )
        | (
            PlacementMigrationStatus::Source {
                generation,
                phase: SourceMigrationPhase::Redirecting,
            },
            PlacementMigrationStatus::Source {
                generation: next_generation,
                phase: SourceMigrationPhase::Committed | SourceMigrationPhase::Aborted,
            },
        ) => generation == next_generation,
        (
            PlacementMigrationStatus::Destination {
                generation,
                phase: DestinationMigrationPhase::Importing,
            },
            PlacementMigrationStatus::Destination {
                generation: next_generation,
                phase: DestinationMigrationPhase::Ready | DestinationMigrationPhase::Aborted,
            },
        )
        | (
            PlacementMigrationStatus::Destination {
                generation,
                phase: DestinationMigrationPhase::Ready,
            },
            PlacementMigrationStatus::Destination {
                generation: next_generation,
                phase: DestinationMigrationPhase::Active | DestinationMigrationPhase::Aborted,
            },
        ) => generation == next_generation,
        (
            PlacementMigrationStatus::Source {
                phase: SourceMigrationPhase::Committed | SourceMigrationPhase::Aborted,
                ..
            }
            | PlacementMigrationStatus::Destination {
                phase: DestinationMigrationPhase::Active | DestinationMigrationPhase::Aborted,
                ..
            },
            PlacementMigrationStatus::None,
        ) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(LocationRegistryError::InvalidMigrationTransition { previous, next })
    }
}

fn advertised_bytes(locations: &Nfs4FsLocations) -> Result<usize, LocationRegistryError> {
    let mut total = 0usize;
    for component in &locations.fs_root {
        total = total
            .checked_add(component.len())
            .ok_or(LocationRegistryError::AdvertisedBytesCapacity)?;
    }
    for location in &locations.locations {
        for server in &location.servers {
            total = total
                .checked_add(server.len())
                .ok_or(LocationRegistryError::AdvertisedBytesCapacity)?;
        }
        for component in &location.root_path {
            total = total
                .checked_add(component.len())
                .ok_or(LocationRegistryError::AdvertisedBytesCapacity)?;
        }
    }
    Ok(total)
}

fn intersect_attributes(requested: &[u32], available: &[u32]) -> Bitmap {
    let highest_word = available
        .iter()
        .filter(|attribute| bitmap_contains(requested, **attribute))
        .map(|attribute| (*attribute / 32) as usize)
        .max();
    let Some(highest_word) = highest_word else {
        return Vec::new();
    };
    let mut result = vec![0; highest_word + 1];
    for attribute in available {
        if bitmap_contains(requested, *attribute) {
            result[(*attribute / 32) as usize] |= 1 << (*attribute % 32);
        }
    }
    result
}

fn bitmap_is_subset(requested: &[u32], available: &[u32]) -> bool {
    let available_bitmap = intersect_attributes(requested, available);
    requested
        .iter()
        .enumerate()
        .all(|(index, word)| *word == available_bitmap.get(index).copied().unwrap_or(0))
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocationRegistryError {
    #[error("location registry limits must be nonzero")]
    InvalidLimits,
    #[error("location registry filesystem capacity is exhausted")]
    FilesystemCapacity,
    #[error("location registry advertised-byte capacity is exhausted")]
    AdvertisedBytesCapacity,
    #[error("filesystem exceeds its advertised-byte limit")]
    AdvertisedBytesPerFilesystem,
    #[error("export {0:?} already has location state")]
    DuplicateExport(ExportId),
    #[error("export {0:?} has no location state")]
    UnknownExport(ExportId),
    #[error("filesystem has too many locations")]
    TooManyLocations,
    #[error("location purpose count does not match the location count")]
    PurposeCount,
    #[error("an absent or moved filesystem must advertise at least one location")]
    AbsentWithoutLocations,
    #[error("a location must designate at least one server")]
    LocationWithoutServers,
    #[error("a location designates too many servers")]
    TooManyServers,
    #[error("a location server name exceeds its configured bound")]
    ServerNameTooLong,
    #[error("a location server name contains a null byte")]
    InvalidServerName,
    #[error("a location path has too many components")]
    TooManyPathComponents,
    #[error("a location path component is invalid")]
    InvalidPathComponent,
    #[error("current-server and migration-target locations must precede replicas")]
    LocationOrdering,
    #[error("location purpose is inconsistent with filesystem presence")]
    PurposeInconsistentWithPresence,
    #[error("migration phase is inconsistent with filesystem presence")]
    MigrationInconsistentWithPresence,
    #[error("invalid migration transition from {previous:?} to {next:?}")]
    InvalidMigrationTransition {
        previous: PlacementMigrationStatus,
        next: PlacementMigrationStatus,
    },
}

/// Explicit attestation that two server processes use the same fenced state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SharedStateAttestation {
    Unattested,
    Fenced {
        authority_identity: [u8; 16],
        stable_scope: Vec<u8>,
    },
}

/// Configured identity for one endpoint. Endpoint labels are opaque; this type
/// never resolves them or infers identities from DNS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    endpoint: String,
    process_identity: [u8; 16],
    server_instance_identity: [u8; 16],
    persistent_server_identity: Option<[u8; 16]>,
    shared_state: SharedStateAttestation,
}

impl EndpointIdentity {
    pub fn process_local(
        endpoint: impl Into<String>,
        process_identity: [u8; 16],
        server_instance_identity: [u8; 16],
    ) -> Result<Self, EndpointRegistryError> {
        Self::build(
            endpoint.into(),
            process_identity,
            server_instance_identity,
            None,
            SharedStateAttestation::Unattested,
        )
    }

    pub fn fenced_shared(
        endpoint: impl Into<String>,
        process_identity: [u8; 16],
        server_instance_identity: [u8; 16],
        persistent_server_identity: [u8; 16],
        authority_identity: [u8; 16],
        stable_scope: impl Into<Vec<u8>>,
    ) -> Result<Self, EndpointRegistryError> {
        Self::build(
            endpoint.into(),
            process_identity,
            server_instance_identity,
            Some(persistent_server_identity),
            SharedStateAttestation::Fenced {
                authority_identity,
                stable_scope: stable_scope.into(),
            },
        )
    }

    /// Records a persistent logical server identity without attesting that the
    /// endpoint shares live fenced state with another server process.
    ///
    /// This is intentionally insufficient for cross-process trunking.
    pub fn persistent_unattested(
        endpoint: impl Into<String>,
        process_identity: [u8; 16],
        server_instance_identity: [u8; 16],
        persistent_server_identity: [u8; 16],
    ) -> Result<Self, EndpointRegistryError> {
        Self::build(
            endpoint.into(),
            process_identity,
            server_instance_identity,
            Some(persistent_server_identity),
            SharedStateAttestation::Unattested,
        )
    }

    fn build(
        endpoint: String,
        process_identity: [u8; 16],
        server_instance_identity: [u8; 16],
        persistent_server_identity: Option<[u8; 16]>,
        shared_state: SharedStateAttestation,
    ) -> Result<Self, EndpointRegistryError> {
        if endpoint.is_empty() || endpoint.as_bytes().contains(&0) {
            return Err(EndpointRegistryError::InvalidEndpoint);
        }
        if process_identity == [0; 16] || server_instance_identity == [0; 16] {
            return Err(EndpointRegistryError::InvalidIdentity);
        }
        if persistent_server_identity.is_some_and(|identity| identity == [0; 16]) {
            return Err(EndpointRegistryError::InvalidIdentity);
        }
        if let SharedStateAttestation::Fenced {
            authority_identity,
            stable_scope,
        } = &shared_state
        {
            if persistent_server_identity.is_none() || *authority_identity == [0; 16] || stable_scope.is_empty() {
                return Err(EndpointRegistryError::InvalidAttestation);
            }
        }
        Ok(Self {
            endpoint,
            process_identity,
            server_instance_identity,
            persistent_server_identity,
            shared_state,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn process_identity(&self) -> [u8; 16] {
        self.process_identity
    }

    pub fn server_instance_identity(&self) -> [u8; 16] {
        self.server_instance_identity
    }

    pub fn persistent_server_identity(&self) -> Option<[u8; 16]> {
        self.persistent_server_identity
    }

    pub fn shared_state(&self) -> &SharedStateAttestation {
        &self.shared_state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonTrunkingReason {
    EndpointIdentityConflict,
    MissingPersistentServerIdentity,
    PersistentServerIdentityMismatch,
    SharedStateNotAttested,
    SharedStateAttestationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrunkingClassification {
    SameEndpoint,
    TrunkableSameProcess,
    TrunkableFencedSharedState,
    NotTrunkable(NonTrunkingReason),
}

impl TrunkingClassification {
    pub const fn is_trunkable(self) -> bool {
        matches!(self, Self::SameEndpoint | Self::TrunkableSameProcess | Self::TrunkableFencedSharedState)
    }
}

/// Registry of application-attested endpoint identities.
#[derive(Clone, Debug)]
pub struct EndpointIdentityRegistry {
    max_endpoints: usize,
    max_endpoint_bytes: usize,
    max_stable_scope_bytes: usize,
    endpoints: BTreeMap<String, EndpointIdentity>,
}

impl EndpointIdentityRegistry {
    pub fn new(
        max_endpoints: usize,
        max_endpoint_bytes: usize,
        max_stable_scope_bytes: usize,
    ) -> Result<Self, EndpointRegistryError> {
        if max_endpoints == 0 || max_endpoint_bytes == 0 || max_stable_scope_bytes == 0 {
            return Err(EndpointRegistryError::InvalidLimits);
        }
        Ok(Self {
            max_endpoints,
            max_endpoint_bytes,
            max_stable_scope_bytes,
            endpoints: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn register(&mut self, identity: EndpointIdentity) -> Result<(), EndpointRegistryError> {
        if self.endpoints.contains_key(identity.endpoint()) {
            return Err(EndpointRegistryError::DuplicateEndpoint(identity.endpoint.clone()));
        }
        if self.endpoints.len() >= self.max_endpoints {
            return Err(EndpointRegistryError::Capacity);
        }
        if identity.endpoint.len() > self.max_endpoint_bytes {
            return Err(EndpointRegistryError::EndpointTooLong);
        }
        if let SharedStateAttestation::Fenced { stable_scope, .. } = &identity.shared_state {
            if stable_scope.len() > self.max_stable_scope_bytes {
                return Err(EndpointRegistryError::StableScopeTooLong);
            }
        }
        self.endpoints.insert(identity.endpoint.clone(), identity);
        Ok(())
    }

    pub fn get(&self, endpoint: &str) -> Option<&EndpointIdentity> {
        self.endpoints.get(endpoint)
    }

    pub fn classify(
        &self,
        first_endpoint: &str,
        second_endpoint: &str,
    ) -> Result<TrunkingClassification, EndpointRegistryError> {
        let first = self
            .endpoints
            .get(first_endpoint)
            .ok_or_else(|| EndpointRegistryError::UnknownEndpoint(first_endpoint.to_owned()))?;
        let second = self
            .endpoints
            .get(second_endpoint)
            .ok_or_else(|| EndpointRegistryError::UnknownEndpoint(second_endpoint.to_owned()))?;
        Ok(classify_trunking(first, second))
    }
}

pub fn classify_trunking(first: &EndpointIdentity, second: &EndpointIdentity) -> TrunkingClassification {
    if first.endpoint == second.endpoint {
        return if first == second {
            TrunkingClassification::SameEndpoint
        } else {
            TrunkingClassification::NotTrunkable(NonTrunkingReason::EndpointIdentityConflict)
        };
    }
    if first.process_identity == second.process_identity
        && first.server_instance_identity == second.server_instance_identity
    {
        return TrunkingClassification::TrunkableSameProcess;
    }

    let (Some(first_persistent), Some(second_persistent)) =
        (first.persistent_server_identity, second.persistent_server_identity)
    else {
        return TrunkingClassification::NotTrunkable(NonTrunkingReason::MissingPersistentServerIdentity);
    };
    if first_persistent != second_persistent {
        return TrunkingClassification::NotTrunkable(NonTrunkingReason::PersistentServerIdentityMismatch);
    }
    match (&first.shared_state, &second.shared_state) {
        (
            SharedStateAttestation::Fenced {
                authority_identity: first_authority,
                stable_scope: first_scope,
            },
            SharedStateAttestation::Fenced {
                authority_identity: second_authority,
                stable_scope: second_scope,
            },
        ) if first_authority == second_authority && first_scope == second_scope => {
            TrunkingClassification::TrunkableFencedSharedState
        },
        (SharedStateAttestation::Fenced { .. }, SharedStateAttestation::Fenced { .. }) => {
            TrunkingClassification::NotTrunkable(NonTrunkingReason::SharedStateAttestationMismatch)
        },
        _ => TrunkingClassification::NotTrunkable(NonTrunkingReason::SharedStateNotAttested),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EndpointRegistryError {
    #[error("endpoint registry limits must be nonzero")]
    InvalidLimits,
    #[error("endpoint identity is invalid")]
    InvalidEndpoint,
    #[error("endpoint process and server identities must be nonzero")]
    InvalidIdentity,
    #[error("fenced shared-state attestation is incomplete")]
    InvalidAttestation,
    #[error("endpoint identity registry capacity is exhausted")]
    Capacity,
    #[error("endpoint label exceeds its configured bound")]
    EndpointTooLong,
    #[error("stable scope exceeds its configured bound")]
    StableScopeTooLong,
    #[error("endpoint {0:?} is already registered")]
    DuplicateEndpoint(String),
    #[error("endpoint {0:?} is not registered")]
    UnknownEndpoint(String),
}

#[cfg(test)]
mod tests {
    use super::super::attributes::bitmap_from_attributes;
    use super::super::types::{FATTR4_SIZE, FATTR4_TIME_MODIFY};
    use super::*;

    fn location(server: &str, root_path: &[&str]) -> Nfs4FsLocation {
        Nfs4FsLocation {
            servers: vec![server.to_owned()],
            root_path: root_path.iter().map(|component| (*component).to_owned()).collect(),
        }
    }

    fn locations(entries: Vec<Nfs4FsLocation>) -> Nfs4FsLocations {
        Nfs4FsLocations {
            fs_root: vec!["exports".to_owned(), "data".to_owned()],
            locations: entries,
        }
    }

    fn registry_with(
        export_id: ExportId,
        state: Nfs4LocationState,
        purposes: Vec<LocationPurpose>,
    ) -> LocationRegistry {
        let mut registry = LocationRegistry::new(LocationRegistryLimits::default()).unwrap();
        registry
            .insert(export_id, FileSystemLocationRecord::new(state, purposes, PlacementMigrationStatus::None))
            .unwrap();
        registry
    }

    #[test]
    fn absent_getattr_requires_fs_locations_and_omits_unavailable_attributes() {
        let export = ExportId(7);
        let registry = registry_with(
            export,
            Nfs4LocationState::Absent(locations(vec![location("target.example", &["data"])])),
            vec![LocationPurpose::ReferralTarget],
        );
        let without_locations = bitmap_from_attributes([FATTR4_FSID]).unwrap();
        assert_eq!(
            registry
                .decide_operation(export, LocationOperation::GetAttr(&without_locations))
                .unwrap(),
            LocationOperationDecision::ReturnStatus(NfsStatus::Moved)
        );

        let requested =
            bitmap_from_attributes([FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_SIZE, FATTR4_MOUNTED_ON_FILEID]).unwrap();
        let LocationOperationDecision::RestrictedAttributes {
            available_attributes, ..
        } = registry
            .decide_operation(export, LocationOperation::GetAttr(&requested))
            .unwrap()
        else {
            panic!("expected restricted absent-filesystem attributes");
        };
        assert!(bitmap_contains(&available_attributes, FATTR4_FSID));
        assert!(bitmap_contains(&available_attributes, FATTR4_FS_LOCATIONS));
        assert!(bitmap_contains(&available_attributes, FATTR4_MOUNTED_ON_FILEID));
        assert!(!bitmap_contains(&available_attributes, FATTR4_SIZE));
    }

    #[test]
    fn absent_verify_and_nverify_reject_any_unavailable_attribute() {
        let export = ExportId(8);
        let registry = registry_with(
            export,
            Nfs4LocationState::Moved(locations(vec![location("new.example", &["new"])])),
            vec![LocationPurpose::MigrationTarget],
        );
        let allowed = bitmap_from_attributes([FATTR4_FSID, FATTR4_FS_LOCATIONS]).unwrap();
        assert!(matches!(
            registry.decide_operation(export, LocationOperation::Verify(&allowed)).unwrap(),
            LocationOperationDecision::RestrictedAttributes { .. }
        ));

        let unsupported = bitmap_from_attributes([FATTR4_FS_LOCATIONS, FATTR4_TIME_MODIFY]).unwrap();
        assert_eq!(
            registry
                .decide_operation(export, LocationOperation::NVerify(&unsupported))
                .unwrap(),
            LocationOperationDecision::ReturnStatus(NfsStatus::Moved)
        );
    }

    #[test]
    fn readdir_on_absent_current_filehandle_always_moves() {
        let export = ExportId(9);
        let registry = registry_with(
            export,
            Nfs4LocationState::Absent(locations(vec![location("referral.example", &["root"])])),
            vec![LocationPurpose::ReferralTarget],
        );
        let requested = bitmap_from_attributes([FATTR4_FS_LOCATIONS, FATTR4_RDATTR_ERROR]).unwrap();
        assert_eq!(
            registry
                .decide_operation(export, LocationOperation::ReadDir(&requested))
                .unwrap(),
            LocationOperationDecision::ReturnStatus(NfsStatus::Moved)
        );
    }

    #[test]
    fn readdir_child_absence_has_all_three_rfc_decisions() {
        let export = ExportId(10);
        let registry = registry_with(
            export,
            Nfs4LocationState::Absent(locations(vec![location("referral.example", &["root"])])),
            vec![LocationPurpose::ReferralTarget],
        );

        let with_locations =
            bitmap_from_attributes([FATTR4_FS_LOCATIONS, FATTR4_RDATTR_ERROR, FATTR4_FSID, FATTR4_SIZE]).unwrap();
        let ReadDirEntryDecision::RestrictedAttributes {
            available_attributes,
            rdattr_error,
            ..
        } = registry.decide_readdir_entry(export, &with_locations).unwrap()
        else {
            panic!("expected restricted entry attributes");
        };
        assert_eq!(rdattr_error, NfsStatus::Ok);
        assert!(bitmap_contains(&available_attributes, FATTR4_FS_LOCATIONS));
        assert!(!bitmap_contains(&available_attributes, FATTR4_SIZE));

        let with_rdattr = bitmap_from_attributes([FATTR4_RDATTR_ERROR, FATTR4_FSID, FATTR4_SIZE]).unwrap();
        let ReadDirEntryDecision::RestrictedAttributes {
            available_attributes,
            rdattr_error,
            ..
        } = registry.decide_readdir_entry(export, &with_rdattr).unwrap()
        else {
            panic!("expected per-entry rdattr_error");
        };
        assert_eq!(rdattr_error, NfsStatus::Moved);
        assert!(bitmap_contains(&available_attributes, FATTR4_FSID));
        assert!(!bitmap_contains(&available_attributes, FATTR4_SIZE));

        let neither = bitmap_from_attributes([FATTR4_FSID, FATTR4_SIZE]).unwrap();
        assert_eq!(
            registry.decide_readdir_entry(export, &neither).unwrap(),
            ReadDirEntryDecision::FailOperation(NfsStatus::Moved)
        );
    }

    #[test]
    fn present_replica_advertisement_does_not_block_operations() {
        let export = ExportId(11);
        let registry = registry_with(
            export,
            Nfs4LocationState::Present(locations(vec![
                location("", &["exports", "data"]),
                location("replica.example", &["replica"]),
            ])),
            vec![LocationPurpose::CurrentServer, LocationPurpose::Replica],
        );
        assert_eq!(registry.get(export).unwrap().kind(), FileSystemLocationKind::Replicated);
        assert_eq!(
            registry.decide_operation(export, LocationOperation::ReadOnly).unwrap(),
            LocationOperationDecision::Proceed
        );
    }

    #[test]
    fn registry_enforces_bounds_canonical_paths_and_rfc8587_ordering() {
        let limits = LocationRegistryLimits {
            max_locations_per_filesystem: 1,
            ..LocationRegistryLimits::default()
        };
        let mut registry = LocationRegistry::new(limits).unwrap();
        let too_many = FileSystemLocationRecord::new(
            Nfs4LocationState::Present(locations(vec![
                location("one.example", &["one"]),
                location("two.example", &["two"]),
            ])),
            vec![LocationPurpose::CurrentServer, LocationPurpose::Replica],
            PlacementMigrationStatus::None,
        );
        assert_eq!(registry.insert(ExportId(1), too_many), Err(LocationRegistryError::TooManyLocations));

        let mut registry = LocationRegistry::new(LocationRegistryLimits::default()).unwrap();
        let wrong_order = FileSystemLocationRecord::new(
            Nfs4LocationState::Moved(locations(vec![
                location("replica.example", &["replica"]),
                location("target.example", &["target"]),
            ])),
            vec![LocationPurpose::Replica, LocationPurpose::MigrationTarget],
            PlacementMigrationStatus::None,
        );
        assert_eq!(registry.insert(ExportId(2), wrong_order), Err(LocationRegistryError::LocationOrdering));

        let invalid_path = FileSystemLocationRecord::new(
            Nfs4LocationState::Absent(locations(vec![location("target.example", &[".."])])),
            vec![LocationPurpose::ReferralTarget],
            PlacementMigrationStatus::None,
        );
        assert_eq!(registry.insert(ExportId(3), invalid_path), Err(LocationRegistryError::InvalidPathComponent));
    }

    #[test]
    fn same_process_and_server_instance_is_explicitly_trunkable() {
        let first = EndpointIdentity::process_local("10.0.0.1:2049", [1; 16], [2; 16]).unwrap();
        let second = EndpointIdentity::process_local("10.0.0.2:2049", [1; 16], [2; 16]).unwrap();
        assert_eq!(classify_trunking(&first, &second), TrunkingClassification::TrunkableSameProcess);
    }

    #[test]
    fn cross_process_needs_matching_persistent_identity_and_fenced_state() {
        let local = EndpointIdentity::process_local("10.0.0.1:2049", [1; 16], [2; 16]).unwrap();
        let other = EndpointIdentity::process_local("10.0.0.2:2049", [3; 16], [4; 16]).unwrap();
        assert_eq!(
            classify_trunking(&local, &other),
            TrunkingClassification::NotTrunkable(NonTrunkingReason::MissingPersistentServerIdentity)
        );

        let first_unattested =
            EndpointIdentity::persistent_unattested("10.0.0.1:2049", [1; 16], [2; 16], [5; 16]).unwrap();
        let second_unattested =
            EndpointIdentity::persistent_unattested("10.0.0.2:2049", [3; 16], [4; 16], [5; 16]).unwrap();
        assert_eq!(
            classify_trunking(&first_unattested, &second_unattested),
            TrunkingClassification::NotTrunkable(NonTrunkingReason::SharedStateNotAttested)
        );

        let first =
            EndpointIdentity::fenced_shared("10.0.0.1:2049", [1; 16], [2; 16], [5; 16], [6; 16], b"scope".to_vec())
                .unwrap();
        let mismatched_scope =
            EndpointIdentity::fenced_shared("10.0.0.2:2049", [3; 16], [4; 16], [5; 16], [6; 16], b"other".to_vec())
                .unwrap();
        assert_eq!(
            classify_trunking(&first, &mismatched_scope),
            TrunkingClassification::NotTrunkable(NonTrunkingReason::SharedStateAttestationMismatch)
        );

        let second =
            EndpointIdentity::fenced_shared("10.0.0.2:2049", [3; 16], [4; 16], [5; 16], [6; 16], b"scope".to_vec())
                .unwrap();
        assert_eq!(classify_trunking(&first, &second), TrunkingClassification::TrunkableFencedSharedState);
    }

    #[test]
    fn endpoint_registry_only_classifies_configured_identities() {
        let mut endpoints = EndpointIdentityRegistry::new(2, 128, 128).unwrap();
        endpoints
            .register(EndpointIdentity::process_local("a:2049", [1; 16], [2; 16]).unwrap())
            .unwrap();
        endpoints
            .register(EndpointIdentity::process_local("b:2049", [1; 16], [2; 16]).unwrap())
            .unwrap();
        assert_eq!(endpoints.classify("a:2049", "b:2049").unwrap(), TrunkingClassification::TrunkableSameProcess);
        assert_eq!(
            endpoints.classify("a:2049", "not-discovered"),
            Err(EndpointRegistryError::UnknownEndpoint("not-discovered".to_owned()))
        );
    }

    #[test]
    fn migration_phases_gate_mutations_and_validate_two_phase_transitions() {
        let export = ExportId(12);
        let present = locations(Vec::new());
        let mut registry = LocationRegistry::new(LocationRegistryLimits::default()).unwrap();
        registry
            .insert(
                export,
                FileSystemLocationRecord::new(
                    Nfs4LocationState::Present(present.clone()),
                    Vec::new(),
                    PlacementMigrationStatus::None,
                ),
            )
            .unwrap();
        registry
            .replace(
                export,
                FileSystemLocationRecord::new(
                    Nfs4LocationState::Present(present.clone()),
                    Vec::new(),
                    PlacementMigrationStatus::Source {
                        generation: 4,
                        phase: SourceMigrationPhase::Preparing,
                    },
                ),
            )
            .unwrap();
        assert_eq!(
            registry.decide_operation(export, LocationOperation::Mutating).unwrap(),
            LocationOperationDecision::ReturnStatus(NfsStatus::Delay)
        );
        assert_eq!(
            registry.decide_operation(export, LocationOperation::ReadOnly).unwrap(),
            LocationOperationDecision::Proceed
        );

        let invalid = registry.replace(
            export,
            FileSystemLocationRecord::new(
                Nfs4LocationState::Present(present),
                Vec::new(),
                PlacementMigrationStatus::Source {
                    generation: 5,
                    phase: SourceMigrationPhase::Quiesced,
                },
            ),
        );
        assert!(matches!(invalid, Err(LocationRegistryError::InvalidMigrationTransition { .. })));
    }

    #[test]
    fn destination_is_delayed_until_activation() {
        let export = ExportId(13);
        let present = locations(Vec::new());
        let mut registry = LocationRegistry::new(LocationRegistryLimits::default()).unwrap();
        registry
            .insert(
                export,
                FileSystemLocationRecord::new(
                    Nfs4LocationState::Present(present.clone()),
                    Vec::new(),
                    PlacementMigrationStatus::Destination {
                        generation: 9,
                        phase: DestinationMigrationPhase::Importing,
                    },
                ),
            )
            .unwrap();
        assert_eq!(
            registry.decide_operation(export, LocationOperation::ReadOnly).unwrap(),
            LocationOperationDecision::ReturnStatus(NfsStatus::Delay)
        );

        registry
            .replace(
                export,
                FileSystemLocationRecord::new(
                    Nfs4LocationState::Present(present.clone()),
                    Vec::new(),
                    PlacementMigrationStatus::Destination {
                        generation: 9,
                        phase: DestinationMigrationPhase::Ready,
                    },
                ),
            )
            .unwrap();
        registry
            .replace(
                export,
                FileSystemLocationRecord::new(
                    Nfs4LocationState::Present(present),
                    Vec::new(),
                    PlacementMigrationStatus::Destination {
                        generation: 9,
                        phase: DestinationMigrationPhase::Active,
                    },
                ),
            )
            .unwrap();
        assert_eq!(
            registry.decide_operation(export, LocationOperation::ReadOnly).unwrap(),
            LocationOperationDecision::Proceed
        );
    }
}
