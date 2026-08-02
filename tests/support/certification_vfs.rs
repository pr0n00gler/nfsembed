use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nfsembed::vfs::{
    ChangeInfo, CreateMode, CreatedObject, DeviceNumber, DirectoryEntry, ExportId, FileAttributes, FileType, FsInfo,
    FsStat, MutationResult, Nfs4Capabilities, Nfs4OpenAccess, Nfs4OpenExpectation, Nfs4OpenPreflight, Nfs4OpenRequest,
    Nfs4OpenResult, Nfs4OpenTarget, Nfs4OpenTransaction, NfsError, NfsName, NfsTime, NodeType, ObjectKey, PathConf,
    Principal, ProtocolVersion, ReadDirectoryPage, ReadResult, RequestContext, SetAttributes, VfsCapabilities,
    VirtualFileSystem, WccAttributes, WriteResult, WriteStability,
};

const ROOT_ID: u64 = 1;
const VERIFIER: [u8; 8] = *b"CERTDIR1";
const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
#[cfg(test)]
const MAX_OPEN_OUTCOMES: usize = 8;
#[cfg(not(test))]
const MAX_OPEN_OUTCOMES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificationProfile {
    ReadWrite,
    ReadOnly,
    CaseInsensitive,
}

#[derive(Clone)]
pub struct CertificationVfs {
    export_id: ExportId,
    profile: CertificationProfile,
    state: Arc<Mutex<State>>,
    #[cfg(test)]
    file_reservation_attempts: Arc<std::sync::atomic::AtomicUsize>,
}

struct State {
    next_id: u64,
    nodes: HashMap<u64, Node>,
    open_outcomes: HashMap<u64, OpenOutcomeRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenInvocation {
    principal: Principal,
    export_id: ExportId,
    protocol: ProtocolVersion,
    client_id: Option<u64>,
    parent: ObjectKey,
    name: NfsName,
    request: Nfs4OpenRequest,
    transaction: Nfs4OpenTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OpenOutcomeRecord {
    Pending(OpenInvocation),
    Complete {
        invocation: OpenInvocation,
        outcome: Result<Nfs4OpenResult, NfsError>,
    },
}

impl OpenOutcomeRecord {
    fn invocation(&self) -> &OpenInvocation {
        match self {
            Self::Pending(invocation) | Self::Complete { invocation, .. } => invocation,
        }
    }
}

struct Node {
    file_type: FileType,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u32,
    data: Vec<u8>,
    symlink: Vec<u8>,
    children: BTreeMap<Vec<u8>, u64>,
    exclusive_verifier: Option<[u8; 8]>,
    device: Option<DeviceNumber>,
    modified: u64,
    open_pins: HashSet<[u8; 16]>,
}

impl Node {
    fn new(file_type: FileType, mode: u32) -> Self {
        Self {
            file_type,
            mode,
            uid: 0,
            gid: 0,
            links: if file_type == FileType::Directory { 2 } else { 1 },
            data: Vec::new(),
            symlink: Vec::new(),
            children: BTreeMap::new(),
            exclusive_verifier: None,
            device: None,
            modified: 1,
            open_pins: HashSet::new(),
        }
    }
}

impl CertificationVfs {
    pub fn new(export_id: ExportId, profile: CertificationProfile) -> Self {
        let mut root = Node::new(FileType::Directory, 0o777);
        let mut file = Node::new(FileType::Regular, 0o666);
        file.data = (0..2 * 1024 * 1024).map(|index| (index % 251) as u8).collect();
        let directory = Node::new(FileType::Directory, 0o777);
        let mut symlink = Node::new(FileType::Symlink, 0o777);
        symlink.symlink = b"file".to_vec();
        root.children.insert(b"file".to_vec(), 2);
        root.children.insert(b"dir".to_vec(), 3);
        root.children.insert(b"link".to_vec(), 4);
        root.links = 3;
        let state = State {
            next_id: 5,
            nodes: [(ROOT_ID, root), (2, file), (3, directory), (4, symlink)].into_iter().collect(),
            open_outcomes: HashMap::new(),
        };
        Self {
            export_id,
            profile,
            state: Arc::new(Mutex::new(state)),
            #[cfg(test)]
            file_reservation_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn check_context(&self, context: &RequestContext) -> Result<(), NfsError> {
        if context.export_id == self.export_id {
            Ok(())
        } else {
            Err(NfsError::Access)
        }
    }

    fn check_mutable(&self, context: &RequestContext) -> Result<(), NfsError> {
        self.check_context(context)?;
        if self.profile == CertificationProfile::ReadOnly {
            Err(NfsError::ReadOnly)
        } else {
            Ok(())
        }
    }

    fn require_permissions(context: &RequestContext, node: &Node, required: u32) -> Result<(), NfsError> {
        let available = match &context.principal {
            // The certification export intentionally gives AUTH_NONE the
            // permissive identity used by its non-authorization test cases.
            Principal::Anonymous => 0o7,
            Principal::AuthSys { uid, .. } if *uid == 0 => 0o7,
            Principal::AuthSys { uid, .. } if *uid == node.uid => (node.mode >> 6) & 0o7,
            Principal::AuthSys {
                gid,
                supplementary_gids,
                ..
            } if *gid == node.gid || supplementary_gids.contains(&node.gid) => (node.mode >> 3) & 0o7,
            Principal::AuthSys { .. } => node.mode & 0o7,
            Principal::Gss { .. } => 0,
            _ => 0,
        };
        if available & required == required {
            Ok(())
        } else {
            Err(NfsError::Access)
        }
    }

    fn require_open_access(context: &RequestContext, node: &Node, access: Nfs4OpenAccess) -> Result<(), NfsError> {
        let required = (u32::from(access.reads()) * 0o4) | (u32::from(access.writes()) * 0o2);
        Self::require_permissions(context, node, required)
    }

    fn object_id(object: ObjectKey) -> Result<u64, NfsError> {
        if object.generation == 1 {
            Ok(object.file_id)
        } else {
            Err(NfsError::Stale)
        }
    }

    fn key(file_id: u64) -> ObjectKey {
        ObjectKey { file_id, generation: 1 }
    }

    fn attributes(state: &State, file_id: u64) -> Result<FileAttributes, NfsError> {
        let node = state.nodes.get(&file_id).ok_or(NfsError::Stale)?;
        let size = match node.file_type {
            FileType::Regular => node.data.len() as u64,
            FileType::Symlink => node.symlink.len() as u64,
            _ => 0,
        };
        let time = NfsTime {
            seconds: i64::try_from(node.modified).unwrap_or(i64::MAX),
            nanoseconds: 0,
        };
        Ok(FileAttributes {
            file_type: node.file_type,
            mode: node.mode,
            links: node.links,
            uid: node.uid,
            gid: node.gid,
            size,
            used: size,
            device: node.device,
            fs_id: 1001,
            file_id,
            change_id: node.modified.into(),
            access_time: time,
            modify_time: time,
            change_time: time,
        })
    }

    fn wcc(state: &State, file_id: u64) -> Option<WccAttributes> {
        Self::attributes(state, file_id).ok().map(|attributes| WccAttributes {
            size: attributes.size,
            change_id: attributes.change_id,
            modify_time: attributes.modify_time,
            change_time: attributes.change_time,
        })
    }

    fn find_child(&self, directory: &Node, requested: &[u8]) -> Option<(Vec<u8>, u64)> {
        if self.profile == CertificationProfile::CaseInsensitive {
            directory
                .children
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(requested))
                .map(|(name, id)| (name.clone(), *id))
        } else {
            directory.children.get(requested).copied().map(|id| (requested.to_vec(), id))
        }
    }

    fn bump_change(node: &mut Node) -> Result<(), NfsError> {
        node.modified = node.modified.checked_add(1).ok_or(NfsError::NoSpace)?;
        Ok(())
    }

    fn decrement_link_and_collect(state: &mut State, file_id: u64) -> Result<(), NfsError> {
        let remove = {
            let node = state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?;
            node.links = node.links.saturating_sub(1);
            Self::bump_change(node)?;
            node.links == 0 && node.open_pins.is_empty()
        };
        if remove {
            state.nodes.remove(&file_id);
        }
        Ok(())
    }

    fn directory_contains(state: &State, ancestor: u64, candidate: u64) -> bool {
        let mut pending = vec![ancestor];
        let mut visited = HashSet::new();
        while let Some(file_id) = pending.pop() {
            if file_id == candidate {
                return true;
            }
            if !visited.insert(file_id) {
                continue;
            }
            if let Some(node) = state.nodes.get(&file_id) {
                pending.extend(node.children.values().filter(|child| {
                    state
                        .nodes
                        .get(child)
                        .is_some_and(|child_node| child_node.file_type == FileType::Directory)
                }));
            }
        }
        false
    }

    fn created(
        state: &State,
        parent: u64,
        file_id: u64,
        before: Option<WccAttributes>,
    ) -> MutationResult<CreatedObject> {
        Self::mutation(
            CreatedObject {
                object: Self::key(file_id),
                attributes: Self::attributes(state, file_id).ok(),
            },
            before,
            Self::attributes(state, parent).ok(),
        )
    }

    fn mutation<T>(value: T, before: Option<WccAttributes>, after: Option<FileAttributes>) -> MutationResult<T> {
        let change_info = before.as_ref().zip(after.as_ref()).map(|(before, after)| ChangeInfo {
            atomic: true,
            before: before.change_id,
            after: after.change_id,
        });
        MutationResult {
            value,
            change_info,
            before,
            after,
        }
    }

    fn checked_file_size(size: u64) -> Result<usize, NfsError> {
        if size > MAX_FILE_SIZE {
            return Err(NfsError::FileTooLarge);
        }
        usize::try_from(size).map_err(|_| NfsError::FileTooLarge)
    }

    fn requested_attribute_size(file_type: FileType, size: Option<u64>) -> Result<Option<usize>, NfsError> {
        let Some(size) = size else {
            return Ok(None);
        };
        match file_type {
            FileType::Regular => Self::checked_file_size(size).map(Some),
            FileType::Directory => Err(NfsError::IsDirectory),
            _ => Err(NfsError::Invalid),
        }
    }

    fn reserve_file_size(&self, node: &mut Node, size: usize) -> Result<(), NfsError> {
        if size > node.data.len() {
            #[cfg(test)]
            self.file_reservation_attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            node.data
                .try_reserve_exact(size - node.data.len())
                .map_err(|_| NfsError::NoSpace)?;
        }
        Ok(())
    }

    fn apply_attributes(&self, node: &mut Node, attributes: SetAttributes) -> Result<(), NfsError> {
        let requested_size = Self::requested_attribute_size(node.file_type, attributes.size)?;
        if let Some(size) = requested_size {
            self.reserve_file_size(node, size)?;
        }

        let mut changed =
            attributes.access_time.is_some() || attributes.modify_time.is_some() || attributes.acl.is_some();
        if let Some(mode) = attributes.mode {
            changed |= node.mode != mode;
            node.mode = mode;
        }
        if let Some(uid) = attributes.uid {
            changed |= node.uid != uid;
            node.uid = uid;
        }
        if let Some(gid) = attributes.gid {
            changed |= node.gid != gid;
            node.gid = gid;
        }
        if let Some(size) = requested_size {
            changed |= node.data.len() != size;
            node.data.resize(size, 0);
        }
        if changed {
            Self::bump_change(node)?;
        }
        Ok(())
    }

    fn validate_open_snapshot(
        &self,
        context: &RequestContext,
        state: &State,
        parent: u64,
        name: &NfsName,
        request: &Nfs4OpenRequest,
    ) -> Result<Option<u64>, NfsError> {
        if (request.create.is_some() || request.truncate_existing) && self.profile == CertificationProfile::ReadOnly {
            return Err(NfsError::ReadOnly);
        }
        let directory = state.nodes.get(&parent).ok_or(NfsError::Stale)?;
        if directory.file_type != FileType::Directory {
            return Err(NfsError::NotDirectory);
        }
        Self::require_permissions(context, directory, 0o1)?;
        let existing = self.find_child(directory, name.as_bytes()).map(|(_, file_id)| file_id);

        if let Some(file_id) = existing {
            // RFC 7530 gives an existing GUARDED name precedence over target
            // type errors. Keep this check before loading the target node.
            if request
                .create
                .as_ref()
                .is_some_and(|create| matches!(create.mode, CreateMode::Guarded))
            {
                return Err(NfsError::Exists);
            }
            if let Some(create) = &request.create {
                if let CreateMode::Exclusive { verifier } = create.mode {
                    if state.nodes.get(&file_id).and_then(|node| node.exclusive_verifier) != Some(verifier) {
                        return Err(NfsError::Exists);
                    }
                }
            }
            let node = state.nodes.get(&file_id).ok_or(NfsError::Stale)?;
            match node.file_type {
                FileType::Regular => {},
                FileType::Directory => return Err(NfsError::IsDirectory),
                _ => return Err(NfsError::BadType),
            }
            Self::require_open_access(context, node, request.access)?;
            if request.truncate_existing {
                // A read share does not imply authority to modify file data.
                // OPEN must check truncate permission independently in both
                // preflight and the atomic transaction.
                Self::require_permissions(context, node, 0o2)?;
            }
            return Ok(Some(file_id));
        }

        let Some(create) = &request.create else {
            return Err(NfsError::NotFound);
        };
        Self::require_permissions(context, directory, 0o3)?;
        state.next_id.checked_add(1).ok_or(NfsError::NoSpace)?;
        // Validate every fallible create-attribute constraint without
        // reserving or allocating resources during the side-effect-free
        // preflight. Allocation is deferred to the atomic OPEN phase.
        Self::requested_attribute_size(FileType::Regular, create.attributes.size)?;
        Ok(None)
    }

    fn open_invocation(
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        request: Nfs4OpenRequest,
        transaction: Nfs4OpenTransaction,
    ) -> OpenInvocation {
        OpenInvocation {
            principal: context.principal.clone(),
            export_id: context.export_id,
            protocol: context.protocol,
            client_id: context.client_id,
            parent,
            name: name.clone(),
            request,
            transaction,
        }
    }

    fn open_context_matches(invocation: &OpenInvocation, context: &RequestContext) -> bool {
        invocation.principal == context.principal
            && invocation.export_id == context.export_id
            && invocation.protocol == context.protocol
            && invocation.client_id == context.client_id
    }

    fn execute_open_transaction(
        &self,
        context: &RequestContext,
        state: &mut State,
        invocation: &OpenInvocation,
    ) -> Result<Nfs4OpenResult, NfsError> {
        self.check_context(context)?;
        let parent = Self::object_id(invocation.parent)?;
        let before = Self::attributes(state, parent)?.change_id;
        let observed = self.validate_open_snapshot(context, state, parent, &invocation.name, &invocation.request)?;
        match (invocation.transaction.expected, observed) {
            (Nfs4OpenExpectation::Existing(expected), Some(file_id)) if expected == Self::key(file_id) => {},
            (Nfs4OpenExpectation::Missing, None) => {},
            // GUARDED insertion races retain their precise error instead of
            // becoming a generic retry response.
            (Nfs4OpenExpectation::Missing, Some(_))
                if invocation
                    .request
                    .create
                    .as_ref()
                    .is_some_and(|create| matches!(create.mode, CreateMode::Guarded)) =>
            {
                return Err(NfsError::Exists);
            },
            _ => return Err(NfsError::Jukebox),
        }

        let file_id = if let Some(file_id) = observed {
            let node = state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?;
            if invocation.request.truncate_existing && !node.data.is_empty() {
                // Reserve the change-id transition before pin installation so
                // every subsequent step in the in-memory transaction is
                // infallible.
                node.modified.checked_add(1).ok_or(NfsError::NoSpace)?;
            }
            if invocation.transaction.acquire_pin {
                node.open_pins.insert(invocation.transaction.pin_id);
            }
            if invocation.request.truncate_existing && !node.data.is_empty() {
                node.data.clear();
                node.modified += 1;
            }
            file_id
        } else {
            let create = invocation.request.create.as_ref().ok_or(NfsError::NotFound)?;
            let file_id = state.next_id;
            let next_id = state.next_id.checked_add(1).ok_or(NfsError::NoSpace)?;
            state
                .nodes
                .get(&parent)
                .ok_or(NfsError::Stale)?
                .modified
                .checked_add(1)
                .ok_or(NfsError::NoSpace)?;
            let mut node = Node::new(FileType::Regular, 0o666);
            if let CreateMode::Exclusive { verifier } = create.mode {
                node.exclusive_verifier = Some(verifier);
            }
            self.apply_attributes(&mut node, create.attributes.clone())?;
            if invocation.transaction.acquire_pin {
                // The pin is part of the unpublished object. Namespace
                // publication below therefore cannot race ahead of retention.
                node.open_pins.insert(invocation.transaction.pin_id);
            }
            state.next_id = next_id;
            state.nodes.insert(file_id, node);
            let directory = state.nodes.get_mut(&parent).ok_or(NfsError::Stale)?;
            directory.children.insert(invocation.name.as_bytes().to_vec(), file_id);
            directory.modified += 1;
            file_id
        };

        let after = Self::attributes(state, parent)?.change_id;
        Ok(Nfs4OpenResult {
            value: CreatedObject {
                object: Self::key(file_id),
                attributes: Some(Self::attributes(state, file_id)?),
            },
            change_info: ChangeInfo {
                atomic: true,
                before,
                after,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn create_node(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        file_type: FileType,
        attributes: SetAttributes,
        device: Option<DeviceNumber>,
        exclusive_verifier: Option<[u8; 8]>,
        allow_existing: bool,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.check_mutable(context)?;
        let parent = Self::object_id(parent)?;
        let mut state = self.state.lock().unwrap();
        let before = Self::wcc(&state, parent);
        let existing = {
            let directory = state.nodes.get(&parent).ok_or(NfsError::Stale)?;
            if directory.file_type != FileType::Directory {
                return Err(NfsError::NotDirectory);
            }
            self.find_child(directory, name.as_bytes()).map(|(_, id)| id)
        };
        if let Some(file_id) = existing {
            let same_exclusive_verifier = exclusive_verifier.is_some_and(|verifier| {
                state.nodes.get(&file_id).and_then(|node| node.exclusive_verifier) == Some(verifier)
            });
            if allow_existing || same_exclusive_verifier {
                return Ok(Self::created(&state, parent, file_id, before));
            }
            return Err(NfsError::Exists);
        }
        let file_id = state.next_id;
        state.next_id = state.next_id.checked_add(1).ok_or(NfsError::NoSpace)?;
        let mut node = Node::new(file_type, if file_type == FileType::Directory { 0o777 } else { 0o666 });
        node.device = device;
        node.exclusive_verifier = exclusive_verifier;
        self.apply_attributes(&mut node, attributes)?;
        if file_type == FileType::Directory {
            state
                .nodes
                .get(&parent)
                .ok_or(NfsError::Stale)?
                .links
                .checked_add(1)
                .ok_or(NfsError::TooManyLinks)?;
        }
        state.nodes.insert(file_id, node);
        let directory = state.nodes.get_mut(&parent).ok_or(NfsError::Stale)?;
        directory.children.insert(name.as_bytes().to_vec(), file_id);
        if file_type == FileType::Directory {
            directory.links += 1;
        }
        Self::bump_change(directory)?;
        Ok(Self::created(&state, parent, file_id, before))
    }
}

#[async_trait]
impl VirtualFileSystem for CertificationVfs {
    fn capabilities(&self) -> VfsCapabilities {
        if self.profile == CertificationProfile::ReadOnly {
            VfsCapabilities::READ_ONLY
        } else {
            VfsCapabilities::READ_WRITE
        }
    }

    fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
        Some(if self.profile == CertificationProfile::ReadOnly {
            Nfs4Capabilities::READ_ONLY
        } else {
            Nfs4Capabilities::READ_WRITE
        })
    }

    fn root(&self) -> ObjectKey {
        Self::key(ROOT_ID)
    }

    async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
        self.check_context(context)?;
        Self::attributes(&self.state.lock().unwrap(), Self::object_id(object)?)
    }

    async fn lookup(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError> {
        self.check_context(context)?;
        let state = self.state.lock().unwrap();
        let directory = state.nodes.get(&Self::object_id(parent)?).ok_or(NfsError::Stale)?;
        if directory.file_type != FileType::Directory {
            return Err(NfsError::NotDirectory);
        }
        let (_, file_id) = self.find_child(directory, name.as_bytes()).ok_or(NfsError::NotFound)?;
        Ok(CreatedObject {
            object: Self::key(file_id),
            attributes: Self::attributes(&state, file_id).ok(),
        })
    }

    async fn lookup_parent(&self, context: &RequestContext, directory: ObjectKey) -> Result<CreatedObject, NfsError> {
        self.check_context(context)?;
        let directory = Self::object_id(directory)?;
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&directory).ok_or(NfsError::Stale)?;
        if node.file_type != FileType::Directory {
            return Err(NfsError::NotDirectory);
        }
        let parent = if directory == ROOT_ID {
            ROOT_ID
        } else {
            state
                .nodes
                .iter()
                .find_map(|(file_id, candidate)| {
                    candidate.children.values().any(|child| *child == directory).then_some(*file_id)
                })
                .ok_or(NfsError::NotFound)?
        };
        Ok(CreatedObject {
            object: Self::key(parent),
            attributes: Self::attributes(&state, parent).ok(),
        })
    }

    async fn nfs4_open_preflight(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        request: &Nfs4OpenRequest,
    ) -> Result<Nfs4OpenPreflight, NfsError> {
        self.check_context(context)?;
        let parent = Self::object_id(parent)?;
        let state = self.state.lock().unwrap();
        let before = Self::attributes(&state, parent)?.change_id;
        let target = match self.validate_open_snapshot(context, &state, parent, name, request)? {
            Some(file_id) => Nfs4OpenTarget::Existing(CreatedObject {
                object: Self::key(file_id),
                attributes: Self::attributes(&state, file_id).ok(),
            }),
            None => Nfs4OpenTarget::Missing,
        };
        let after = Self::attributes(&state, parent)?.change_id;
        Ok(Nfs4OpenPreflight {
            target,
            change_info: ChangeInfo {
                atomic: true,
                before,
                after,
            },
        })
    }

    async fn nfs4_open(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        request: Nfs4OpenRequest,
        transaction: Nfs4OpenTransaction,
    ) -> Result<Nfs4OpenResult, NfsError> {
        let invocation = Self::open_invocation(context, parent, name, request, transaction);
        let mut state = self.state.lock().unwrap();
        if let Some(record) = state.open_outcomes.get(&transaction.operation_id) {
            if record.invocation() != &invocation {
                return Err(NfsError::Invalid);
            }
            return match record {
                OpenOutcomeRecord::Pending(_) => Err(NfsError::Jukebox),
                OpenOutcomeRecord::Complete { outcome, .. } => outcome.clone(),
            };
        }
        if transaction.expected == Nfs4OpenExpectation::Missing && !transaction.acquire_pin {
            return Err(NfsError::Invalid);
        }
        if state.open_outcomes.len() >= MAX_OPEN_OUTCOMES {
            return Err(NfsError::Jukebox);
        }
        // Reserve the live outcome slot before any authorization or mutation.
        // A durable backend would persist this Pending record in the same
        // cancellation-safe transaction protocol.
        state
            .open_outcomes
            .insert(transaction.operation_id, OpenOutcomeRecord::Pending(invocation.clone()));
        let outcome = self.execute_open_transaction(context, &mut state, &invocation);
        state.open_outcomes.insert(
            transaction.operation_id,
            OpenOutcomeRecord::Complete {
                invocation,
                outcome: outcome.clone(),
            },
        );
        outcome
    }

    async fn nfs4_finish_open_operation(&self, context: &RequestContext, operation_id: u64) -> Result<(), NfsError> {
        let mut state = self.state.lock().unwrap();
        let Some(record) = state.open_outcomes.get(&operation_id) else {
            self.check_context(context)?;
            return Ok(());
        };
        if !Self::open_context_matches(record.invocation(), context) {
            return Err(NfsError::Invalid);
        }
        state.open_outcomes.remove(&operation_id);
        Ok(())
    }

    async fn retain_open_object(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        open_instance: [u8; 16],
    ) -> Result<(), NfsError> {
        self.check_context(context)?;
        let file_id = Self::object_id(object)?;
        let mut state = self.state.lock().unwrap();
        state
            .nodes
            .get_mut(&file_id)
            .ok_or(NfsError::Stale)?
            .open_pins
            .insert(open_instance);
        Ok(())
    }

    async fn release_open_object(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        open_instance: [u8; 16],
    ) -> Result<(), NfsError> {
        self.check_context(context)?;
        let file_id = Self::object_id(object)?;
        let mut state = self.state.lock().unwrap();
        let remove = {
            let Some(node) = state.nodes.get_mut(&file_id) else {
                return Ok(());
            };
            node.open_pins.remove(&open_instance);
            node.links == 0 && node.open_pins.is_empty()
        };
        if remove {
            state.nodes.remove(&file_id);
        }
        Ok(())
    }

    async fn access(&self, context: &RequestContext, _object: ObjectKey, requested: u32) -> Result<u32, NfsError> {
        self.check_context(context)?;
        const MUTATING: u32 = 0x0004 | 0x0008 | 0x0010;
        Ok(if self.profile == CertificationProfile::ReadOnly {
            requested & !MUTATING
        } else {
            requested
        })
    }

    async fn setattr(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        attributes: SetAttributes,
        guard: Option<NfsTime>,
    ) -> Result<MutationResult<()>, NfsError> {
        self.check_mutable(context)?;
        let file_id = Self::object_id(object)?;
        let mut state = self.state.lock().unwrap();
        if let Some(guard) = guard {
            if guard != Self::attributes(&state, file_id)?.change_time {
                return Err(NfsError::NotSynchronized);
            }
        }
        let before = Self::wcc(&state, file_id);
        self.apply_attributes(state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?, attributes)?;
        Ok(Self::mutation((), before, Self::attributes(&state, file_id).ok()))
    }

    async fn readlink(&self, context: &RequestContext, object: ObjectKey) -> Result<Vec<u8>, NfsError> {
        self.check_context(context)?;
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&Self::object_id(object)?).ok_or(NfsError::Stale)?;
        if node.file_type == FileType::Symlink {
            Ok(node.symlink.clone())
        } else {
            Err(NfsError::Invalid)
        }
    }

    async fn read(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, NfsError> {
        self.check_context(context)?;
        let state = self.state.lock().unwrap();
        let file_id = Self::object_id(object)?;
        let node = state.nodes.get(&file_id).ok_or(NfsError::Stale)?;
        if node.file_type != FileType::Regular {
            return Err(NfsError::Invalid);
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(node.data.len());
        let end = start.saturating_add(count as usize).min(node.data.len());
        Ok(ReadResult {
            data: node.data[start..end].to_vec(),
            eof: end == node.data.len(),
            attributes: Self::attributes(&state, file_id).ok(),
        })
    }

    async fn nfs4_check_zero_length_write(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        _offset: u64,
        _requested: WriteStability,
    ) -> Result<(), NfsError> {
        self.check_mutable(context)?;
        let file_id = Self::object_id(object)?;
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&file_id).ok_or(NfsError::Stale)?;
        match node.file_type {
            FileType::Regular => {},
            FileType::Directory => return Err(NfsError::IsDirectory),
            _ => return Err(NfsError::Invalid),
        }
        Self::require_permissions(context, node, 0o2)
    }

    async fn write(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        data: &[u8],
        requested: WriteStability,
    ) -> Result<MutationResult<WriteResult>, NfsError> {
        self.check_mutable(context)?;
        let file_id = Self::object_id(object)?;
        let mut state = self.state.lock().unwrap();
        let node = state.nodes.get(&file_id).ok_or(NfsError::Stale)?;
        match node.file_type {
            FileType::Regular => {},
            FileType::Directory => return Err(NfsError::IsDirectory),
            _ => return Err(NfsError::Invalid),
        }
        Self::require_permissions(context, node, 0o2)?;
        let before = Self::wcc(&state, file_id);
        let node = state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?;
        let count = u32::try_from(data.len()).map_err(|_| NfsError::FileTooLarge)?;
        if data.is_empty() {
            return Ok(Self::mutation(
                WriteResult {
                    count,
                    committed: requested,
                },
                before,
                Self::attributes(&state, file_id).ok(),
            ));
        }
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| NfsError::FileTooLarge)?)
            .ok_or(NfsError::FileTooLarge)?;
        let start = Self::checked_file_size(offset)?;
        let end = Self::checked_file_size(end)?;
        self.reserve_file_size(node, end)?;
        if end > node.data.len() {
            node.data.resize(end, 0);
        }
        node.data[start..end].copy_from_slice(data);
        Self::bump_change(node)?;
        Ok(Self::mutation(
            WriteResult {
                count,
                committed: requested,
            },
            before,
            Self::attributes(&state, file_id).ok(),
        ))
    }

    async fn create(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
        mode: CreateMode,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_node(
            context,
            parent,
            name,
            FileType::Regular,
            attributes,
            None,
            match mode {
                CreateMode::Exclusive { verifier } => Some(verifier),
                _ => None,
            },
            mode == CreateMode::Unchecked,
        )
    }

    async fn mkdir(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_node(context, parent, name, FileType::Directory, attributes, None, None, false)
    }

    async fn symlink(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        target: &[u8],
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        let result = self.create_node(context, parent, name, FileType::Symlink, attributes, None, None, false)?;
        let mut state = self.state.lock().unwrap();
        let node = state.nodes.get_mut(&result.value.object.file_id).ok_or(NfsError::Stale)?;
        node.symlink = target.to_vec();
        Self::bump_change(node)?;
        Ok(Self::created(&state, Self::object_id(parent)?, result.value.object.file_id, result.before))
    }

    async fn mknod(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        node_type: NodeType,
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        let (file_type, device) = match node_type {
            NodeType::BlockDevice { major, minor } => (FileType::BlockDevice, Some(DeviceNumber { major, minor })),
            NodeType::CharacterDevice { major, minor } => {
                (FileType::CharacterDevice, Some(DeviceNumber { major, minor }))
            },
            NodeType::Socket => (FileType::Socket, None),
            NodeType::Fifo => (FileType::Fifo, None),
        };
        self.create_node(context, parent, name, file_type, attributes, device, None, false)
    }

    async fn remove(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.check_mutable(context)?;
        let parent = Self::object_id(parent)?;
        let mut state = self.state.lock().unwrap();
        let before = Self::wcc(&state, parent);
        let (stored_name, file_id) = {
            let directory = state.nodes.get(&parent).ok_or(NfsError::Stale)?;
            self.find_child(directory, name.as_bytes()).ok_or(NfsError::NotFound)?
        };
        if state.nodes.get(&file_id).ok_or(NfsError::Stale)?.file_type == FileType::Directory {
            return Err(NfsError::IsDirectory);
        }
        state.nodes.get_mut(&parent).unwrap().children.remove(&stored_name);
        Self::bump_change(state.nodes.get_mut(&parent).ok_or(NfsError::Stale)?)?;
        Self::decrement_link_and_collect(&mut state, file_id)?;
        Ok(Self::mutation((), before, Self::attributes(&state, parent).ok()))
    }

    async fn rmdir(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.check_mutable(context)?;
        let parent = Self::object_id(parent)?;
        let mut state = self.state.lock().unwrap();
        let before = Self::wcc(&state, parent);
        let (stored_name, file_id) = {
            let directory = state.nodes.get(&parent).ok_or(NfsError::Stale)?;
            self.find_child(directory, name.as_bytes()).ok_or(NfsError::NotFound)?
        };
        let node = state.nodes.get(&file_id).ok_or(NfsError::Stale)?;
        if node.file_type != FileType::Directory {
            return Err(NfsError::NotDirectory);
        }
        if !node.children.is_empty() {
            return Err(NfsError::NotEmpty);
        }
        state.nodes.get_mut(&parent).unwrap().children.remove(&stored_name);
        state.nodes.remove(&file_id);
        let parent_node = state.nodes.get_mut(&parent).ok_or(NfsError::Stale)?;
        parent_node.links = parent_node.links.checked_sub(1).ok_or(NfsError::ServerFault)?;
        Self::bump_change(parent_node)?;
        Ok(Self::mutation((), before, Self::attributes(&state, parent).ok()))
    }

    async fn rename(
        &self,
        context: &RequestContext,
        from_parent: ObjectKey,
        from_name: &NfsName,
        to_parent: ObjectKey,
        to_name: &NfsName,
    ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
        self.check_mutable(context)?;
        let from_parent = Self::object_id(from_parent)?;
        let to_parent = Self::object_id(to_parent)?;
        let mut state = self.state.lock().unwrap();
        for parent in [from_parent, to_parent] {
            if state.nodes.get(&parent).ok_or(NfsError::Stale)?.file_type != FileType::Directory {
                return Err(NfsError::NotDirectory);
            }
        }
        let from_before = Self::wcc(&state, from_parent);
        let to_before = Self::wcc(&state, to_parent);
        let (stored_name, file_id) = {
            let directory = state.nodes.get(&from_parent).ok_or(NfsError::Stale)?;
            self.find_child(directory, from_name.as_bytes()).ok_or(NfsError::NotFound)?
        };
        let source_type = state.nodes.get(&file_id).ok_or(NfsError::Stale)?.file_type;
        let target = {
            let directory = state.nodes.get(&to_parent).ok_or(NfsError::Stale)?;
            self.find_child(directory, to_name.as_bytes())
        };

        // Renaming a name onto itself, or onto another hard link for the
        // same object, leaves the namespace and both change values intact.
        if target.as_ref().is_some_and(|(_, target_id)| *target_id == file_id) {
            return Ok((
                Self::mutation((), from_before, Self::attributes(&state, from_parent).ok()),
                Self::mutation((), to_before, Self::attributes(&state, to_parent).ok()),
            ));
        }

        if source_type == FileType::Directory && Self::directory_contains(&state, file_id, to_parent) {
            return Err(NfsError::Invalid);
        }

        let target_type = target
            .as_ref()
            .map(|(_, target_id)| state.nodes.get(target_id).ok_or(NfsError::Stale).map(|node| node.file_type))
            .transpose()?;
        match (source_type == FileType::Directory, target_type) {
            (true, Some(FileType::Directory)) => {
                let target_id = target.as_ref().expect("target type came from a target").1;
                if !state.nodes.get(&target_id).ok_or(NfsError::Stale)?.children.is_empty() {
                    return Err(NfsError::NotEmpty);
                }
            },
            (true, Some(_)) => return Err(NfsError::NotDirectory),
            (false, Some(FileType::Directory)) => return Err(NfsError::IsDirectory),
            _ => {},
        }

        state
            .nodes
            .get_mut(&from_parent)
            .expect("source parent was validated")
            .children
            .remove(&stored_name);
        if let Some((target_name, _)) = &target {
            state
                .nodes
                .get_mut(&to_parent)
                .expect("target parent was validated")
                .children
                .remove(target_name);
        }
        state
            .nodes
            .get_mut(&to_parent)
            .expect("target parent was validated")
            .children
            .insert(to_name.as_bytes().to_vec(), file_id);

        let target_is_directory = target_type == Some(FileType::Directory);
        if source_type == FileType::Directory {
            if from_parent != to_parent {
                let parent = state.nodes.get_mut(&from_parent).expect("source parent was validated");
                parent.links = parent.links.checked_sub(1).ok_or(NfsError::ServerFault)?;
                if !target_is_directory {
                    let parent = state.nodes.get_mut(&to_parent).expect("target parent was validated");
                    parent.links = parent.links.checked_add(1).ok_or(NfsError::TooManyLinks)?;
                }
            } else if target_is_directory {
                let parent = state.nodes.get_mut(&from_parent).expect("source parent was validated");
                parent.links = parent.links.checked_sub(1).ok_or(NfsError::ServerFault)?;
            }
        }

        if from_parent == to_parent {
            Self::bump_change(state.nodes.get_mut(&from_parent).expect("source parent was validated"))?;
        } else {
            Self::bump_change(state.nodes.get_mut(&from_parent).expect("source parent was validated"))?;
            Self::bump_change(state.nodes.get_mut(&to_parent).expect("target parent was validated"))?;
        }
        if let Some((_, replaced)) = target {
            if target_is_directory {
                state.nodes.remove(&replaced);
            } else {
                Self::decrement_link_and_collect(&mut state, replaced)?;
            }
        }
        Ok((
            Self::mutation((), from_before, Self::attributes(&state, from_parent).ok()),
            Self::mutation((), to_before, Self::attributes(&state, to_parent).ok()),
        ))
    }

    async fn link(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        to_parent: ObjectKey,
        to_name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.check_mutable(context)?;
        let file_id = Self::object_id(object)?;
        let parent = Self::object_id(to_parent)?;
        let mut state = self.state.lock().unwrap();
        if state.nodes.get(&file_id).ok_or(NfsError::Stale)?.file_type == FileType::Directory {
            return Err(NfsError::IsDirectory);
        }
        let before = Self::wcc(&state, parent);
        let directory = state.nodes.get(&parent).ok_or(NfsError::Stale)?;
        if directory.file_type != FileType::Directory {
            return Err(NfsError::NotDirectory);
        }
        if self.find_child(directory, to_name.as_bytes()).is_some() {
            return Err(NfsError::Exists);
        }
        state
            .nodes
            .get(&file_id)
            .ok_or(NfsError::Stale)?
            .links
            .checked_add(1)
            .ok_or(NfsError::TooManyLinks)?;
        let directory = state.nodes.get_mut(&parent).expect("target parent was validated");
        directory.children.insert(to_name.as_bytes().to_vec(), file_id);
        Self::bump_change(directory)?;
        let node = state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?;
        node.links = node.links.checked_add(1).ok_or(NfsError::TooManyLinks)?;
        Self::bump_change(node)?;
        Ok(Self::mutation((), before, Self::attributes(&state, parent).ok()))
    }

    async fn readdir(
        &self,
        context: &RequestContext,
        directory: ObjectKey,
        cookie: u64,
        verifier: [u8; 8],
        backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        self.check_context(context)?;
        if cookie != 0 && verifier != VERIFIER {
            return Err(NfsError::BadCookie);
        }
        let state = self.state.lock().unwrap();
        let node = state.nodes.get(&Self::object_id(directory)?).ok_or(NfsError::Stale)?;
        if node.file_type != FileType::Directory {
            return Err(NfsError::NotDirectory);
        }
        let (start, cookie_base) = match context.protocol {
            ProtocolVersion::V3 => (usize::try_from(cookie).unwrap_or(usize::MAX), 1_u64),
            ProtocolVersion::V4 => {
                let start = if cookie == 0 {
                    0
                } else {
                    usize::try_from(cookie.checked_sub(2).ok_or(NfsError::BadCookie)?).unwrap_or(usize::MAX)
                };
                (start, 3)
            },
        };
        let entries = node
            .children
            .iter()
            .enumerate()
            .skip(start)
            .take(backend_hint.max(1))
            .map(|(index, (name, file_id))| DirectoryEntry {
                object: Self::key(*file_id),
                file_id: *file_id,
                name: NfsName::new(name.clone()).unwrap(),
                cookie: index as u64 + cookie_base,
                attributes: Self::attributes(&state, *file_id).ok(),
            })
            .collect::<Vec<_>>();
        Ok(ReadDirectoryPage {
            verifier: VERIFIER,
            eof: start.saturating_add(entries.len()) >= node.children.len(),
            entries,
        })
    }

    async fn fsstat(&self, context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        self.check_context(context)?;
        Ok(FsStat {
            total_bytes: 1 << 40,
            free_bytes: 1 << 39,
            available_bytes: 1 << 39,
            total_files: 1_000_000,
            free_files: 999_000,
            available_files: 999_000,
            invariant_seconds: 1,
        })
    }

    async fn fsinfo(&self, context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
        self.check_context(context)?;
        Ok(FsInfo {
            max_read: 1024 * 1024,
            preferred_read: 128 * 1024,
            read_multiple: 4096,
            max_write: 1024 * 1024,
            preferred_write: 128 * 1024,
            write_multiple: 4096,
            preferred_readdir: 32 * 1024,
            max_file_size: MAX_FILE_SIZE,
            time_granularity: NfsTime {
                seconds: 0,
                nanoseconds: 1,
            },
        })
    }

    async fn pathconf(&self, context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        self.check_context(context)?;
        Ok(PathConf {
            max_links: u32::MAX,
            max_name_length: NfsName::MAX_LEN as u32,
            no_truncation: true,
            chown_restricted: false,
            case_insensitive: self.profile == CertificationProfile::CaseInsensitive,
            case_preserving: true,
        })
    }

    async fn commit(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<MutationResult<()>, NfsError> {
        self.check_mutable(context)?;
        let file_id = Self::object_id(object)?;
        let state = self.state.lock().unwrap();
        Ok(Self::mutation((), Self::wcc(&state, file_id), Self::attributes(&state, file_id).ok()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_OPEN_OPERATION: AtomicU64 = AtomicU64::new(1);

    fn context() -> RequestContext {
        RequestContext {
            principal: Principal::Anonymous,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            export_id: ExportId(1),
            protocol: nfsembed::vfs::ProtocolVersion::V3,
            client_id: None,
        }
    }

    fn v4_context() -> RequestContext {
        RequestContext {
            protocol: nfsembed::vfs::ProtocolVersion::V4,
            client_id: Some(42),
            ..context()
        }
    }

    fn open_transaction(expected: Nfs4OpenExpectation, acquire_pin: bool) -> Nfs4OpenTransaction {
        let operation_id = NEXT_OPEN_OPERATION.fetch_add(1, Ordering::Relaxed);
        let mut pin_id = [0; 16];
        pin_id[8..].copy_from_slice(&operation_id.to_be_bytes());
        Nfs4OpenTransaction {
            operation_id,
            expected,
            pin_id,
            acquire_pin,
        }
    }

    async fn execute_open(
        vfs: &CertificationVfs,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        request: Nfs4OpenRequest,
    ) -> Result<Nfs4OpenResult, NfsError> {
        let preflight = vfs.nfs4_open_preflight(context, parent, name, &request).await?;
        let transaction = open_transaction(preflight.target.expectation(), true);
        let result = vfs.nfs4_open(context, parent, name, request, transaction).await;
        vfs.nfs4_finish_open_operation(context, transaction.operation_id).await?;
        result
    }

    #[tokio::test]
    async fn guarded_setattr_checks_change_time_before_mutating() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let object = CertificationVfs::key(2);
        let original = vfs.getattr(&context(), object).await.unwrap();
        let mut attributes = SetAttributes::default();
        attributes.mode = Some(0o600);

        assert!(matches!(
            vfs.setattr(
                &context(),
                object,
                attributes.clone(),
                Some(NfsTime {
                    seconds: original.change_time.seconds + 1,
                    nanoseconds: original.change_time.nanoseconds,
                }),
            )
            .await,
            Err(NfsError::NotSynchronized)
        ));
        assert_eq!(vfs.getattr(&context(), object).await.unwrap().mode, original.mode);

        vfs.setattr(&context(), object, attributes, Some(original.change_time))
            .await
            .unwrap();
        assert_eq!(vfs.getattr(&context(), object).await.unwrap().mode, 0o600);
    }

    #[tokio::test]
    async fn zero_length_write_check_authorizes_without_mutating() {
        let writable = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let object = CertificationVfs::key(2);
        let before = writable.getattr(&v4_context(), object).await.unwrap();
        assert_eq!(
            writable
                .nfs4_check_zero_length_write(&v4_context(), object, 0, WriteStability::FileSync)
                .await,
            Ok(())
        );
        assert_eq!(writable.getattr(&v4_context(), object).await.unwrap(), before);

        let denied_vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        denied_vfs.state.lock().unwrap().nodes.get_mut(&2).unwrap().mode = 0o644;
        let denied_before = denied_vfs.getattr(&v4_context(), object).await.unwrap();
        let mut denied_context = v4_context();
        denied_context.principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"other".to_vec(),
        };
        assert_eq!(
            denied_vfs
                .nfs4_check_zero_length_write(&denied_context, object, 0, WriteStability::FileSync)
                .await,
            Err(NfsError::Access)
        );
        assert_eq!(denied_vfs.getattr(&v4_context(), object).await.unwrap(), denied_before);

        let read_only = CertificationVfs::new(ExportId(1), CertificationProfile::ReadOnly);
        let read_only_before = read_only.getattr(&v4_context(), object).await.unwrap();
        assert_eq!(
            read_only
                .nfs4_check_zero_length_write(&v4_context(), object, 0, WriteStability::FileSync)
                .await,
            Err(NfsError::ReadOnly)
        );
        assert_eq!(read_only.getattr(&v4_context(), object).await.unwrap(), read_only_before);
    }

    #[test]
    fn nfs4_capabilities_follow_the_certification_profile() {
        assert_eq!(
            CertificationVfs::new(ExportId(1), CertificationProfile::ReadOnly).nfs4_capabilities(),
            Some(Nfs4Capabilities::READ_ONLY)
        );
        for profile in [CertificationProfile::ReadWrite, CertificationProfile::CaseInsensitive] {
            assert_eq!(
                CertificationVfs::new(ExportId(1), profile).nfs4_capabilities(),
                Some(Nfs4Capabilities::READ_WRITE)
            );
        }
    }

    #[tokio::test]
    async fn nfs4_contract_supports_parent_lookup_and_atomic_open_create() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        assert_eq!(vfs.nfs4_capabilities(), Some(Nfs4Capabilities::READ_WRITE));

        let directory = vfs
            .lookup(&v4_context(), vfs.root(), &NfsName::new(b"dir".to_vec()).unwrap())
            .await
            .unwrap()
            .object;
        assert_eq!(vfs.lookup_parent(&v4_context(), directory).await.unwrap().object, vfs.root());

        let name = NfsName::new(b"opened".to_vec()).unwrap();
        let opened = execute_open(
            &vfs,
            &v4_context(),
            vfs.root(),
            &name,
            Nfs4OpenRequest {
                access: Nfs4OpenAccess::ReadWrite,
                create: Some(nfsembed::vfs::Nfs4OpenCreate {
                    attributes: SetAttributes {
                        mode: Some(0o640),
                        ..SetAttributes::default()
                    },
                    mode: CreateMode::Guarded,
                }),
                truncate_existing: false,
            },
        )
        .await
        .unwrap();
        assert!(opened.change_info.atomic && opened.change_info.after > opened.change_info.before);
        assert_eq!(opened.value.attributes.unwrap().mode, 0o640);
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object, opened.value.object);
    }

    #[tokio::test]
    async fn nfs4_open_preflight_is_side_effect_free_and_validates_the_full_request() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        let original = vfs.getattr(&v4_context(), object).await.unwrap();
        let truncate = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    size: Some(0),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Unchecked,
            }),
            truncate_existing: true,
        };

        let preflight = vfs
            .nfs4_open_preflight(&v4_context(), vfs.root(), &name, &truncate)
            .await
            .unwrap();
        assert_eq!(
            preflight.target,
            Nfs4OpenTarget::Existing(CreatedObject {
                object,
                attributes: Some(original.clone()),
            })
        );
        assert!(preflight.change_info.atomic && preflight.change_info.before == preflight.change_info.after);
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap(), original);

        let oversized_name = NfsName::new(b"oversized-open".to_vec()).unwrap();
        let oversized = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    size: Some(MAX_FILE_SIZE + 1),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Guarded,
            }),
            truncate_existing: false,
        };
        assert_eq!(
            vfs.nfs4_open_preflight(&v4_context(), vfs.root(), &oversized_name, &oversized)
                .await,
            Err(NfsError::FileTooLarge)
        );
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &oversized_name).await, Err(NfsError::NotFound));

        let read_only = CertificationVfs::new(ExportId(1), CertificationProfile::ReadOnly);
        assert_eq!(
            read_only
                .nfs4_open_preflight(&v4_context(), read_only.root(), &name, &truncate)
                .await,
            Err(NfsError::ReadOnly)
        );
    }

    #[tokio::test]
    async fn nfs4_open_preflight_validates_size_without_reserving_file_storage() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"deferred-open-allocation".to_vec()).unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    size: Some(4096),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Guarded,
            }),
            truncate_existing: false,
        };
        let reservations_before = vfs.file_reservation_attempts.load(Ordering::Relaxed);

        let preflight = vfs
            .nfs4_open_preflight(&v4_context(), vfs.root(), &name, &request)
            .await
            .unwrap();
        assert_eq!(preflight.target, Nfs4OpenTarget::Missing);
        assert_eq!(
            vfs.file_reservation_attempts.load(Ordering::Relaxed),
            reservations_before,
            "preflight must validate without attempting file-storage allocation"
        );

        let transaction = open_transaction(Nfs4OpenExpectation::Missing, true);
        let opened = vfs
            .nfs4_open(&v4_context(), vfs.root(), &name, request, transaction)
            .await
            .unwrap();
        assert_eq!(opened.value.attributes.as_ref().unwrap().size, 4096);
        assert_eq!(
            vfs.file_reservation_attempts.load(Ordering::Relaxed),
            reservations_before + 1,
            "the atomic OPEN phase must still allocate and apply the requested size"
        );
        vfs.nfs4_finish_open_operation(&v4_context(), transaction.operation_id)
            .await
            .unwrap();
        vfs.release_open_object(&v4_context(), opened.value.object, transaction.pin_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nfs4_open_expected_object_cas_never_truncates_a_replacement() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let target_name = NfsName::new(b"file".to_vec()).unwrap();
        let replacement_name = NfsName::new(b"replacement".to_vec()).unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    size: Some(0),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Unchecked,
            }),
            truncate_existing: true,
        };
        let preflight = vfs
            .nfs4_open_preflight(&v4_context(), vfs.root(), &target_name, &request)
            .await
            .unwrap();
        let transaction = open_transaction(preflight.target.expectation(), true);

        let replacement = vfs
            .create(&v4_context(), vfs.root(), &replacement_name, SetAttributes::default(), CreateMode::Guarded)
            .await
            .unwrap()
            .value
            .object;
        vfs.write(&v4_context(), replacement, 0, b"replacement-data", WriteStability::FileSync)
            .await
            .unwrap();
        vfs.rename(&v4_context(), vfs.root(), &replacement_name, vfs.root(), &target_name)
            .await
            .unwrap();

        assert_eq!(
            vfs.nfs4_open(&v4_context(), vfs.root(), &target_name, request, transaction)
                .await,
            Err(NfsError::Jukebox)
        );
        assert_eq!(vfs.read(&v4_context(), replacement, 0, u32::MAX).await.unwrap().data, b"replacement-data");
    }

    #[tokio::test]
    async fn nfs4_open_missing_cas_and_guarded_error_precedence_are_precise() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"insert-race".to_vec()).unwrap();
        let guarded = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes::default(),
                mode: CreateMode::Guarded,
            }),
            truncate_existing: false,
        };
        let preflight = vfs
            .nfs4_open_preflight(&v4_context(), vfs.root(), &name, &guarded)
            .await
            .unwrap();
        assert_eq!(preflight.target, Nfs4OpenTarget::Missing);
        vfs.mkdir(&v4_context(), vfs.root(), &name, SetAttributes::default())
            .await
            .unwrap();
        assert_eq!(
            vfs.nfs4_open(
                &v4_context(),
                vfs.root(),
                &name,
                guarded.clone(),
                open_transaction(Nfs4OpenExpectation::Missing, true),
            )
            .await,
            Err(NfsError::Exists)
        );
        // A duplicate GUARDED create reports EXISTS even though the existing
        // target is a directory and would otherwise report ISDIR.
        assert_eq!(vfs.nfs4_open_preflight(&v4_context(), vfs.root(), &name, &guarded).await, Err(NfsError::Exists));
    }

    #[tokio::test]
    async fn atomic_open_authorizes_the_requested_access_against_mode_bits() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        vfs.setattr(
            &v4_context(),
            object,
            SetAttributes {
                mode: Some(0o700),
                ..SetAttributes::default()
            },
            None,
        )
        .await
        .unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Read,
            create: None,
            truncate_existing: false,
        };
        let mut other = v4_context();
        other.principal = Principal::AuthSys {
            uid: 1,
            gid: 1,
            supplementary_gids: Vec::new(),
            machine_name: b"other".to_vec(),
        };
        assert_eq!(execute_open(&vfs, &other, vfs.root(), &name, request.clone()).await, Err(NfsError::Access));

        let mut root = v4_context();
        root.principal = Principal::AuthSys {
            uid: 0,
            gid: 0,
            supplementary_gids: Vec::new(),
            machine_name: b"root".to_vec(),
        };
        assert_eq!(
            execute_open(&vfs, &root, vfs.root(), &name, request)
                .await
                .unwrap()
                .value
                .object,
            object
        );
    }

    #[tokio::test]
    async fn read_share_does_not_authorize_truncation_in_either_open_phase() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        vfs.setattr(
            &v4_context(),
            object,
            SetAttributes {
                mode: Some(0o444),
                ..SetAttributes::default()
            },
            None,
        )
        .await
        .unwrap();
        let original = vfs.getattr(&v4_context(), object).await.unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Read,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    size: Some(0),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Unchecked,
            }),
            truncate_existing: true,
        };
        let mut reader = v4_context();
        reader.principal = Principal::AuthSys {
            uid: 7,
            gid: 7,
            supplementary_gids: Vec::new(),
            machine_name: b"reader".to_vec(),
        };

        assert_eq!(vfs.nfs4_open_preflight(&reader, vfs.root(), &name, &request).await, Err(NfsError::Access));
        assert_eq!(
            vfs.nfs4_open(
                &reader,
                vfs.root(),
                &name,
                request,
                open_transaction(Nfs4OpenExpectation::Existing(object), true),
            )
            .await,
            Err(NfsError::Access)
        );
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap(), original);
    }

    #[tokio::test]
    async fn open_metadata_is_mandatory_for_preflight_and_existing_results() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Read,
            create: None,
            truncate_existing: false,
        };
        let preflight = vfs
            .nfs4_open_preflight(&v4_context(), vfs.root(), &name, &request)
            .await
            .unwrap();
        assert!(preflight.change_info.atomic);
        assert_eq!(preflight.change_info.before, preflight.change_info.after);

        let transaction = open_transaction(preflight.target.expectation(), false);
        let opened = vfs
            .nfs4_open(&v4_context(), vfs.root(), &name, request, transaction)
            .await
            .unwrap();
        assert!(opened.change_info.atomic);
        assert_eq!(opened.change_info.before, opened.change_info.after);
        assert_eq!(
            opened.change_info,
            vfs.nfs4_open_preflight(
                &v4_context(),
                vfs.root(),
                &name,
                &Nfs4OpenRequest {
                    access: Nfs4OpenAccess::Read,
                    create: None,
                    truncate_existing: false,
                },
            )
            .await
            .unwrap()
            .change_info
        );
    }

    #[tokio::test]
    async fn open_retry_returns_the_exact_result_without_retruncating() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Write,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    size: Some(0),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Unchecked,
            }),
            truncate_existing: true,
        };
        let transaction = open_transaction(Nfs4OpenExpectation::Existing(object), true);
        let first = vfs
            .nfs4_open(&v4_context(), vfs.root(), &name, request.clone(), transaction)
            .await
            .unwrap();
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap().size, 0);

        vfs.write(&v4_context(), object, 0, b"after-first-open", WriteStability::FileSync)
            .await
            .unwrap();
        let retry = vfs
            .nfs4_open(&v4_context(), vfs.root(), &name, request, transaction)
            .await
            .unwrap();
        assert_eq!(retry, first);
        assert_eq!(vfs.read(&v4_context(), object, 0, u32::MAX).await.unwrap().data, b"after-first-open");
        vfs.nfs4_finish_open_operation(&v4_context(), transaction.operation_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_open_installs_its_pin_before_namespace_publication() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"atomically-pinned".to_vec()).unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes::default(),
                mode: CreateMode::Guarded,
            }),
            truncate_existing: false,
        };
        let transaction = open_transaction(Nfs4OpenExpectation::Missing, true);
        let opened = vfs
            .nfs4_open(&v4_context(), vfs.root(), &name, request, transaction)
            .await
            .unwrap();
        let object = opened.value.object;
        {
            let state = vfs.state.lock().unwrap();
            assert!(state
                .nodes
                .get(&object.file_id)
                .unwrap()
                .open_pins
                .contains(&transaction.pin_id));
            assert_eq!(state.nodes.get(&ROOT_ID).unwrap().children.get(name.as_bytes()), Some(&object.file_id));
        }

        vfs.nfs4_finish_open_operation(&v4_context(), transaction.operation_id)
            .await
            .unwrap();
        vfs.remove(&v4_context(), vfs.root(), &name).await.unwrap();
        assert!(vfs.getattr(&v4_context(), object).await.is_ok());
        vfs.release_open_object(&v4_context(), object, transaction.pin_id)
            .await
            .unwrap();
        assert_eq!(vfs.getattr(&v4_context(), object).await, Err(NfsError::Stale));
    }

    #[tokio::test]
    async fn missing_open_without_initial_pin_is_rejected_before_reservation() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"unretained-create".to_vec()).unwrap();
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes::default(),
                mode: CreateMode::Guarded,
            }),
            truncate_existing: false,
        };
        let transaction = open_transaction(Nfs4OpenExpectation::Missing, false);

        assert_eq!(vfs.nfs4_open(&v4_context(), vfs.root(), &name, request, transaction).await, Err(NfsError::Invalid));
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &name).await, Err(NfsError::NotFound));
        assert!(!vfs.state.lock().unwrap().open_outcomes.contains_key(&transaction.operation_id));
    }

    #[tokio::test]
    async fn open_operation_id_collision_rejects_different_arguments() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Read,
            create: None,
            truncate_existing: false,
        };
        let transaction = open_transaction(Nfs4OpenExpectation::Existing(object), false);
        vfs.nfs4_open(&v4_context(), vfs.root(), &name, request.clone(), transaction)
            .await
            .unwrap();
        let mut changed = request;
        changed.access = Nfs4OpenAccess::Write;
        assert_eq!(vfs.nfs4_open(&v4_context(), vfs.root(), &name, changed, transaction).await, Err(NfsError::Invalid));
    }

    #[tokio::test]
    async fn open_operation_identity_collision_and_mismatched_finish_preserve_the_original_outcome() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let original_context = v4_context();
        let object = vfs.lookup(&original_context, vfs.root(), &name).await.unwrap().object;
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Read,
            create: None,
            truncate_existing: false,
        };
        let transaction = open_transaction(Nfs4OpenExpectation::Existing(object), false);
        let original = vfs
            .nfs4_open(&original_context, vfs.root(), &name, request.clone(), transaction)
            .await
            .unwrap();

        let mut different_principal = original_context.clone();
        different_principal.principal = Principal::AuthSys {
            uid: 7,
            gid: 7,
            supplementary_gids: Vec::new(),
            machine_name: b"different-principal".to_vec(),
        };
        let mut different_export = original_context.clone();
        different_export.export_id = ExportId(2);
        let mut different_protocol = original_context.clone();
        different_protocol.protocol = ProtocolVersion::V3;
        let mut different_client = original_context.clone();
        different_client.client_id = Some(43);

        for mismatched in [
            different_principal,
            different_export,
            different_protocol,
            different_client,
        ] {
            assert_eq!(
                vfs.nfs4_open(&mismatched, vfs.root(), &name, request.clone(), transaction)
                    .await,
                Err(NfsError::Invalid)
            );
            assert_eq!(
                vfs.nfs4_finish_open_operation(&mismatched, transaction.operation_id).await,
                Err(NfsError::Invalid)
            );
            assert!(vfs.state.lock().unwrap().open_outcomes.contains_key(&transaction.operation_id));
            assert_eq!(
                vfs.nfs4_open(&original_context, vfs.root(), &name, request.clone(), transaction)
                    .await
                    .unwrap(),
                original
            );
        }

        vfs.nfs4_finish_open_operation(&original_context, transaction.operation_id)
            .await
            .unwrap();
        assert!(!vfs.state.lock().unwrap().open_outcomes.contains_key(&transaction.operation_id));
    }

    #[tokio::test]
    async fn open_outcome_capacity_is_reserved_and_finish_releases_it() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        let request = Nfs4OpenRequest {
            access: Nfs4OpenAccess::Read,
            create: None,
            truncate_existing: false,
        };
        let mut transactions = Vec::new();
        let mut first_result = None;
        for _ in 0..MAX_OPEN_OUTCOMES {
            let transaction = open_transaction(Nfs4OpenExpectation::Existing(object), false);
            let opened = vfs
                .nfs4_open(&v4_context(), vfs.root(), &name, request.clone(), transaction)
                .await
                .unwrap();
            if first_result.is_none() {
                first_result = Some(opened);
            }
            transactions.push(transaction);
        }
        let waiting = open_transaction(Nfs4OpenExpectation::Existing(object), false);
        assert_eq!(
            vfs.nfs4_open(&v4_context(), vfs.root(), &name, request.clone(), waiting).await,
            Err(NfsError::Jukebox)
        );
        assert_eq!(
            vfs.nfs4_open(&v4_context(), vfs.root(), &name, request.clone(), transactions[0])
                .await
                .unwrap(),
            first_result.unwrap()
        );

        vfs.nfs4_finish_open_operation(&v4_context(), transactions[0].operation_id)
            .await
            .unwrap();
        // Finish is idempotent, and the released capacity can be reserved by
        // the previously rejected operation without evicting another result.
        vfs.nfs4_finish_open_operation(&v4_context(), transactions[0].operation_id)
            .await
            .unwrap();
        vfs.nfs4_open(&v4_context(), vfs.root(), &name, request, waiting).await.unwrap();
        assert_eq!(vfs.state.lock().unwrap().open_outcomes.len(), MAX_OPEN_OUTCOMES);
    }

    #[tokio::test]
    async fn nfs4_readdir_uses_nonreserved_continuation_cookies() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let first = vfs.readdir(&v4_context(), vfs.root(), 0, [0; 8], 2).await.unwrap();
        assert_eq!(first.entries.iter().map(|entry| entry.cookie).collect::<Vec<_>>(), vec![3, 4]);
        assert!(!first.eof);

        let second = vfs.readdir(&v4_context(), vfs.root(), 4, first.verifier, 2).await.unwrap();
        assert_eq!(second.entries.iter().map(|entry| entry.cookie).collect::<Vec<_>>(), vec![5]);
        assert!(second.eof);
    }

    #[tokio::test]
    async fn oversized_setattr_is_atomic_and_leaves_the_state_usable() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let object = CertificationVfs::key(2);
        let original = vfs.getattr(&v4_context(), object).await.unwrap();

        let result = vfs
            .setattr(
                &v4_context(),
                object,
                SetAttributes {
                    mode: Some(0o600),
                    size: Some(u64::MAX),
                    ..SetAttributes::default()
                },
                None,
            )
            .await;
        assert_eq!(result, Err(NfsError::FileTooLarge));
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap(), original);

        vfs.setattr(
            &v4_context(),
            object,
            SetAttributes {
                mode: Some(0o600),
                ..SetAttributes::default()
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap().mode, 0o600);
        assert_eq!(vfs.fsinfo(&v4_context(), object).await.unwrap().max_file_size, MAX_FILE_SIZE);
    }

    #[tokio::test]
    async fn directory_write_and_size_setattr_return_is_directory_without_mutating() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let directory = vfs
            .lookup(&v4_context(), vfs.root(), &NfsName::new(b"dir".to_vec()).unwrap())
            .await
            .unwrap()
            .object;
        let original = vfs.getattr(&v4_context(), directory).await.unwrap();

        assert_eq!(
            vfs.write(&v4_context(), directory, 0, b"x", WriteStability::FileSync).await,
            Err(NfsError::IsDirectory)
        );
        assert_eq!(
            vfs.setattr(
                &v4_context(),
                directory,
                SetAttributes {
                    mode: Some(0o700),
                    size: Some(0),
                    ..SetAttributes::default()
                },
                None,
            )
            .await,
            Err(NfsError::IsDirectory)
        );
        assert_eq!(vfs.getattr(&v4_context(), directory).await.unwrap(), original);
    }

    #[tokio::test]
    async fn empty_and_oversized_writes_do_not_mutate_or_poison_state() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let object = CertificationVfs::key(2);
        let original = vfs.getattr(&v4_context(), object).await.unwrap();

        let empty = vfs
            .write(&v4_context(), object, u64::MAX, b"", WriteStability::Unstable)
            .await
            .unwrap();
        assert_eq!(empty.value.count, 0);
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap(), original);

        assert_eq!(
            vfs.write(&v4_context(), object, MAX_FILE_SIZE, b"x", WriteStability::FileSync,)
                .await,
            Err(NfsError::FileTooLarge)
        );
        assert_eq!(vfs.getattr(&v4_context(), object).await.unwrap(), original);

        vfs.write(&v4_context(), object, 0, b"x", WriteStability::FileSync)
            .await
            .unwrap();
        assert_eq!(vfs.read(&v4_context(), object, 0, 1).await.unwrap().data, b"x");
    }

    #[tokio::test]
    async fn pinned_unlinked_object_remains_usable_until_release() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"file".to_vec()).unwrap();
        let object = vfs.lookup(&v4_context(), vfs.root(), &name).await.unwrap().object;
        let pin = [0x5a; 16];

        vfs.retain_open_object(&v4_context(), object, pin).await.unwrap();
        vfs.remove(&v4_context(), vfs.root(), &name).await.unwrap();
        vfs.write(&v4_context(), object, 0, b"still-open", WriteStability::FileSync)
            .await
            .unwrap();
        assert_eq!(vfs.read(&v4_context(), object, 0, 10).await.unwrap().data, b"still-open");

        vfs.release_open_object(&v4_context(), object, pin).await.unwrap();
        assert_eq!(vfs.getattr(&v4_context(), object).await, Err(NfsError::Stale));
    }

    #[tokio::test]
    async fn replacing_a_pinned_name_does_not_invalidate_the_open_object() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let target_name = NfsName::new(b"target".to_vec()).unwrap();
        let target = vfs
            .create(&v4_context(), vfs.root(), &target_name, SetAttributes::default(), CreateMode::Guarded)
            .await
            .unwrap()
            .value
            .object;
        vfs.write(&v4_context(), target, 0, b"old-target", WriteStability::FileSync)
            .await
            .unwrap();
        let pin = [0xa5; 16];
        vfs.retain_open_object(&v4_context(), target, pin).await.unwrap();

        vfs.rename(&v4_context(), vfs.root(), &NfsName::new(b"file".to_vec()).unwrap(), vfs.root(), &target_name)
            .await
            .unwrap();
        assert_eq!(vfs.read(&v4_context(), target, 0, 10).await.unwrap().data, b"old-target");

        vfs.release_open_object(&v4_context(), target, pin).await.unwrap();
        assert_eq!(vfs.getattr(&v4_context(), target).await, Err(NfsError::Stale));
    }

    #[tokio::test]
    async fn write_preserves_the_existing_tail_and_zero_fills_sparse_extensions() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"preserve-tail".to_vec()).unwrap();
        let object = execute_open(
            &vfs,
            &v4_context(),
            vfs.root(),
            &name,
            Nfs4OpenRequest {
                access: Nfs4OpenAccess::ReadWrite,
                create: Some(nfsembed::vfs::Nfs4OpenCreate {
                    attributes: SetAttributes {
                        size: Some(32),
                        ..SetAttributes::default()
                    },
                    mode: CreateMode::Unchecked,
                }),
                truncate_existing: false,
            },
        )
        .await
        .unwrap()
        .value
        .object;

        vfs.write(&v4_context(), object, 0, b"write data", WriteStability::Unstable)
            .await
            .unwrap();
        let prefix = vfs.read(&v4_context(), object, 0, 20).await.unwrap();
        assert_eq!(prefix.data, [b"write data".as_slice(), &[0; 10]].concat());
        assert!(!prefix.eof);

        vfs.write(&v4_context(), object, 40, b"tail", WriteStability::DataSync)
            .await
            .unwrap();
        let extension = vfs.read(&v4_context(), object, 30, 20).await.unwrap();
        assert_eq!(extension.data, [&[0; 10], b"tail".as_slice()].concat());
        assert!(extension.eof);
    }

    #[tokio::test]
    async fn unchecked_open_recreate_ignores_attributes_except_zero_size_truncation() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let name = NfsName::new(b"unchecked".to_vec()).unwrap();
        let create = |mode, size, truncate_existing| Nfs4OpenRequest {
            access: Nfs4OpenAccess::ReadWrite,
            create: Some(nfsembed::vfs::Nfs4OpenCreate {
                attributes: SetAttributes {
                    mode: Some(mode),
                    size: Some(size),
                    ..SetAttributes::default()
                },
                mode: CreateMode::Unchecked,
            }),
            truncate_existing,
        };

        let object = execute_open(&vfs, &v4_context(), vfs.root(), &name, create(0o644, 32, false))
            .await
            .unwrap()
            .value
            .object;
        execute_open(&vfs, &v4_context(), vfs.root(), &name, create(0o600, 16, false))
            .await
            .unwrap();
        let recreated = vfs.getattr(&v4_context(), object).await.unwrap();
        assert_eq!(recreated.mode, 0o644);
        assert_eq!(recreated.size, 32);

        execute_open(&vfs, &v4_context(), vfs.root(), &name, create(0o600, 0, true))
            .await
            .unwrap();
        let truncated = vfs.getattr(&v4_context(), object).await.unwrap();
        assert_eq!(truncated.mode, 0o644);
        assert_eq!(truncated.size, 0);
    }

    #[tokio::test]
    async fn rename_type_errors_are_atomic_and_nonempty_directories_are_preserved() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let directory_name = NfsName::new(b"rename-dir".to_vec()).unwrap();
        let file_name = NfsName::new(b"rename-file".to_vec()).unwrap();
        let full_name = NfsName::new(b"rename-full".to_vec()).unwrap();
        let child_name = NfsName::new(b"child".to_vec()).unwrap();
        let directory = vfs
            .mkdir(&v4_context(), vfs.root(), &directory_name, SetAttributes::default())
            .await
            .unwrap()
            .value
            .object;
        let file = vfs
            .create(&v4_context(), vfs.root(), &file_name, SetAttributes::default(), CreateMode::Guarded)
            .await
            .unwrap()
            .value
            .object;
        let full = vfs
            .mkdir(&v4_context(), vfs.root(), &full_name, SetAttributes::default())
            .await
            .unwrap()
            .value
            .object;
        vfs.mkdir(&v4_context(), full, &child_name, SetAttributes::default())
            .await
            .unwrap();
        let root_before = vfs.getattr(&v4_context(), vfs.root()).await.unwrap();

        assert_eq!(
            vfs.rename(&v4_context(), vfs.root(), &directory_name, vfs.root(), &file_name)
                .await,
            Err(NfsError::NotDirectory)
        );
        assert_eq!(
            vfs.rename(&v4_context(), vfs.root(), &file_name, vfs.root(), &directory_name)
                .await,
            Err(NfsError::IsDirectory)
        );
        assert_eq!(
            vfs.rename(&v4_context(), vfs.root(), &directory_name, vfs.root(), &full_name)
                .await,
            Err(NfsError::NotEmpty)
        );

        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &directory_name).await.unwrap().object, directory);
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &file_name).await.unwrap().object, file);
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &full_name).await.unwrap().object, full);
        assert_eq!(vfs.getattr(&v4_context(), vfs.root()).await.unwrap(), root_before);
    }

    #[tokio::test]
    async fn self_and_hard_link_renames_are_exact_noops() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let file_name = NfsName::new(b"rename-self-file".to_vec()).unwrap();
        let link_name = NfsName::new(b"rename-self-link".to_vec()).unwrap();
        let directory_name = NfsName::new(b"rename-self-dir".to_vec()).unwrap();
        let file = vfs
            .create(&v4_context(), vfs.root(), &file_name, SetAttributes::default(), CreateMode::Guarded)
            .await
            .unwrap()
            .value
            .object;
        vfs.mkdir(&v4_context(), vfs.root(), &directory_name, SetAttributes::default())
            .await
            .unwrap();

        for name in [&file_name, &directory_name] {
            let root_before = vfs.getattr(&v4_context(), vfs.root()).await.unwrap();
            let (source, target) = vfs.rename(&v4_context(), vfs.root(), name, vfs.root(), name).await.unwrap();
            assert_eq!(source.change_info.unwrap().before, source.change_info.unwrap().after);
            assert_eq!(target.change_info.unwrap().before, target.change_info.unwrap().after);
            assert_eq!(vfs.getattr(&v4_context(), vfs.root()).await.unwrap(), root_before);
        }

        vfs.link(&v4_context(), file, vfs.root(), &link_name).await.unwrap();
        let root_before = vfs.getattr(&v4_context(), vfs.root()).await.unwrap();
        let file_before = vfs.getattr(&v4_context(), file).await.unwrap();
        let (source, target) = vfs
            .rename(&v4_context(), vfs.root(), &file_name, vfs.root(), &link_name)
            .await
            .unwrap();
        assert_eq!(source.change_info.unwrap().before, source.change_info.unwrap().after);
        assert_eq!(target.change_info.unwrap().before, target.change_info.unwrap().after);
        assert_eq!(vfs.getattr(&v4_context(), vfs.root()).await.unwrap(), root_before);
        assert_eq!(vfs.getattr(&v4_context(), file).await.unwrap(), file_before);
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &file_name).await.unwrap().object, file);
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &link_name).await.unwrap().object, file);
    }

    #[tokio::test]
    async fn rename_replacement_preserves_directory_and_link_invariants() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let source_name = NfsName::new(b"replacement-source".to_vec()).unwrap();
        let target_name = NfsName::new(b"replacement-target".to_vec()).unwrap();
        let child_name = NfsName::new(b"replacement-child".to_vec()).unwrap();
        let source = vfs
            .mkdir(&v4_context(), vfs.root(), &source_name, SetAttributes::default())
            .await
            .unwrap()
            .value
            .object;
        let target = vfs
            .mkdir(&v4_context(), vfs.root(), &target_name, SetAttributes::default())
            .await
            .unwrap()
            .value
            .object;
        vfs.create(&v4_context(), source, &child_name, SetAttributes::default(), CreateMode::Guarded)
            .await
            .unwrap();
        let links_before = vfs.getattr(&v4_context(), vfs.root()).await.unwrap().links;

        let (source_change, target_change) = vfs
            .rename(&v4_context(), vfs.root(), &source_name, vfs.root(), &target_name)
            .await
            .unwrap();
        assert!(source_change.change_info.is_some_and(|change| change.after > change.before));
        assert!(target_change.change_info.is_some_and(|change| change.after > change.before));
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &source_name).await, Err(NfsError::NotFound));
        assert_eq!(vfs.lookup(&v4_context(), vfs.root(), &target_name).await.unwrap().object, source);
        assert!(vfs.lookup(&v4_context(), source, &child_name).await.unwrap().object.file_id > 0);
        assert_eq!(vfs.getattr(&v4_context(), target).await, Err(NfsError::Stale));
        assert_eq!(vfs.getattr(&v4_context(), vfs.root()).await.unwrap().links, links_before.checked_sub(1).unwrap());
    }

    #[tokio::test]
    async fn link_rejects_directories_and_nondirectory_parents_without_mutating() {
        let vfs = CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite);
        let file = vfs
            .lookup(&v4_context(), vfs.root(), &NfsName::new(b"file".to_vec()).unwrap())
            .await
            .unwrap()
            .object;
        let directory = vfs
            .lookup(&v4_context(), vfs.root(), &NfsName::new(b"dir".to_vec()).unwrap())
            .await
            .unwrap()
            .object;
        let name = NfsName::new(b"hard-link".to_vec()).unwrap();
        let root_before = vfs.getattr(&v4_context(), vfs.root()).await.unwrap();
        let file_before = vfs.getattr(&v4_context(), file).await.unwrap();

        assert_eq!(vfs.link(&v4_context(), directory, vfs.root(), &name).await, Err(NfsError::IsDirectory));
        assert_eq!(vfs.link(&v4_context(), file, file, &name).await, Err(NfsError::NotDirectory));
        assert_eq!(vfs.getattr(&v4_context(), vfs.root()).await.unwrap(), root_before);
        assert_eq!(vfs.getattr(&v4_context(), file).await.unwrap(), file_before);

        vfs.link(&v4_context(), file, vfs.root(), &name).await.unwrap();
        assert_eq!(vfs.getattr(&v4_context(), file).await.unwrap().links, file_before.links.checked_add(1).unwrap());
    }
}
