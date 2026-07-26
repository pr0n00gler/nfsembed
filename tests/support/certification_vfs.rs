use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
#[cfg(test)]
use nfsembed::vfs::Principal;
use nfsembed::vfs::{
    CreateMode, CreatedObject, DeviceNumber, DirectoryEntry, ExportId, FileAttributes, FileType, FsInfo, FsStat,
    MutationResult, NfsError, NfsName, NfsTime, NodeType, ObjectKey, PathConf, ReadDirectoryPage, ReadResult,
    RequestContext, SetAttributes, VfsCapabilities, VirtualFileSystem, WccAttributes, WriteResult, WriteStability,
};

const ROOT_ID: u64 = 1;
const VERIFIER: [u8; 8] = *b"CERTDIR1";

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
}

struct State {
    next_id: u64,
    nodes: HashMap<u64, Node>,
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
    modified: u32,
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
        let state = State {
            next_id: 5,
            nodes: [(ROOT_ID, root), (2, file), (3, directory), (4, symlink)].into_iter().collect(),
        };
        Self {
            export_id,
            profile,
            state: Arc::new(Mutex::new(state)),
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
            seconds: u64::from(node.modified),
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
            access_time: time,
            modify_time: time,
            change_time: time,
        })
    }

    fn wcc(state: &State, file_id: u64) -> Option<WccAttributes> {
        Self::attributes(state, file_id).ok().map(|attributes| WccAttributes {
            size: attributes.size,
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

    fn created(
        state: &State,
        parent: u64,
        file_id: u64,
        before: Option<WccAttributes>,
    ) -> MutationResult<CreatedObject> {
        MutationResult {
            value: CreatedObject {
                object: Self::key(file_id),
                attributes: Self::attributes(state, file_id).ok(),
            },
            before,
            after: Self::attributes(state, parent).ok(),
        }
    }

    fn apply_attributes(node: &mut Node, attributes: SetAttributes) -> Result<(), NfsError> {
        if let Some(mode) = attributes.mode {
            node.mode = mode;
        }
        if let Some(uid) = attributes.uid {
            node.uid = uid;
        }
        if let Some(gid) = attributes.gid {
            node.gid = gid;
        }
        if let Some(size) = attributes.size {
            if node.file_type != FileType::Regular {
                return Err(NfsError::Invalid);
            }
            node.data.resize(usize::try_from(size).map_err(|_| NfsError::FileTooLarge)?, 0);
        }
        node.modified = node.modified.wrapping_add(1);
        Ok(())
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
        Self::apply_attributes(&mut node, attributes)?;
        state.nodes.insert(file_id, node);
        let directory = state.nodes.get_mut(&parent).ok_or(NfsError::Stale)?;
        directory.children.insert(name.as_bytes().to_vec(), file_id);
        directory.modified = directory.modified.wrapping_add(1);
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
        Self::apply_attributes(state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?, attributes)?;
        Ok(MutationResult {
            value: (),
            before,
            after: Self::attributes(&state, file_id).ok(),
        })
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
        let before = Self::wcc(&state, file_id);
        let node = state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?;
        if node.file_type != FileType::Regular {
            return Err(NfsError::Invalid);
        }
        let start = usize::try_from(offset).map_err(|_| NfsError::FileTooLarge)?;
        let end = start.checked_add(data.len()).ok_or(NfsError::FileTooLarge)?;
        if node.data.len() < end {
            node.data.resize(end, 0);
        }
        node.data[start..end].copy_from_slice(data);
        node.modified = node.modified.wrapping_add(1);
        Ok(MutationResult {
            value: WriteResult {
                count: data.len() as u32,
                committed: requested,
            },
            before,
            after: Self::attributes(&state, file_id).ok(),
        })
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
        let node = state.nodes.get_mut(&file_id).ok_or(NfsError::Stale)?;
        node.links = node.links.saturating_sub(1);
        if node.links == 0 {
            state.nodes.remove(&file_id);
        }
        Ok(MutationResult {
            value: (),
            before,
            after: Self::attributes(&state, parent).ok(),
        })
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
        Ok(MutationResult {
            value: (),
            before,
            after: Self::attributes(&state, parent).ok(),
        })
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
        let from_before = Self::wcc(&state, from_parent);
        let to_before = Self::wcc(&state, to_parent);
        let (stored_name, file_id) = {
            let directory = state.nodes.get(&from_parent).ok_or(NfsError::Stale)?;
            self.find_child(directory, from_name.as_bytes()).ok_or(NfsError::NotFound)?
        };
        state.nodes.get_mut(&from_parent).unwrap().children.remove(&stored_name);
        if let Some(replaced) = state
            .nodes
            .get_mut(&to_parent)
            .ok_or(NfsError::Stale)?
            .children
            .insert(to_name.as_bytes().to_vec(), file_id)
        {
            state.nodes.remove(&replaced);
        }
        Ok((
            MutationResult {
                value: (),
                before: from_before,
                after: Self::attributes(&state, from_parent).ok(),
            },
            MutationResult {
                value: (),
                before: to_before,
                after: Self::attributes(&state, to_parent).ok(),
            },
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
            return Err(NfsError::Permission);
        }
        let before = Self::wcc(&state, parent);
        let directory = state.nodes.get_mut(&parent).ok_or(NfsError::Stale)?;
        if directory.children.contains_key(to_name.as_bytes()) {
            return Err(NfsError::Exists);
        }
        directory.children.insert(to_name.as_bytes().to_vec(), file_id);
        state.nodes.get_mut(&file_id).unwrap().links += 1;
        Ok(MutationResult {
            value: (),
            before,
            after: Self::attributes(&state, parent).ok(),
        })
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
        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
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
                cookie: index as u64 + 1,
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
            max_file_size: u64::MAX,
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
        Ok(MutationResult {
            value: (),
            before: Self::wcc(&state, file_id),
            after: Self::attributes(&state, file_id).ok(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RequestContext {
        RequestContext {
            principal: Principal::Anonymous,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            export_id: ExportId(1),
        }
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
}
