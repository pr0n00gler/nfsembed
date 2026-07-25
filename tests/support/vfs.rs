use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nfsserver::vfs::{
    CreateMode, CreatedObject, DeviceNumber, DirectoryEntry, ExportId, FileAttributes, FileType, FsInfo, FsStat,
    MutationResult, NfsError, NfsName, NfsTime, NodeType, ObjectKey, PathConf, Principal, ReadDirectoryPage,
    ReadResult, RequestContext, SetAttributes, VfsCapabilities, VirtualFileSystem, WccAttributes, WriteResult,
    WriteStability,
};

pub const ROOT: ObjectKey = ObjectKey {
    file_id: 1,
    generation: 1,
};
pub const FILE: ObjectKey = ObjectKey {
    file_id: 2,
    generation: 1,
};
pub const SYMLINK: ObjectKey = ObjectKey {
    file_id: 3,
    generation: 1,
};
pub const DIRECTORY: ObjectKey = ObjectKey {
    file_id: 4,
    generation: 1,
};
pub const DEVICE: ObjectKey = ObjectKey {
    file_id: 5,
    generation: 1,
};
pub const CREATED_FILE: ObjectKey = ObjectKey {
    file_id: 100,
    generation: 1,
};
pub const CREATED_DIRECTORY: ObjectKey = ObjectKey {
    file_id: 101,
    generation: 1,
};
pub const CREATED_SYMLINK: ObjectKey = ObjectKey {
    file_id: 102,
    generation: 1,
};
pub const CREATED_NODE: ObjectKey = ObjectKey {
    file_id: 103,
    generation: 1,
};

struct ActiveDelayGuard<'a>(&'a AtomicUsize);

impl Drop for ActiveDelayGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct CallObservation {
    pub operation: &'static str,
    pub context: RequestContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteObservation {
    pub object: ObjectKey,
    pub offset: u64,
    pub data: Vec<u8>,
    pub requested: WriteStability,
}

#[derive(Default)]
struct Control {
    calls: Vec<CallObservation>,
    failures: HashMap<&'static str, NfsError>,
    delays: HashMap<&'static str, Duration>,
    post_delays: HashMap<&'static str, Duration>,
    last_write: Option<WriteObservation>,
    write_result: Option<WriteResult>,
    last_read: Option<(u64, u32)>,
    last_create_mode: Option<CreateMode>,
    last_readdir: Option<(u64, [u8; 8], usize)>,
    last_lookup_name: Option<Vec<u8>>,
    last_access: Option<u32>,
    last_symlink_target: Option<Vec<u8>>,
    last_mknod: Option<NodeType>,
    readlink_target: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Clone)]
pub struct ConformanceVfs {
    export_id: ExportId,
    capabilities: VfsCapabilities,
    case_insensitive: bool,
    allow_all_access: bool,
    control: Arc<Mutex<Control>>,
    active_delays: Arc<AtomicUsize>,
    max_active_delays: Arc<AtomicUsize>,
}

impl ConformanceVfs {
    pub fn new(export_id: ExportId) -> Self {
        let control = Control {
            data: b"hello world".to_vec(),
            readlink_target: b"target/path".to_vec(),
            ..Control::default()
        };
        Self {
            export_id,
            capabilities: VfsCapabilities::READ_WRITE,
            case_insensitive: false,
            allow_all_access: false,
            control: Arc::new(Mutex::new(control)),
            active_delays: Arc::new(AtomicUsize::new(0)),
            max_active_delays: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn read_only(export_id: ExportId) -> Self {
        Self {
            capabilities: VfsCapabilities::READ_ONLY,
            ..Self::new(export_id)
        }
    }

    pub fn case_insensitive(export_id: ExportId) -> Self {
        Self {
            case_insensitive: true,
            ..Self::new(export_id)
        }
    }

    pub fn certification(export_id: ExportId) -> Self {
        Self {
            allow_all_access: true,
            ..Self::new(export_id)
        }
    }

    pub fn fail(&self, operation: &'static str, error: NfsError) {
        self.control.lock().unwrap().failures.insert(operation, error);
    }

    pub fn clear_failure(&self, operation: &'static str) {
        self.control.lock().unwrap().failures.remove(operation);
    }

    pub fn delay(&self, operation: &'static str, duration: Duration) {
        self.control.lock().unwrap().delays.insert(operation, duration);
    }

    pub fn delay_after(&self, operation: &'static str, duration: Duration) {
        self.control.lock().unwrap().post_delays.insert(operation, duration);
    }

    pub fn clear_delay(&self, operation: &'static str) {
        self.control.lock().unwrap().delays.remove(operation);
    }

    pub fn clear_delay_after(&self, operation: &'static str) {
        self.control.lock().unwrap().post_delays.remove(operation);
    }

    pub fn call_count(&self, operation: &'static str) -> usize {
        self.control
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.operation == operation)
            .count()
    }

    pub fn last_context(&self, operation: &'static str) -> Option<RequestContext> {
        self.control
            .lock()
            .unwrap()
            .calls
            .iter()
            .rev()
            .find(|call| call.operation == operation)
            .map(|call| call.context.clone())
    }

    pub fn last_write(&self) -> Option<WriteObservation> {
        self.control.lock().unwrap().last_write.clone()
    }

    pub fn set_write_result(&self, result: Option<WriteResult>) {
        self.control.lock().unwrap().write_result = result;
    }

    pub fn last_read(&self) -> Option<(u64, u32)> {
        self.control.lock().unwrap().last_read
    }

    pub fn set_data(&self, data: Vec<u8>) {
        self.control.lock().unwrap().data = data;
    }

    pub fn last_create_mode(&self) -> Option<CreateMode> {
        self.control.lock().unwrap().last_create_mode
    }

    pub fn last_readdir(&self) -> Option<(u64, [u8; 8], usize)> {
        self.control.lock().unwrap().last_readdir
    }

    pub fn last_lookup_name(&self) -> Option<Vec<u8>> {
        self.control.lock().unwrap().last_lookup_name.clone()
    }

    pub fn last_access(&self) -> Option<u32> {
        self.control.lock().unwrap().last_access
    }

    pub fn last_symlink_target(&self) -> Option<Vec<u8>> {
        self.control.lock().unwrap().last_symlink_target.clone()
    }

    pub fn last_mknod(&self) -> Option<NodeType> {
        self.control.lock().unwrap().last_mknod
    }

    pub fn set_readlink_target(&self, target: Vec<u8>) {
        self.control.lock().unwrap().readlink_target = target;
    }

    pub fn reset_concurrency_observation(&self) {
        self.max_active_delays.store(0, Ordering::SeqCst);
    }

    pub fn max_concurrency_observed(&self) -> usize {
        self.max_active_delays.load(Ordering::SeqCst)
    }

    pub fn active_delays(&self) -> usize {
        self.active_delays.load(Ordering::SeqCst)
    }

    async fn begin(&self, operation: &'static str, context: &RequestContext) -> Result<(), NfsError> {
        let (delay, failure) = {
            let mut control = self.control.lock().unwrap();
            control.calls.push(CallObservation {
                operation,
                context: context.clone(),
            });
            (control.delays.get(operation).copied(), control.failures.get(operation).copied())
        };
        if context.export_id != self.export_id {
            return Err(NfsError::Access);
        }
        if self.capabilities.read_only
            && matches!(
                operation,
                "setattr"
                    | "write"
                    | "create"
                    | "mkdir"
                    | "symlink"
                    | "mknod"
                    | "remove"
                    | "rmdir"
                    | "rename"
                    | "link"
                    | "commit"
            )
        {
            return Err(NfsError::ReadOnly);
        }
        if let Some(delay) = delay {
            let active = self.active_delays.fetch_add(1, Ordering::SeqCst) + 1;
            let _guard = ActiveDelayGuard(&self.active_delays);
            self.max_active_delays.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }

    fn attributes(object: ObjectKey) -> Result<FileAttributes, NfsError> {
        if object.generation != 1 {
            return Err(NfsError::Stale);
        }
        let file_type = match object.file_id {
            1 | 4 | 101 => FileType::Directory,
            3 | 102 => FileType::Symlink,
            2 | 100 => FileType::Regular,
            5 => FileType::BlockDevice,
            103 => FileType::Fifo,
            _ => return Err(NfsError::NotFound),
        };
        Ok(FileAttributes {
            file_type,
            mode: if file_type == FileType::Directory { 0o755 } else { 0o644 },
            links: if file_type == FileType::Directory { 2 } else { 1 },
            uid: 1000,
            gid: 100,
            size: if object == FILE { 11 } else { 0 },
            used: if object == FILE { 4096 } else { 0 },
            device: (object == DEVICE).then_some(DeviceNumber { major: 12, minor: 34 }),
            fs_id: 55,
            file_id: object.file_id,
            access_time: NfsTime {
                seconds: 10,
                nanoseconds: 11,
            },
            modify_time: NfsTime {
                seconds: 12,
                nanoseconds: 13,
            },
            change_time: NfsTime {
                seconds: 14,
                nanoseconds: 15,
            },
        })
    }

    fn wcc(object: ObjectKey) -> WccAttributes {
        let attributes = Self::attributes(object).unwrap();
        WccAttributes {
            size: attributes.size,
            modify_time: attributes.modify_time,
            change_time: attributes.change_time,
        }
    }

    fn mutation<T>(object: ObjectKey, value: T) -> MutationResult<T> {
        MutationResult {
            value,
            before: Some(Self::wcc(object)),
            after: Self::attributes(object).ok(),
        }
    }

    fn created(object: ObjectKey) -> MutationResult<CreatedObject> {
        MutationResult {
            value: CreatedObject {
                object,
                attributes: Self::attributes(object).ok(),
            },
            before: Some(Self::wcc(ROOT)),
            after: Self::attributes(ROOT).ok(),
        }
    }
}

#[async_trait]
impl VirtualFileSystem for ConformanceVfs {
    fn capabilities(&self) -> VfsCapabilities {
        self.capabilities
    }

    fn root(&self) -> ObjectKey {
        ROOT
    }

    async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
        self.begin("getattr", context).await?;
        Self::attributes(object)
    }

    async fn lookup(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError> {
        self.begin("lookup", context).await?;
        if parent != ROOT && parent != DIRECTORY {
            return Err(NfsError::NotDirectory);
        }
        self.control.lock().unwrap().last_lookup_name = Some(name.as_bytes().to_vec());
        let normalized;
        let name = if self.case_insensitive {
            normalized = name.as_bytes().iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
            normalized.as_slice()
        } else {
            name.as_bytes()
        };
        let object = match name {
            b"file" => FILE,
            b"link" => SYMLINK,
            b"dir" => DIRECTORY,
            b"device" => DEVICE,
            b"created" => CREATED_FILE,
            _ => return Err(NfsError::NotFound),
        };
        Ok(CreatedObject {
            object,
            attributes: Self::attributes(object).ok(),
        })
    }

    async fn access(&self, context: &RequestContext, _object: ObjectKey, requested: u32) -> Result<u32, NfsError> {
        self.begin("access", context).await?;
        self.control.lock().unwrap().last_access = Some(requested);
        Ok(if self.allow_all_access {
            requested
        } else {
            requested & 0x15
        })
    }

    async fn setattr(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        _attributes: SetAttributes,
        guard: Option<NfsTime>,
    ) -> Result<MutationResult<()>, NfsError> {
        self.begin("setattr", context).await?;
        if let Some(guard) = guard {
            if guard != Self::attributes(object)?.change_time {
                return Err(NfsError::NotSynchronized);
            }
        }
        Ok(Self::mutation(object, ()))
    }

    async fn readlink(&self, context: &RequestContext, object: ObjectKey) -> Result<Vec<u8>, NfsError> {
        self.begin("readlink", context).await?;
        if object != SYMLINK {
            return Err(NfsError::Invalid);
        }
        Ok(self.control.lock().unwrap().readlink_target.clone())
    }

    async fn read(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, NfsError> {
        self.begin("read", context).await?;
        if object != FILE {
            return Err(NfsError::Invalid);
        }
        self.control.lock().unwrap().last_read = Some((offset, count));
        let data = self.control.lock().unwrap().data.clone();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
        let end = start.saturating_add(count as usize).min(data.len());
        Ok(ReadResult {
            data: data[start..end].to_vec(),
            eof: end == data.len(),
            attributes: Self::attributes(FILE).ok(),
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
        self.begin("write", context).await?;
        let (post_delay, write_result) = {
            let mut control = self.control.lock().unwrap();
            control.last_write = Some(WriteObservation {
                object,
                offset,
                data: data.to_vec(),
                requested,
            });
            (
                control.post_delays.get("write").copied(),
                control.write_result.unwrap_or(WriteResult {
                    count: data.len() as u32,
                    committed: requested,
                }),
            )
        };
        if let Some(delay) = post_delay {
            tokio::time::sleep(delay).await;
        }
        Ok(Self::mutation(object, write_result))
    }

    async fn create(
        &self,
        context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _attributes: SetAttributes,
        mode: CreateMode,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.begin("create", context).await?;
        self.control.lock().unwrap().last_create_mode = Some(mode);
        Ok(Self::created(CREATED_FILE))
    }

    async fn mkdir(
        &self,
        context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.begin("mkdir", context).await?;
        Ok(Self::created(CREATED_DIRECTORY))
    }

    async fn symlink(
        &self,
        context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        target: &[u8],
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.begin("symlink", context).await?;
        self.control.lock().unwrap().last_symlink_target = Some(target.to_vec());
        Ok(Self::created(CREATED_SYMLINK))
    }

    async fn mknod(
        &self,
        context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        node_type: NodeType,
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.begin("mknod", context).await?;
        self.control.lock().unwrap().last_mknod = Some(node_type);
        Ok(Self::created(CREATED_NODE))
    }

    async fn remove(
        &self,
        context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.begin("remove", context).await?;
        Ok(Self::mutation(ROOT, ()))
    }

    async fn rmdir(
        &self,
        context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.begin("rmdir", context).await?;
        Ok(Self::mutation(ROOT, ()))
    }

    async fn rename(
        &self,
        context: &RequestContext,
        _from_parent: ObjectKey,
        _from_name: &NfsName,
        _to_parent: ObjectKey,
        _to_name: &NfsName,
    ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
        self.begin("rename", context).await?;
        Ok((Self::mutation(ROOT, ()), Self::mutation(DIRECTORY, ())))
    }

    async fn link(
        &self,
        context: &RequestContext,
        _object: ObjectKey,
        _to_parent: ObjectKey,
        _to_name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.begin("link", context).await?;
        Ok(Self::mutation(ROOT, ()))
    }

    async fn readdir(
        &self,
        context: &RequestContext,
        directory: ObjectKey,
        cookie: u64,
        verifier: [u8; 8],
        backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        self.begin("readdir", context).await?;
        if verifier != [0; 8] && verifier != [9; 8] {
            return Err(NfsError::BadCookie);
        }
        self.control.lock().unwrap().last_readdir = Some((cookie, verifier, backend_hint));
        if directory == DIRECTORY {
            return Ok(ReadDirectoryPage {
                verifier: [9; 8],
                entries: Vec::new(),
                eof: true,
            });
        }
        let entries = [
            (FILE, b"file".as_slice(), 1),
            (SYMLINK, b"link".as_slice(), 2),
            (DIRECTORY, b"dir", 3),
        ]
        .into_iter()
        .filter(|(_, _, entry_cookie)| *entry_cookie > cookie)
        .take(backend_hint)
        .map(|(object, name, entry_cookie)| DirectoryEntry {
            object,
            file_id: object.file_id,
            name: NfsName::new(name.to_vec()).unwrap(),
            cookie: entry_cookie,
            attributes: Self::attributes(object).ok(),
        })
        .collect();
        Ok(ReadDirectoryPage {
            verifier: [9; 8],
            entries,
            eof: true,
        })
    }

    async fn fsstat(&self, context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        self.begin("fsstat", context).await?;
        Ok(FsStat {
            total_bytes: 1_000_000,
            free_bytes: 500_000,
            available_bytes: 400_000,
            total_files: 10_000,
            free_files: 5_000,
            available_files: 4_000,
            invariant_seconds: 30,
        })
    }

    async fn fsinfo(&self, context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
        self.begin("fsinfo", context).await?;
        Ok(FsInfo {
            max_read: 64 * 1024,
            preferred_read: 32 * 1024,
            read_multiple: 4096,
            max_write: 64 * 1024,
            preferred_write: 32 * 1024,
            write_multiple: 4096,
            preferred_readdir: 16 * 1024,
            max_file_size: 1 << 40,
            time_granularity: NfsTime {
                seconds: 0,
                nanoseconds: 1_000,
            },
        })
    }

    async fn pathconf(&self, context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        self.begin("pathconf", context).await?;
        Ok(PathConf {
            max_links: 32000,
            max_name_length: u32::MAX,
            no_truncation: true,
            chown_restricted: true,
            case_insensitive: false,
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
        self.begin("commit", context).await?;
        Ok(Self::mutation(object, ()))
    }
}

pub fn assert_auth_sys(principal: &Principal) {
    assert_eq!(
        principal,
        &Principal::AuthSys {
            uid: 1000,
            gid: 100,
            supplementary_gids: vec![10, 20],
            machine_name: b"e2e-client".to_vec(),
        }
    );
}
