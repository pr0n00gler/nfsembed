use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{Metadata, Permissions};
use std::io;
use std::io::SeekFrom;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use nfsserve::vfs::{
    CreateMode, CreatedObject, DirectoryEntry, FileAttributes, FileType, FsInfo, FsStat, MutationResult, NfsError,
    NfsName, NfsTime, ObjectKey, PathConf, ReadDirectoryPage, ReadResult, RequestContext, SetAttributes, SetTime,
    VfsCapabilities, VirtualFileSystem, WccAttributes, WriteResult, WriteStability,
};
use nfsserve::{AuthPolicy, NfsServer};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::debug;

const ROOT_ID: u64 = 1;
const GENERATION: u64 = 1;

#[derive(Debug)]
struct FsMap {
    root: PathBuf,
    next_file_id: u64,
    id_to_relative: HashMap<u64, Vec<OsString>>,
    relative_to_id: HashMap<Vec<OsString>, u64>,
    exclusive_verifiers: HashMap<Vec<OsString>, [u8; 8]>,
}

impl FsMap {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            next_file_id: ROOT_ID + 1,
            id_to_relative: HashMap::from([(ROOT_ID, Vec::new())]),
            relative_to_id: HashMap::from([(Vec::new(), ROOT_ID)]),
            exclusive_verifiers: HashMap::new(),
        }
    }

    fn relative(&self, object: ObjectKey) -> Result<Vec<OsString>, NfsError> {
        if object.generation != GENERATION {
            return Err(NfsError::Stale);
        }
        self.id_to_relative.get(&object.file_id).cloned().ok_or(NfsError::Stale)
    }

    fn path(&self, relative: &[OsString]) -> PathBuf {
        let mut path = self.root.clone();
        path.extend(relative);
        path
    }

    fn child_relative(&self, parent: ObjectKey, name: &NfsName) -> Result<Vec<OsString>, NfsError> {
        let mut relative = self.relative(parent)?;
        relative.push(OsString::from_vec(name.as_bytes().to_vec()));
        Ok(relative)
    }

    fn intern(&mut self, relative: Vec<OsString>) -> u64 {
        if let Some(file_id) = self.relative_to_id.get(&relative) {
            return *file_id;
        }
        let file_id = self.next_file_id;
        self.next_file_id += 1;
        self.id_to_relative.insert(file_id, relative.clone());
        self.relative_to_id.insert(relative, file_id);
        file_id
    }

    fn forget_prefix(&mut self, prefix: &[OsString]) {
        let forgotten = self
            .id_to_relative
            .iter()
            .filter(|(_, relative)| relative.starts_with(prefix))
            .map(|(file_id, relative)| (*file_id, relative.clone()))
            .collect::<Vec<_>>();
        for (file_id, relative) in forgotten {
            self.id_to_relative.remove(&file_id);
            self.relative_to_id.remove(&relative);
            self.exclusive_verifiers.remove(&relative);
        }
    }

    fn move_prefix(&mut self, from: &[OsString], to: &[OsString]) {
        self.forget_prefix(to);
        let moved = self
            .id_to_relative
            .iter()
            .filter(|(_, relative)| relative.starts_with(from))
            .map(|(file_id, relative)| (*file_id, relative.clone()))
            .collect::<Vec<_>>();
        for (file_id, old_relative) in moved {
            let mut new_relative = to.to_vec();
            new_relative.extend_from_slice(&old_relative[from.len()..]);
            self.id_to_relative.insert(file_id, new_relative.clone());
            self.relative_to_id.remove(&old_relative);
            self.relative_to_id.insert(new_relative.clone(), file_id);
            if let Some(verifier) = self.exclusive_verifiers.remove(&old_relative) {
                self.exclusive_verifiers.insert(new_relative, verifier);
            }
        }
    }
}

#[derive(Debug)]
pub struct MirrorFs {
    map: tokio::sync::Mutex<FsMap>,
}

impl MirrorFs {
    pub fn new(root: PathBuf) -> Self {
        Self {
            map: tokio::sync::Mutex::new(FsMap::new(root)),
        }
    }

    fn key(file_id: u64) -> ObjectKey {
        ObjectKey {
            file_id,
            generation: GENERATION,
        }
    }

    async fn object_path(&self, object: ObjectKey) -> Result<(u64, PathBuf), NfsError> {
        let map = self.map.lock().await;
        let relative = map.relative(object)?;
        Ok((object.file_id, map.path(&relative)))
    }

    async fn child_path(&self, parent: ObjectKey, name: &NfsName) -> Result<(Vec<OsString>, PathBuf), NfsError> {
        let map = self.map.lock().await;
        let relative = map.child_relative(parent, name)?;
        let path = map.path(&relative);
        Ok((relative, path))
    }

    async fn created(&self, relative: Vec<OsString>, metadata: Metadata) -> CreatedObject {
        let mut map = self.map.lock().await;
        let file_id = map.intern(relative);
        CreatedObject {
            object: Self::key(file_id),
            attributes: Some(metadata_to_attributes(file_id, &metadata)),
        }
    }

    async fn parent_snapshot(&self, parent: ObjectKey) -> Result<(Option<WccAttributes>, PathBuf), NfsError> {
        let (_, path) = self.object_path(parent).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok((Some(metadata_to_wcc(&metadata)), path))
    }

    async fn create_object(
        &self,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
        kind: CreateKind<'_>,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        let (before, parent_path) = self.parent_snapshot(parent).await?;
        if !tokio::fs::symlink_metadata(&parent_path).await.map_err(map_io_error)?.is_dir() {
            return Err(NfsError::NotDirectory);
        }
        let (relative, path) = self.child_path(parent, name).await?;

        match kind {
            CreateKind::File(mode) => {
                if let CreateMode::Exclusive { verifier } = mode {
                    if tokio::fs::symlink_metadata(&path).await.is_ok() {
                        let map = self.map.lock().await;
                        if map.exclusive_verifiers.get(&relative) != Some(&verifier) {
                            return Err(NfsError::Exists);
                        }
                    } else {
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .await
                            .map_err(map_io_error)?;
                        self.map.lock().await.exclusive_verifiers.insert(relative.clone(), verifier);
                    }
                } else {
                    let mut options = OpenOptions::new();
                    options.write(true);
                    match mode {
                        CreateMode::Unchecked => {
                            options.create(true);
                        },
                        CreateMode::Guarded => {
                            options.create_new(true);
                        },
                        CreateMode::Exclusive { .. } => unreachable!(),
                    }
                    options.open(&path).await.map_err(map_io_error)?;
                    apply_attributes(&path, &attributes).await?;
                }
            },
            CreateKind::Directory => {
                tokio::fs::create_dir(&path).await.map_err(map_io_error)?;
                apply_attributes(&path, &attributes).await?;
            },
            CreateKind::Symlink(target) => {
                tokio::fs::symlink(OsStr::from_bytes(target), &path)
                    .await
                    .map_err(map_io_error)?;
            },
        }

        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        let created = self.created(relative, metadata).await;
        let after = tokio::fs::symlink_metadata(parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(parent.file_id, &metadata));
        Ok(MutationResult {
            value: created,
            before,
            after,
        })
    }

    async fn remove_object(
        &self,
        parent: ObjectKey,
        name: &NfsName,
        directory: bool,
    ) -> Result<MutationResult<()>, NfsError> {
        let (before, parent_path) = self.parent_snapshot(parent).await?;
        let (relative, path) = self.child_path(parent, name).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        if directory {
            if !metadata.is_dir() {
                return Err(NfsError::NotDirectory);
            }
            tokio::fs::remove_dir(&path).await.map_err(map_io_error)?;
        } else {
            if metadata.is_dir() {
                return Err(NfsError::IsDirectory);
            }
            tokio::fs::remove_file(&path).await.map_err(map_io_error)?;
        }
        self.map.lock().await.forget_prefix(&relative);
        let after = tokio::fs::symlink_metadata(parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(parent.file_id, &metadata));
        Ok(MutationResult {
            value: (),
            before,
            after,
        })
    }
}

enum CreateKind<'a> {
    File(CreateMode),
    Directory,
    Symlink(&'a [u8]),
}

#[async_trait]
impl VirtualFileSystem for MirrorFs {
    fn capabilities(&self) -> VfsCapabilities {
        VfsCapabilities {
            hard_links: false,
            mknod: false,
            ..VfsCapabilities::READ_WRITE
        }
    }

    fn root(&self) -> ObjectKey {
        Self::key(ROOT_ID)
    }

    async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        debug!(?path, "getattr");
        Ok(metadata_to_attributes(file_id, &metadata))
    }

    async fn lookup(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError> {
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            let mut map = self.map.lock().await;
            let mut relative = map.relative(parent)?;
            if name.as_bytes() == b".." {
                relative.pop();
            }
            let path = map.path(&relative);
            let metadata = tokio::fs::symlink_metadata(path).await.map_err(map_io_error)?;
            let file_id = map.intern(relative);
            return Ok(CreatedObject {
                object: Self::key(file_id),
                attributes: Some(metadata_to_attributes(file_id, &metadata)),
            });
        }
        let (relative, path) = self.child_path(parent, name).await?;
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok(self.created(relative, metadata).await)
    }

    async fn access(&self, _context: &RequestContext, _object: ObjectKey, requested: u32) -> Result<u32, NfsError> {
        Ok(requested)
    }

    async fn setattr(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        attributes: SetAttributes,
        guard: Option<NfsTime>,
    ) -> Result<MutationResult<()>, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let before_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        if guard.is_some_and(|guard| guard != metadata_to_attributes(file_id, &before_metadata).change_time) {
            return Err(NfsError::NotSynchronized);
        }
        apply_attributes(&path, &attributes).await?;
        let after_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok(MutationResult {
            value: (),
            before: Some(metadata_to_wcc(&before_metadata)),
            after: Some(metadata_to_attributes(file_id, &after_metadata)),
        })
    }

    async fn readlink(&self, _context: &RequestContext, object: ObjectKey) -> Result<Vec<u8>, NfsError> {
        let (_, path) = self.object_path(object).await?;
        if !tokio::fs::symlink_metadata(&path)
            .await
            .map_err(map_io_error)?
            .file_type()
            .is_symlink()
        {
            return Err(NfsError::BadType);
        }
        Ok(tokio::fs::read_link(path)
            .await
            .map_err(map_io_error)?
            .into_os_string()
            .into_vec())
    }

    async fn read(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let mut file = File::open(&path).await.map_err(map_io_error)?;
        let metadata = file.metadata().await.map_err(map_io_error)?;
        if !metadata.is_file() {
            return Err(if metadata.is_dir() {
                NfsError::IsDirectory
            } else {
                NfsError::Invalid
            });
        }
        let start = offset.min(metadata.len());
        let end = offset.saturating_add(count as u64).min(metadata.len());
        file.seek(SeekFrom::Start(start)).await.map_err(map_io_error)?;
        let mut data = vec![0; usize::try_from(end - start).map_err(|_| NfsError::TooSmall)?];
        file.read_exact(&mut data).await.map_err(map_io_error)?;
        Ok(ReadResult {
            data,
            eof: end == metadata.len(),
            attributes: Some(metadata_to_attributes(file_id, &metadata)),
        })
    }

    async fn write(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        data: &[u8],
        requested: WriteStability,
    ) -> Result<MutationResult<WriteResult>, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let before_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        if !before_metadata.is_file() {
            return Err(if before_metadata.is_dir() {
                NfsError::IsDirectory
            } else {
                NfsError::Invalid
            });
        }
        let mut file = OpenOptions::new().write(true).open(&path).await.map_err(map_io_error)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(map_io_error)?;
        file.write_all(data).await.map_err(map_io_error)?;
        let committed = match requested {
            WriteStability::Unstable => WriteStability::Unstable,
            WriteStability::DataSync => {
                file.sync_data().await.map_err(map_io_error)?;
                WriteStability::DataSync
            },
            WriteStability::FileSync => {
                file.sync_all().await.map_err(map_io_error)?;
                WriteStability::FileSync
            },
        };
        let after_metadata = file.metadata().await.map_err(map_io_error)?;
        Ok(MutationResult {
            value: WriteResult {
                count: u32::try_from(data.len()).unwrap_or(u32::MAX),
                committed,
            },
            before: Some(metadata_to_wcc(&before_metadata)),
            after: Some(metadata_to_attributes(file_id, &after_metadata)),
        })
    }

    async fn create(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
        mode: CreateMode,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_object(parent, name, attributes, CreateKind::File(mode)).await
    }

    async fn mkdir(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_object(parent, name, attributes, CreateKind::Directory).await
    }

    async fn symlink(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
        target: &[u8],
        attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        self.create_object(parent, name, attributes, CreateKind::Symlink(target)).await
    }

    async fn remove(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.remove_object(parent, name, false).await
    }

    async fn rmdir(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        self.remove_object(parent, name, true).await
    }

    async fn rename(
        &self,
        _context: &RequestContext,
        from_parent: ObjectKey,
        from_name: &NfsName,
        to_parent: ObjectKey,
        to_name: &NfsName,
    ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
        let (from_before, from_parent_path) = self.parent_snapshot(from_parent).await?;
        let (to_before, to_parent_path) = self.parent_snapshot(to_parent).await?;
        let (from_relative, from_path) = self.child_path(from_parent, from_name).await?;
        let (to_relative, to_path) = self.child_path(to_parent, to_name).await?;
        tokio::fs::rename(&from_path, &to_path).await.map_err(map_io_error)?;
        self.map.lock().await.move_prefix(&from_relative, &to_relative);
        let from_after = tokio::fs::symlink_metadata(from_parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(from_parent.file_id, &metadata));
        let to_after = tokio::fs::symlink_metadata(to_parent_path)
            .await
            .ok()
            .map(|metadata| metadata_to_attributes(to_parent.file_id, &metadata));
        Ok((
            MutationResult {
                value: (),
                before: from_before,
                after: from_after,
            },
            MutationResult {
                value: (),
                before: to_before,
                after: to_after,
            },
        ))
    }

    async fn readdir(
        &self,
        _context: &RequestContext,
        directory: ObjectKey,
        cookie: u64,
        verifier: [u8; 8],
        backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        let (_, directory_path) = self.object_path(directory).await?;
        let directory_metadata = tokio::fs::symlink_metadata(&directory_path).await.map_err(map_io_error)?;
        if !directory_metadata.is_dir() {
            return Err(NfsError::NotDirectory);
        }
        let current_verifier = directory_verifier(&directory_metadata);
        if cookie != 0 && verifier != current_verifier {
            return Err(NfsError::BadCookie);
        }

        let mut reader = tokio::fs::read_dir(&directory_path).await.map_err(map_io_error)?;
        let mut children = Vec::new();
        while let Some(entry) = reader.next_entry().await.map_err(map_io_error)? {
            let path = entry.path();
            children.push((
                entry.file_name(),
                path.clone(),
                tokio::fs::symlink_metadata(path).await.map_err(map_io_error)?,
            ));
        }
        children.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        let selected = children.iter().skip(start).take(backend_hint.max(1));
        let mut entries = Vec::new();
        for (index, (name, _path, metadata)) in selected.enumerate() {
            let nfs_name = NfsName::new(name.as_bytes().to_vec())?;
            let relative = {
                let map = self.map.lock().await;
                let mut relative = map.relative(directory)?;
                relative.push(name.clone());
                relative
            };
            let file_id = self.map.lock().await.intern(relative);
            entries.push(DirectoryEntry {
                object: Self::key(file_id),
                file_id,
                name: nfs_name,
                cookie: (start + index + 1) as u64,
                attributes: Some(metadata_to_attributes(file_id, metadata)),
            });
        }
        Ok(ReadDirectoryPage {
            verifier: current_verifier,
            eof: start.saturating_add(entries.len()) >= children.len(),
            entries,
        })
    }

    async fn fsstat(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        // The standard library has no portable statvfs API. These conservative
        // values keep the example mountable without adding a platform binding.
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

    async fn fsinfo(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
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

    async fn pathconf(&self, _context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        Ok(PathConf {
            max_links: u32::MAX,
            max_name_length: NfsName::MAX_LEN as u32,
            no_truncation: true,
            chown_restricted: true,
            case_insensitive: false,
            case_preserving: true,
        })
    }

    async fn commit(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<MutationResult<()>, NfsError> {
        let (file_id, path) = self.object_path(object).await?;
        let before_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
            .map_err(map_io_error)?
            .sync_all()
            .await
            .map_err(map_io_error)?;
        let after_metadata = tokio::fs::symlink_metadata(&path).await.map_err(map_io_error)?;
        Ok(MutationResult {
            value: (),
            before: Some(metadata_to_wcc(&before_metadata)),
            after: Some(metadata_to_attributes(file_id, &after_metadata)),
        })
    }
}

fn map_io_error(error: io::Error) -> NfsError {
    match error.kind() {
        io::ErrorKind::NotFound => NfsError::NotFound,
        io::ErrorKind::PermissionDenied => NfsError::Access,
        io::ErrorKind::AlreadyExists => NfsError::Exists,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => NfsError::Invalid,
        io::ErrorKind::StorageFull => NfsError::NoSpace,
        _ => match error.raw_os_error() {
            Some(18) => NfsError::CrossDevice,
            Some(20) => NfsError::NotDirectory,
            Some(21) => NfsError::IsDirectory,
            Some(36) => NfsError::NameTooLong,
            Some(39) | Some(66) => NfsError::NotEmpty,
            _ => NfsError::Io,
        },
    }
}

fn metadata_time(seconds: i64, nanoseconds: i64) -> NfsTime {
    NfsTime {
        seconds: seconds.max(0) as u64,
        nanoseconds: nanoseconds.clamp(0, 999_999_999) as u32,
    }
}

fn metadata_to_attributes(file_id: u64, metadata: &Metadata) -> FileAttributes {
    let os_type = metadata.file_type();
    let file_type = if os_type.is_file() {
        FileType::Regular
    } else if os_type.is_dir() {
        FileType::Directory
    } else if os_type.is_symlink() {
        FileType::Symlink
    } else if os_type.is_block_device() {
        FileType::BlockDevice
    } else if os_type.is_char_device() {
        FileType::CharacterDevice
    } else if os_type.is_socket() {
        FileType::Socket
    } else {
        FileType::Fifo
    };
    FileAttributes {
        file_type,
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink() as u32,
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.len(),
        used: metadata.blocks().saturating_mul(512),
        device: None,
        fs_id: metadata.dev(),
        file_id,
        access_time: metadata_time(metadata.atime(), metadata.atime_nsec()),
        modify_time: metadata_time(metadata.mtime(), metadata.mtime_nsec()),
        change_time: metadata_time(metadata.ctime(), metadata.ctime_nsec()),
    }
}

fn metadata_to_wcc(metadata: &Metadata) -> WccAttributes {
    WccAttributes {
        size: metadata.len(),
        modify_time: metadata_time(metadata.mtime(), metadata.mtime_nsec()),
        change_time: metadata_time(metadata.ctime(), metadata.ctime_nsec()),
    }
}

fn directory_verifier(metadata: &Metadata) -> [u8; 8] {
    let seconds = metadata.mtime() as u64;
    let nanoseconds = metadata.mtime_nsec() as u64;
    (seconds.rotate_left(17) ^ nanoseconds ^ metadata.ino()).to_be_bytes()
}

async fn apply_attributes(path: &Path, attributes: &SetAttributes) -> Result<(), NfsError> {
    if let Some(mode) = attributes.mode {
        let writable_mode = (mode | 0o200) & 0o7777;
        tokio::fs::set_permissions(path, Permissions::from_mode(writable_mode))
            .await
            .map_err(map_io_error)?;
    }
    if attributes.uid.is_some() || attributes.gid.is_some() {
        debug!("setting uid/gid is not implemented by the mirror example");
    }
    if let Some(size) = attributes.size {
        OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .map_err(map_io_error)?
            .set_len(size)
            .await
            .map_err(map_io_error)?;
    }
    if let Some(access_time) = attributes.access_time {
        let time = set_time_to_file_time(access_time);
        filetime::set_file_atime(path, time).map_err(map_io_error)?;
    }
    if let Some(modify_time) = attributes.modify_time {
        let time = set_time_to_file_time(modify_time);
        filetime::set_file_mtime(path, time).map_err(map_io_error)?;
    }
    Ok(())
}

fn set_time_to_file_time(time: SetTime) -> filetime::FileTime {
    match time {
        SetTime::ServerTime => filetime::FileTime::now(),
        SetTime::ClientTime(time) => filetime::FileTime::from_unix_time(time.seconds as i64, time.nanoseconds),
    }
}

const HOST_PORT: u16 = 11111;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .init();

    let root = PathBuf::from(std::env::args().nth(1).ok_or("must supply directory to mirror")?);
    if !root.is_dir() {
        return Err("mirror root must be a directory".into());
    }
    let listener = TcpListener::bind(("127.0.0.1", HOST_PORT)).await?;
    let server = NfsServer::builder(MirrorFs::new(root))
        .auth_policy(AuthPolicy::AuthSysOrAnonymous)
        .build()?;
    server.serve(listener, std::future::pending()).await?;
    Ok(())
}

// Test with:
// mount -t nfs -o nolocks,vers=3,tcp,port=11111,mountport=11111,soft 127.0.0.1:/ mnt/
