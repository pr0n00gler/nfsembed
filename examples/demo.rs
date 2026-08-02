use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nfsembed::vfs::{
    CreateMode, CreatedObject, DirectoryEntry, FileAttributes, FileType, FsInfo, FsStat, MutationResult, NfsError,
    NfsName, NfsTime, ObjectKey, PathConf, ReadDirectoryPage, ReadResult, RequestContext, SetAttributes, SetTime,
    VfsCapabilities, VirtualFileSystem, WccAttributes, WriteResult, WriteStability,
};
use nfsembed::{
    AuthPolicy, ExportConfig, ExportId, FileHandlePolicy, FileSystemId, NfsServer, PortmapperSockets, ProtocolSet,
    SecurityPolicy, ServerSockets,
};
use tokio::net::{TcpListener, UdpSocket};

const ROOT_ID: u64 = 1;
const GENERATION: u64 = 1;
const READDIR_VERIFIER: [u8; 8] = *b"DEMODIR1";

#[derive(Debug, Clone)]
enum Contents {
    File(Vec<u8>),
    Directory(Vec<u64>),
}

#[derive(Debug, Clone)]
struct Entry {
    id: u64,
    attributes: FileAttributes,
    name: Vec<u8>,
    parent: u64,
    contents: Contents,
    exclusive_verifier: Option<[u8; 8]>,
}

fn now() -> NfsTime {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    NfsTime {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanoseconds: duration.subsec_nanos(),
    }
}

fn make_file(name: &[u8], id: u64, parent: u64, contents: &[u8]) -> Entry {
    let time = now();
    Entry {
        id,
        attributes: FileAttributes {
            file_type: FileType::Regular,
            mode: 0o755,
            links: 1,
            uid: 507,
            gid: 507,
            size: contents.len() as u64,
            used: contents.len() as u64,
            device: None,
            fs_id: 0,
            file_id: id,
            change_id: id.into(),
            access_time: time,
            modify_time: time,
            change_time: time,
        },
        name: name.to_vec(),
        parent,
        contents: Contents::File(contents.to_vec()),
        exclusive_verifier: None,
    }
}

fn make_directory(name: &[u8], id: u64, parent: u64, children: Vec<u64>) -> Entry {
    let time = now();
    Entry {
        id,
        attributes: FileAttributes {
            file_type: FileType::Directory,
            mode: 0o777,
            links: 2,
            uid: 507,
            gid: 507,
            size: 0,
            used: 0,
            device: None,
            fs_id: 0,
            file_id: id,
            change_id: id.into(),
            access_time: time,
            modify_time: time,
            change_time: time,
        },
        name: name.to_vec(),
        parent,
        contents: Contents::Directory(children),
        exclusive_verifier: None,
    }
}

#[derive(Debug)]
pub struct DemoFs {
    entries: Mutex<Vec<Entry>>,
}

impl Default for DemoFs {
    fn default() -> Self {
        // /
        // |- a.txt
        // |- b.txt
        // `- another_dir
        //    `- thisworks.txt
        let entries = vec![
            make_file(b"", 0, 0, &[]), // Object id zero remains unused.
            make_directory(b"/", ROOT_ID, ROOT_ID, vec![2, 3, 4]),
            make_file(b"a.txt", 2, ROOT_ID, b"hello world\n"),
            make_file(b"b.txt", 3, ROOT_ID, b"Greetings to xet data\n"),
            make_directory(b"another_dir", 4, ROOT_ID, vec![5]),
            make_file(b"thisworks.txt", 5, 4, b"i hope\n"),
        ];
        Self {
            entries: Mutex::new(entries),
        }
    }
}

impl DemoFs {
    fn key(id: u64) -> ObjectKey {
        ObjectKey {
            file_id: id,
            generation: GENERATION,
        }
    }

    fn id(object: ObjectKey) -> Result<u64, NfsError> {
        if object.generation == GENERATION {
            Ok(object.file_id)
        } else {
            Err(NfsError::Stale)
        }
    }

    fn wcc(attributes: &FileAttributes) -> WccAttributes {
        WccAttributes {
            size: attributes.size,
            change_id: attributes.change_id,
            modify_time: attributes.modify_time,
            change_time: attributes.change_time,
        }
    }

    fn created(entry: &Entry) -> CreatedObject {
        CreatedObject {
            object: Self::key(entry.id),
            attributes: Some(entry.attributes.clone()),
        }
    }

    fn apply_attributes(entry: &mut Entry, attributes: SetAttributes) -> Result<(), NfsError> {
        if let Some(mode) = attributes.mode {
            entry.attributes.mode = mode;
        }
        if let Some(uid) = attributes.uid {
            entry.attributes.uid = uid;
        }
        if let Some(gid) = attributes.gid {
            entry.attributes.gid = gid;
        }
        if let Some(size) = attributes.size {
            let Contents::File(bytes) = &mut entry.contents else {
                return Err(NfsError::Invalid);
            };
            bytes.resize(usize::try_from(size).map_err(|_| NfsError::FileTooLarge)?, 0);
            entry.attributes.size = size;
            entry.attributes.used = size;
        }
        entry.attributes.access_time = match attributes.access_time {
            Some(SetTime::ServerTime) => now(),
            Some(SetTime::ClientTime(time)) => time,
            None => entry.attributes.access_time,
        };
        entry.attributes.modify_time = match attributes.modify_time {
            Some(SetTime::ServerTime) => now(),
            Some(SetTime::ClientTime(time)) => time,
            None => entry.attributes.modify_time,
        };
        entry.attributes.change_time = now();
        Ok(())
    }
}

#[async_trait]
impl VirtualFileSystem for DemoFs {
    fn capabilities(&self) -> VfsCapabilities {
        VfsCapabilities {
            hard_links: false,
            symbolic_links: false,
            mknod: false,
            ..VfsCapabilities::READ_WRITE
        }
    }

    fn root(&self) -> ObjectKey {
        Self::key(ROOT_ID)
    }

    async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
        let entries = self.entries.lock().unwrap();
        entries
            .get(Self::id(object)? as usize)
            .map(|entry| entry.attributes.clone())
            .ok_or(NfsError::Stale)
    }

    async fn lookup(
        &self,
        _context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError> {
        let parent = Self::id(parent)?;
        let entries = self.entries.lock().unwrap();
        let directory = entries.get(parent as usize).ok_or(NfsError::Stale)?;
        let Contents::Directory(children) = &directory.contents else {
            return Err(NfsError::NotDirectory);
        };
        if name.as_bytes() == b"." {
            return Ok(Self::created(directory));
        }
        if name.as_bytes() == b".." {
            return entries.get(directory.parent as usize).map(Self::created).ok_or(NfsError::Stale);
        }
        children
            .iter()
            .filter_map(|id| entries.get(*id as usize))
            .find(|entry| entry.name == name.as_bytes())
            .map(Self::created)
            .ok_or(NfsError::NotFound)
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
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get_mut(Self::id(object)? as usize).ok_or(NfsError::Stale)?;
        if guard.is_some_and(|guard| guard != entry.attributes.change_time) {
            return Err(NfsError::NotSynchronized);
        }
        let before = Some(Self::wcc(&entry.attributes));
        Self::apply_attributes(entry, attributes)?;
        Ok(MutationResult {
            value: (),
            change_info: None,
            before,
            after: Some(entry.attributes.clone()),
        })
    }

    async fn read(
        &self,
        _context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadResult, NfsError> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(Self::id(object)? as usize).ok_or(NfsError::Stale)?;
        let Contents::File(bytes) = &entry.contents else {
            return Err(NfsError::IsDirectory);
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        Ok(ReadResult {
            data: bytes[start..end].to_vec(),
            eof: end == bytes.len(),
            attributes: Some(entry.attributes.clone()),
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
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get_mut(Self::id(object)? as usize).ok_or(NfsError::Stale)?;
        let before = Some(Self::wcc(&entry.attributes));
        let Contents::File(bytes) = &mut entry.contents else {
            return Err(NfsError::IsDirectory);
        };
        let start = usize::try_from(offset).map_err(|_| NfsError::FileTooLarge)?;
        let end = start.checked_add(data.len()).ok_or(NfsError::FileTooLarge)?;
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        bytes[start..end].copy_from_slice(data);
        entry.attributes.size = bytes.len() as u64;
        entry.attributes.used = bytes.len() as u64;
        entry.attributes.modify_time = now();
        entry.attributes.change_time = entry.attributes.modify_time;
        Ok(MutationResult {
            value: WriteResult {
                count: data.len() as u32,
                committed: requested,
            },
            change_info: None,
            before,
            after: Some(entry.attributes.clone()),
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
        let parent = Self::id(parent)?;
        let mut entries = self.entries.lock().unwrap();
        let directory = entries.get(parent as usize).ok_or(NfsError::Stale)?;
        let Contents::Directory(children) = &directory.contents else {
            return Err(NfsError::NotDirectory);
        };
        if let Some(existing) = children
            .iter()
            .filter_map(|id| entries.get(*id as usize))
            .find(|entry| entry.name == name.as_bytes())
        {
            let replayed_exclusive = match mode {
                CreateMode::Exclusive { verifier } => existing.exclusive_verifier == Some(verifier),
                _ => false,
            };
            return if mode == CreateMode::Unchecked || replayed_exclusive {
                Ok(MutationResult {
                    value: Self::created(existing),
                    change_info: None,
                    before: Some(Self::wcc(&directory.attributes)),
                    after: Some(directory.attributes.clone()),
                })
            } else {
                Err(NfsError::Exists)
            };
        }
        let before = Some(Self::wcc(&directory.attributes));
        let id = entries.len() as u64;
        let mut entry = make_file(name.as_bytes(), id, parent, &[]);
        if let CreateMode::Exclusive { verifier } = mode {
            entry.exclusive_verifier = Some(verifier);
        }
        Self::apply_attributes(&mut entry, attributes)?;
        entries.push(entry);
        let created = Self::created(entries.last().unwrap());
        let directory = entries.get_mut(parent as usize).unwrap();
        let Contents::Directory(children) = &mut directory.contents else {
            unreachable!();
        };
        children.push(id);
        directory.attributes.change_time = now();
        Ok(MutationResult {
            value: created,
            change_info: None,
            before,
            after: Some(directory.attributes.clone()),
        })
    }

    async fn readdir(
        &self,
        _context: &RequestContext,
        directory: ObjectKey,
        cookie: u64,
        verifier: [u8; 8],
        backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        if cookie != 0 && verifier != READDIR_VERIFIER {
            return Err(NfsError::BadCookie);
        }
        let entries = self.entries.lock().unwrap();
        let directory = entries.get(Self::id(directory)? as usize).ok_or(NfsError::Stale)?;
        let Contents::Directory(children) = &directory.contents else {
            return Err(NfsError::NotDirectory);
        };
        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        let page = children
            .iter()
            .enumerate()
            .skip(start)
            .take(backend_hint.max(1))
            .filter_map(|(index, id)| entries.get(*id as usize).map(|entry| (index, entry)))
            .map(|(index, entry)| DirectoryEntry {
                object: Self::key(entry.id),
                file_id: entry.id,
                name: NfsName::new(entry.name.clone()).unwrap(),
                cookie: index as u64 + 1,
                attributes: Some(entry.attributes.clone()),
            })
            .collect::<Vec<_>>();
        Ok(ReadDirectoryPage {
            verifier: READDIR_VERIFIER,
            eof: start.saturating_add(page.len()) >= children.len(),
            entries: page,
        })
    }

    async fn fsstat(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        Ok(FsStat {
            total_bytes: 1 << 30,
            free_bytes: 1 << 29,
            available_bytes: 1 << 29,
            total_files: 1_000_000,
            free_files: 999_000,
            available_files: 999_000,
            invariant_seconds: 1,
        })
    }

    async fn fsinfo(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
        Ok(default_fs_info())
    }

    async fn pathconf(&self, _context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        Ok(default_path_conf())
    }
}

fn default_fs_info() -> FsInfo {
    FsInfo {
        max_read: 1024 * 1024,
        preferred_read: 128 * 1024,
        read_multiple: 4096,
        max_write: 1024 * 1024,
        preferred_write: 128 * 1024,
        write_multiple: 4096,
        preferred_readdir: 32 * 1024,
        max_file_size: 128 * 1024 * 1024 * 1024,
        time_granularity: NfsTime {
            seconds: 0,
            nanoseconds: 1_000_000,
        },
    }
}

fn default_path_conf() -> PathConf {
    PathConf {
        max_links: u32::MAX,
        max_name_length: NfsName::MAX_LEN as u32,
        no_truncation: true,
        chown_restricted: true,
        case_insensitive: false,
        case_preserving: true,
    }
}

const HOST_PORT: u16 = 11111;
const MOUNT_PORT: u16 = 11112;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .init();

    let listener = TcpListener::bind(("127.0.0.1", HOST_PORT)).await?;
    let mount_listener = TcpListener::bind(("127.0.0.1", MOUNT_PORT)).await?;
    let server = NfsServer::builder(ProtocolSet::V3)
        .add_export_owned(
            ExportConfig::new(
                ExportId(1),
                "/",
                FileSystemId::new(0x4e46_5345, 1),
                SecurityPolicy::auth_sys(),
                FileHandlePolicy::Volatile,
            ),
            DemoFs::default(),
        )
        .auth_policy(AuthPolicy::AuthSysOrAnonymous)
        .build()?;
    if let Ok(address) = std::env::var("NFSEMBED_PORTMAPPER") {
        let portmapper_tcp = TcpListener::bind(address).await?;
        let portmapper_udp = UdpSocket::bind(portmapper_tcp.local_addr()?).await?;
        server
            .serve(
                ServerSockets::new(listener)
                    .with_mount_listener(mount_listener)
                    .with_portmapper(PortmapperSockets::new(portmapper_tcp, portmapper_udp)),
                std::future::pending(),
            )
            .await?;
    } else {
        server
            .serve(ServerSockets::new(listener).with_mount_listener(mount_listener), std::future::pending())
            .await?;
    }
    Ok(())
}

// Test with:
// mount -t nfs -o nolocks,vers=3,tcp,port=11111,mountport=11112,soft 127.0.0.1:/ mnt/
