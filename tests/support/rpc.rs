use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::rpc::record::{read_record, write_record, RecordLimits};
use nfsembed::server::{
    AuthPolicy, ExportConfig, FileHandlePolicy, FileSystemId, NfsServer, NfsServerHandle, ProtocolSet, SecurityPolicy,
    ServerLimits, ServerSockets,
};
use nfsembed::vfs::{ExportId, VirtualFileSystem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const NFS_PROGRAM: u32 = 100_003;
pub const NFS_VERSION: u32 = 3;
pub const MOUNT_PROGRAM: u32 = 100_005;
pub const MOUNT_VERSION: u32 = 3;
pub const PORTMAP_PROGRAM: u32 = 100_000;
pub const PORTMAP_VERSION: u32 = 2;

const RECORD_LIMITS: RecordLimits = RecordLimits {
    max_record_size: 4 * 1024 * 1024,
    max_fragment_size: 2 * 1024 * 1024,
    max_fragments: 32,
};

#[derive(Clone, Debug)]
pub enum Auth {
    Sys,
    None,
    Raw { flavor: u32, body: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcOutcome {
    Accepted {
        xid: u32,
        status: u32,
        payload: Vec<u8>,
    },
    Denied {
        xid: u32,
        reject_status: u32,
        details: Vec<u8>,
    },
}

impl RpcOutcome {
    pub fn accepted(self) -> (u32, Vec<u8>) {
        match self {
            Self::Accepted { status, payload, .. } => (status, payload),
            other => panic!("expected accepted RPC reply, got {other:?}"),
        }
    }
}

pub struct RpcClient {
    address: SocketAddr,
    stream: Option<TcpStream>,
    mount_address: Option<SocketAddr>,
    next_xid: u32,
    auth: Auth,
}

static MOUNT_ENDPOINTS: OnceLock<Mutex<HashMap<SocketAddr, SocketAddr>>> = OnceLock::new();

fn mount_endpoints() -> &'static Mutex<HashMap<SocketAddr, SocketAddr>> {
    MOUNT_ENDPOINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

impl RpcClient {
    pub async fn connect(address: SocketAddr) -> Self {
        let mount_address = mount_endpoints().lock().unwrap().get(&address).copied();
        Self {
            address,
            stream: None,
            mount_address,
            next_xid: 1,
            auth: Auth::Sys,
        }
    }

    pub fn set_auth(&mut self, auth: Auth) {
        self.auth = auth;
    }

    pub async fn call(&mut self, program: u32, version: u32, procedure: u32, arguments: &[u8]) -> RpcOutcome {
        let xid = self.next_xid;
        self.next_xid += 1;
        self.call_with_xid(xid, program, version, procedure, arguments).await
    }

    pub async fn call_with_xid(
        &mut self,
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
    ) -> RpcOutcome {
        let request = rpc_call(xid, 2, program, version, procedure, arguments, &self.auth);
        self.exchange(program, &request).await
    }

    pub async fn call_with_rpc_version(
        &mut self,
        xid: u32,
        rpc_version: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
    ) -> RpcOutcome {
        let request = rpc_call(xid, rpc_version, program, version, procedure, arguments, &self.auth);
        self.exchange(program, &request).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn call_with_verifier(
        &mut self,
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
        verifier_flavor: u32,
        verifier: &[u8],
    ) -> RpcOutcome {
        let request = rpc_call_with_verifier(
            xid,
            2,
            program,
            version,
            procedure,
            arguments,
            &self.auth,
            verifier_flavor,
            verifier,
        );
        self.exchange(program, &request).await
    }

    pub async fn send_without_reading(
        &mut self,
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: &[u8],
    ) {
        let request = rpc_call(xid, 2, program, version, procedure, arguments, &self.auth);
        let stream = self.nfs_stream().await;
        write_record(&mut *stream, &request, 1024 * 1024).await.unwrap();
    }

    pub async fn read_reply(&mut self) -> RpcOutcome {
        let record = read_record(self.nfs_stream().await, RECORD_LIMITS).await.unwrap();
        parse_reply(&record)
    }

    async fn exchange(&mut self, program: u32, request: &[u8]) -> RpcOutcome {
        if program == MOUNT_PROGRAM {
            let address = self.mount_address.unwrap_or(self.address);
            let mut stream = TcpStream::connect(address).await.unwrap();
            write_record(&mut stream, request, 1024 * 1024).await.unwrap();
            let record = read_record(&mut stream, RECORD_LIMITS).await.unwrap();
            // MOUNT calls use a fresh connection. Complete the TCP close
            // handshake before returning so connection-limit tests do not
            // race the server task that owns the released permit.
            stream.shutdown().await.unwrap();
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
            parse_reply(&record)
        } else {
            let stream = self.nfs_stream().await;
            write_record(&mut *stream, request, 1024 * 1024).await.unwrap();
            let record = read_record(&mut *stream, RECORD_LIMITS).await.unwrap();
            parse_reply(&record)
        }
    }

    async fn nfs_stream(&mut self) -> &mut TcpStream {
        if self.stream.is_none() {
            self.stream = Some(TcpStream::connect(self.address).await.unwrap());
        }
        self.stream.as_mut().unwrap()
    }

    pub async fn write_raw(&mut self, bytes: &[u8]) {
        self.nfs_stream().await.write_all(bytes).await.unwrap();
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream.expect("NFS connection was never opened")
    }
}

pub struct RunningServer {
    pub handle: NfsServerHandle,
    pub address: SocketAddr,
    pub mount_address: Option<SocketAddr>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        mount_endpoints().lock().unwrap().remove(&self.address);
        self.handle.shutdown().await.unwrap();
        self.handle.wait().await.unwrap();
    }
}

pub async fn start_server(vfs: Arc<dyn VirtualFileSystem>) -> RunningServer {
    start_server_with(vfs, ServerLimits::production_defaults(), AuthPolicy::AuthSys).await
}

pub async fn start_server_with(
    vfs: Arc<dyn VirtualFileSystem>,
    limits: ServerLimits,
    auth_policy: AuthPolicy,
) -> RunningServer {
    let security_policy = match auth_policy {
        AuthPolicy::AuthSys => SecurityPolicy::auth_sys(),
        AuthPolicy::Anonymous => SecurityPolicy::anonymous(),
        AuthPolicy::AuthSysOrAnonymous => SecurityPolicy::auth_sys_or_anonymous(),
    };
    let server = NfsServer::builder(ProtocolSet::V3)
        .add_export(
            ExportConfig::new(
                ExportId(1),
                "/",
                FileSystemId::new(0x4e46_5345, 1),
                security_policy,
                FileHandlePolicy::Volatile,
            ),
            vfs,
        )
        .limits(limits)
        .auth_policy(auth_policy)
        .build()
        .unwrap();
    start_built_server(server).await
}

pub async fn start_built_server(server: NfsServer) -> RunningServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sockets = if server.protocols().includes_v3() {
        ServerSockets::new(listener).with_mount_listener(TcpListener::bind("127.0.0.1:0").await.unwrap())
    } else {
        ServerSockets::new(listener)
    };
    let handle = server.start(sockets).await.unwrap();
    let address = handle.endpoint_info().address;
    let mount_address = handle
        .endpoint_info()
        .mount_port
        .map(|port| SocketAddr::new(address.ip(), port));
    if let Some(mount_address) = mount_address {
        mount_endpoints().lock().unwrap().insert(address, mount_address);
    }
    RunningServer {
        handle,
        address,
        mount_address,
    }
}

pub fn rpc_call(
    xid: u32,
    rpc_version: u32,
    program: u32,
    version: u32,
    procedure: u32,
    arguments: &[u8],
    auth: &Auth,
) -> Vec<u8> {
    rpc_call_with_verifier(xid, rpc_version, program, version, procedure, arguments, auth, 0, &[])
}

#[allow(clippy::too_many_arguments)]
pub fn rpc_call_with_verifier(
    xid: u32,
    rpc_version: u32,
    program: u32,
    version: u32,
    procedure: u32,
    arguments: &[u8],
    auth: &Auth,
    verifier_flavor: u32,
    verifier: &[u8],
) -> Vec<u8> {
    let (credential_flavor, credential_body) = match auth {
        Auth::Sys => (1, auth_sys_body()),
        Auth::None => (0, Vec::new()),
        Auth::Raw { flavor, body } => (*flavor, body.clone()),
    };
    let mut call = Encoder::new();
    call.write_u32(xid);
    call.write_u32(0);
    call.write_u32(rpc_version);
    call.write_u32(program);
    call.write_u32(version);
    call.write_u32(procedure);
    call.write_u32(credential_flavor);
    call.write_opaque(&credential_body).unwrap();
    call.write_u32(verifier_flavor);
    call.write_opaque(verifier).unwrap();
    call.write_fixed(arguments);
    call.into_bytes()
}

pub fn auth_sys_body() -> Vec<u8> {
    let mut auth = Encoder::new();
    auth.write_u32(0x1234_5678);
    auth.write_opaque(b"e2e-client").unwrap();
    auth.write_u32(1000);
    auth.write_u32(100);
    auth.write_u32(2);
    auth.write_u32(10);
    auth.write_u32(20);
    auth.into_bytes()
}

pub fn parse_reply(record: &[u8]) -> RpcOutcome {
    let mut decoder = Decoder::new(record);
    let xid = decoder.read_u32().unwrap();
    assert_eq!(decoder.read_u32().unwrap(), 1, "server returned an RPC call instead of a reply");
    match decoder.read_u32().unwrap() {
        0 => {
            let _verifier_flavor = decoder.read_u32().unwrap();
            let _verifier = decoder.read_opaque("reply verifier", 400).unwrap();
            let status = decoder.read_u32().unwrap();
            RpcOutcome::Accepted {
                xid,
                status,
                payload: record[decoder.position()..].to_vec(),
            }
        },
        1 => {
            let reject_status = decoder.read_u32().unwrap();
            RpcOutcome::Denied {
                xid,
                reject_status,
                details: record[decoder.position()..].to_vec(),
            }
        },
        value => panic!("invalid RPC reply discriminant {value}"),
    }
}

pub fn nfs_args_handle(handle: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(handle).unwrap();
    encoder.into_bytes()
}

pub fn nfs_args_directory(handle: &[u8], name: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(handle).unwrap();
    encoder.write_opaque(name).unwrap();
    encoder.into_bytes()
}

pub fn encode_empty_set_attributes(encoder: &mut Encoder) {
    encoder.write_bool(false);
    encoder.write_bool(false);
    encoder.write_bool(false);
    encoder.write_bool(false);
    encoder.write_u32(0);
    encoder.write_u32(0);
}

pub async fn mount_root(client: &mut RpcClient, path: &[u8]) -> Vec<u8> {
    let mut arguments = Encoder::new();
    arguments.write_opaque(path).unwrap();
    let (rpc_status, payload) = client
        .call(MOUNT_PROGRAM, MOUNT_VERSION, 1, &arguments.into_bytes())
        .await
        .accepted();
    assert_eq!(rpc_status, 0);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let handle = decoder.read_opaque("mount handle", 64).unwrap();
    let flavors = decoder.read_u32().unwrap();
    assert!(flavors >= 1);
    for _ in 0..flavors {
        let _ = decoder.read_u32().unwrap();
    }
    decoder.finish().unwrap();
    handle
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireAttributes {
    pub file_type: u32,
    pub mode: u32,
    pub links: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub fs_id: u64,
    pub file_id: u64,
}

pub fn decode_attributes(decoder: &mut Decoder<'_>) -> WireAttributes {
    let file_type = decoder.read_u32().unwrap();
    let mode = decoder.read_u32().unwrap();
    let links = decoder.read_u32().unwrap();
    let uid = decoder.read_u32().unwrap();
    let gid = decoder.read_u32().unwrap();
    let size = decoder.read_u64().unwrap();
    let used = decoder.read_u64().unwrap();
    let rdev_major = decoder.read_u32().unwrap();
    let rdev_minor = decoder.read_u32().unwrap();
    let fs_id = decoder.read_u64().unwrap();
    let file_id = decoder.read_u64().unwrap();
    for _ in 0..3 {
        let _seconds = decoder.read_u32().unwrap();
        let _nanoseconds = decoder.read_u32().unwrap();
    }
    WireAttributes {
        file_type,
        mode,
        links,
        uid,
        gid,
        size,
        used,
        rdev_major,
        rdev_minor,
        fs_id,
        file_id,
    }
}

pub fn decode_post_attributes(decoder: &mut Decoder<'_>) -> Option<WireAttributes> {
    decoder.read_bool().unwrap().then(|| decode_attributes(decoder))
}

pub fn decode_wcc(decoder: &mut Decoder<'_>) -> (bool, bool) {
    let before = decoder.read_bool().unwrap();
    if before {
        let _size = decoder.read_u64().unwrap();
        for _ in 0..2 {
            let _seconds = decoder.read_u32().unwrap();
            let _nanoseconds = decoder.read_u32().unwrap();
        }
    }
    let after = decode_post_attributes(decoder).is_some();
    (before, after)
}

pub fn nfs_payload(outcome: RpcOutcome) -> Vec<u8> {
    let (rpc_status, payload) = outcome.accepted();
    assert_eq!(rpc_status, 0, "RPC layer rejected NFS request");
    payload
}

pub fn assert_nfs_status(outcome: RpcOutcome, expected: u32) -> Vec<u8> {
    let payload = nfs_payload(outcome);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), expected);
    payload
}

pub fn record_header(length: usize, last: bool) -> [u8; 4] {
    let length = u32::try_from(length).unwrap();
    (length | if last { 0x8000_0000 } else { 0 }).to_be_bytes()
}
