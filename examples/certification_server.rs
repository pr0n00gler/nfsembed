#[allow(dead_code)]
#[path = "../tests/support/certification_vfs.rs"]
mod certification_vfs;
#[path = "mirrorfs.rs"]
mod mirrorfs_backend;

use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use certification_vfs::{CertificationProfile, CertificationVfs};
use nfsembed::rpc::codec::Decoder;
use nfsembed::rpc::record::{read_record, write_record_limited, RecordLimits};
use nfsembed::{
    AuthPolicy, ExportConfig, ExportId, FileHandlePolicy, FileSystemId, Nfs4Config, NfsServer, NumericIdentityMapper,
    PortmapperSockets, ProtocolSet, SecurityPolicy, ServerSockets, VirtualFileSystem,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("NFSEMBED_TRACE").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .try_init()
            .expect("certification tracing subscriber installs once");
    }
    let mut arguments = env::args().skip(1);
    let listen = arguments.next().unwrap_or_else(|| "127.0.0.1:0".to_owned());
    let ready_file = PathBuf::from(arguments.next().ok_or("missing ready-file argument")?);
    let shutdown_file = PathBuf::from(arguments.next().ok_or("missing shutdown-file argument")?);
    let profile = arguments.next().unwrap_or_else(|| "read-write".to_owned());
    let restart_file = arguments.next().map(PathBuf::from);
    let portmapper_listen = arguments.next();
    let backend_root = arguments.next().map(PathBuf::from);
    let (protocols, protocol_name) = protocol_selection()?;

    let (vfs, lose_first_write_reply): (Arc<dyn VirtualFileSystem>, bool) = match profile.as_str() {
        "read-write" => (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite)), false),
        "lost-reply" => (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::ReadWrite)), true),
        "read-only" => (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::ReadOnly)), false),
        "case-insensitive" => {
            (Arc::new(CertificationVfs::new(ExportId(1), CertificationProfile::CaseInsensitive)), false)
        },
        "mirror" => (
            Arc::new(mirrorfs_backend::MirrorFs::new(backend_root.ok_or("mirror profile requires a backend root")?)),
            false,
        ),
        _ => return Err("unknown certification profile".into()),
    };
    if lose_first_write_reply && protocols.includes_v4() {
        return Err("the lost-reply proxy is an NFSv3-only certification profile".into());
    }
    if profile == "mirror" && protocols.includes_v4() {
        return Err("the mirror certification backend is currently NFSv3-only".into());
    }

    let mut builder = NfsServer::builder(protocols)
        .add_export(
            ExportConfig::new(
                ExportId(1),
                "/",
                FileSystemId::new(0, 1001),
                SecurityPolicy::auth_sys(),
                FileHandlePolicy::Volatile,
            ),
            vfs,
        )
        .auth_policy(AuthPolicy::AuthSysOrAnonymous);
    if protocols.includes_v4() {
        // pynfs uses the interoperable bare-numeric owner form and verifies
        // that a successful SETATTR round-trips the same identity spelling.
        let lease_duration = certification_lease_duration()?;
        builder = builder.nfs4(
            Nfs4Config::in_memory(Arc::new(NumericIdentityMapper::new("")), None)
                .with_lease_duration(lease_duration)
                .with_grace_duration(lease_duration),
        );
    }
    let server = builder.build()?;
    let capability_profile = match (protocols.includes_v4(), profile.as_str()) {
        (true, "read-only") => "nfs4-mandatory-read-only",
        (true, _) => "nfs4-mandatory-read-write",
        (false, "read-only") => "v3-read-only",
        (false, _) => "v3-read-write",
    };
    eprintln!(
        "certification protocol={protocol_name} security=AUTH_SYS recovery={} export=/ capabilities={}",
        if protocols.includes_v4() {
            "InMemoryRejectReclaims"
        } else {
            "not-applicable"
        },
        capability_profile,
    );
    if lose_first_write_reply {
        return serve_with_lost_write_reply(
            &server,
            &listen,
            &ready_file,
            &shutdown_file,
            portmapper_listen.as_deref(),
        )
        .await;
    }
    let mut bind_address = listen;

    loop {
        let listener = TcpListener::bind(&bind_address).await?;
        let address = listener.local_addr()?;
        bind_address = address.to_string();
        let mount_listener = if protocols.includes_v3() {
            Some(TcpListener::bind((address.ip(), 0)).await?)
        } else {
            None
        };
        let mount_port = mount_listener
            .as_ref()
            .map(|listener| listener.local_addr())
            .transpose()?
            .map(|address| address.port());
        let mut sockets = ServerSockets::new(listener);
        if let Some(mount_listener) = mount_listener {
            sockets = sockets.with_mount_listener(mount_listener);
        }
        if let Some(portmapper_listen) = portmapper_listen.as_deref() {
            sockets = sockets.with_portmapper(
                bind_portmapper(portmapper_listen, address.port(), mount_port.unwrap_or(address.port())).await?,
            );
        }
        let handle = server.start(sockets).await?;
        write_ready_file(&ready_file, address.port(), mount_port)?;
        while !shutdown_file.exists() && !restart_file.as_ref().is_some_and(|restart| restart.exists()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.shutdown().await?;
        handle.wait().await?;
        if shutdown_file.exists() || restart_file.is_none() {
            break;
        }
        if let Some(restart) = &restart_file {
            let _ = std::fs::remove_file(restart);
        }
    }
    Ok(())
}

fn certification_lease_duration() -> Result<Duration, Box<dyn std::error::Error>> {
    let Some(value) = env::var_os("NFSEMBED_CERT_LEASE_SECONDS") else {
        return Ok(Duration::from_secs(90));
    };
    let value = value
        .into_string()
        .map_err(|_| "NFSEMBED_CERT_LEASE_SECONDS must be valid UTF-8")?;
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "NFSEMBED_CERT_LEASE_SECONDS must be a positive integer")?;
    if seconds == 0 {
        return Err("NFSEMBED_CERT_LEASE_SECONDS must be greater than zero".into());
    }
    Ok(Duration::from_secs(seconds))
}

fn write_ready_file(path: &Path, nfs_port: u16, mount_port: Option<u16>) -> Result<(), std::io::Error> {
    let contents = match mount_port {
        Some(mount_port) => format!("{nfs_port} {mount_port}\n"),
        None => format!("{nfs_port}\n"),
    };
    std::fs::write(path, contents)
}

fn protocol_selection() -> Result<(ProtocolSet, &'static str), Box<dyn std::error::Error>> {
    match env::var("NFSEMBED_PROTOCOL")
        .unwrap_or_else(|_| "v3".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "v3" => Ok((ProtocolSet::V3, "V3")),
        "v4" => Ok((ProtocolSet::V4, "V4")),
        "v3-and-v4" | "v3andv4" | "both" => Ok((ProtocolSet::V3AndV4, "V3AndV4")),
        _ => Err("NFSEMBED_PROTOCOL must be v3, v4, or v3-and-v4".into()),
    }
}

async fn serve_with_lost_write_reply(
    server: &NfsServer,
    listen: &str,
    ready_file: &Path,
    shutdown_file: &Path,
    portmapper_listen: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let public_listener = TcpListener::bind(listen).await?;
    let public_address = public_listener.local_addr()?;
    let public_port = public_address.port();
    let mount_listener = TcpListener::bind((public_address.ip(), 0)).await?;
    let mount_port = mount_listener.local_addr()?.port();
    let mut sockets = ServerSockets::new(upstream_listener).with_mount_listener(mount_listener);
    if let Some(portmapper_listen) = portmapper_listen {
        sockets = sockets.with_portmapper(bind_portmapper(portmapper_listen, public_port, mount_port).await?);
    }
    let server_handle = server.start(sockets).await?;
    write_ready_file(ready_file, public_port, Some(mount_port))?;
    let lose_reply = Arc::new(AtomicBool::new(true));
    let mut proxies = JoinSet::new();

    loop {
        tokio::select! {
            accepted = public_listener.accept() => {
                let (client, _) = accepted?;
                let lose_reply = lose_reply.clone();
                proxies.spawn(async move {
                    let _ = proxy_connection(client, upstream_address, lose_reply).await;
                });
            },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if shutdown_file.exists() {
                    break;
                }
            },
            Some(_) = proxies.join_next(), if !proxies.is_empty() => {},
        }
    }

    proxies.abort_all();
    while proxies.join_next().await.is_some() {}
    server_handle.shutdown().await?;
    server_handle.wait().await?;
    Ok(())
}

async fn bind_portmapper(
    address: &str,
    advertised_nfs_port: u16,
    advertised_mount_port: u16,
) -> Result<PortmapperSockets, std::io::Error> {
    let tcp = TcpListener::bind(address).await?;
    let udp = UdpSocket::bind(tcp.local_addr()?).await?;
    Ok(PortmapperSockets::new(tcp, udp).advertised_ports(advertised_nfs_port, advertised_mount_port))
}

async fn proxy_connection(
    mut client: TcpStream,
    upstream_address: std::net::SocketAddr,
    lose_reply: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut upstream = TcpStream::connect(upstream_address).await?;
    let limits = RecordLimits {
        max_record_size: 2 * 1024 * 1024,
        max_fragment_size: 1024 * 1024,
        max_fragments: 16,
    };
    loop {
        let request = read_record(&mut client, limits).await?;
        let is_write = is_nfs_write(&request);
        write_record_limited(&mut upstream, &request, limits).await?;
        let reply = read_record(&mut upstream, limits).await?;
        if is_write && lose_reply.swap(false, Ordering::SeqCst) {
            // The backend completed and the reply cache was populated, but
            // the native client observes a lost TCP reply and must reconnect.
            return Ok(());
        }
        write_record_limited(&mut client, &reply, limits).await?;
    }
}

fn is_nfs_write(record: &[u8]) -> bool {
    let mut decoder = Decoder::new(record);
    decoder.read_u32().is_ok()
        && decoder.read_u32() == Ok(0)
        && decoder.read_u32() == Ok(2)
        && decoder.read_u32() == Ok(nfsembed::nfs3::types::PROGRAM)
        && decoder.read_u32() == Ok(nfsembed::nfs3::types::VERSION)
        && decoder.read_u32() == Ok(7)
}
