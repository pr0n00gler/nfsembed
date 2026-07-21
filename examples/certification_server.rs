#[allow(dead_code)]
#[path = "../tests/support/certification_vfs.rs"]
mod certification_vfs;

use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use certification_vfs::{CertificationProfile, CertificationVfs};
use nfsserve::rpc::codec::Decoder;
use nfsserve::rpc::record::{read_record, write_record_limited, RecordLimits};
use nfsserve::{AuthPolicy, ExportId, NfsServer};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let listen = arguments.next().unwrap_or_else(|| "127.0.0.1:0".to_owned());
    let ready_file = PathBuf::from(arguments.next().ok_or("missing ready-file argument")?);
    let shutdown_file = PathBuf::from(arguments.next().ok_or("missing shutdown-file argument")?);
    let (profile, lose_first_write_reply) = match arguments.next().as_deref() {
        None | Some("read-write") => (CertificationProfile::ReadWrite, false),
        Some("lost-reply") => (CertificationProfile::ReadWrite, true),
        Some("read-only") => (CertificationProfile::ReadOnly, false),
        Some("case-insensitive") => (CertificationProfile::CaseInsensitive, false),
        Some(_) => return Err("unknown certification profile".into()),
    };
    let restart_file = arguments.next().map(PathBuf::from);

    let vfs = Arc::new(CertificationVfs::new(ExportId(1), profile));
    let server = NfsServer::builder_arc(vfs)
        .auth_policy(AuthPolicy::AuthSysOrAnonymous)
        .build()?;
    if lose_first_write_reply {
        return serve_with_lost_write_reply(&server, &listen, &ready_file, &shutdown_file).await;
    }
    let mut bind_address = listen;

    loop {
        let listener = TcpListener::bind(&bind_address).await?;
        let address = listener.local_addr()?;
        bind_address = address.to_string();
        std::fs::write(&ready_file, address.port().to_string())?;

        let watched_shutdown = shutdown_file.clone();
        let watched_restart = restart_file.clone();
        server
            .serve(listener, async move {
                while !watched_shutdown.exists() && !watched_restart.as_ref().is_some_and(|restart| restart.exists()) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await?;
        if shutdown_file.exists() || restart_file.is_none() {
            break;
        }
        if let Some(restart) = &restart_file {
            let _ = std::fs::remove_file(restart);
        }
    }
    Ok(())
}

async fn serve_with_lost_write_reply(
    server: &NfsServer,
    listen: &str,
    ready_file: &Path,
    shutdown_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let server_handle = server.start(upstream_listener).await?;
    let public_listener = TcpListener::bind(listen).await?;
    std::fs::write(ready_file, public_listener.local_addr()?.port().to_string())?;
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
        && decoder.read_u32() == Ok(nfsserve::nfs3::types::PROGRAM)
        && decoder.read_u32() == Ok(nfsserve::nfs3::types::VERSION)
        && decoder.read_u32() == Ok(7)
}
