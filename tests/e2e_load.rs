mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use nfsserve::rpc::codec::Encoder;
use nfsserve::server::{AuthPolicy, PortmapperMode, ServerLimits};
use nfsserve::vfs::ExportId;
use support::rpc::{mount_root, nfs_args_handle, nfs_payload, start_server_with, RpcClient, NFS_PROGRAM, NFS_VERSION};
use support::vfs::ConformanceVfs;
use tokio::sync::Barrier;
use tokio::time::timeout;

#[cfg(target_os = "linux")]
fn resident_memory_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
fn resident_memory_kib() -> Option<u64> {
    None
}

#[tokio::test]
async fn sustained_connections_requests_and_mutations_remain_bounded() {
    const CLIENTS: usize = 24;
    const REQUESTS_PER_CLIENT: usize = 100;
    const WRITES_PER_CLIENT: usize = REQUESTS_PER_CLIENT / 4;
    const MAX_INFLIGHT: usize = 8;
    const MAX_RSS_GROWTH_KIB: u64 = 128 * 1024;

    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    vfs.delay("write", Duration::from_millis(1));
    let mut limits = ServerLimits::production_defaults();
    limits.max_connections = CLIENTS + 4;
    limits.max_requests_per_connection = 4;
    limits.max_inflight_requests = MAX_INFLIGHT;
    limits.replay_cache_capacity = CLIENTS * REQUESTS_PER_CLIENT * 2;
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let barrier = Arc::new(Barrier::new(CLIENTS));
    let memory_before = resident_memory_kib();
    let started = Instant::now();

    let mut tasks = Vec::with_capacity(CLIENTS);
    for client_index in 0..CLIENTS {
        let barrier = barrier.clone();
        let address = server.address;
        tasks.push(tokio::spawn(async move {
            let mut client = RpcClient::connect(address).await;
            let root = mount_root(&mut client, b"/").await;
            barrier.wait().await;
            for request_index in 0..REQUESTS_PER_CLIENT {
                let payload = if request_index % 4 == 0 {
                    let data = vec![client_index as u8; 1024];
                    let mut arguments = Encoder::new();
                    arguments.write_opaque(&root).unwrap();
                    arguments.write_u64((request_index * 1024) as u64);
                    arguments.write_u32(data.len() as u32);
                    arguments.write_u32(0);
                    arguments.write_opaque(&data).unwrap();
                    nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 7, &arguments.into_bytes()).await)
                } else {
                    nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root)).await)
                };
                assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 0);
            }
        }));
    }

    timeout(Duration::from_secs(20), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("sustained load did not complete within its certification threshold");

    assert_eq!(vfs.call_count("write"), CLIENTS * WRITES_PER_CLIENT);
    assert!(vfs.max_concurrency_observed() > 1);
    assert!(vfs.max_concurrency_observed() <= MAX_INFLIGHT);
    assert!(started.elapsed() < Duration::from_secs(20));

    server.shutdown().await;
    if let (Some(before), Some(after)) = (memory_before, resident_memory_kib()) {
        assert!(
            after.saturating_sub(before) <= MAX_RSS_GROWTH_KIB,
            "resident memory grew by {} KiB under bounded load",
            after.saturating_sub(before)
        );
    }
}
