mod support;

use std::sync::Arc;

use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::server::{AuthPolicy, PortmapperMode, ServerLimits};
use nfsembed::vfs::ExportId;
use support::rpc::{
    auth_sys_body, mount_root, nfs_args_directory, nfs_args_handle, nfs_payload, record_header, rpc_call, start_server,
    start_server_with, Auth, RpcClient, RpcOutcome, NFS_PROGRAM, NFS_VERSION,
};
use support::vfs::ConformanceVfs;

async fn lookup_handle(client: &mut RpcClient, root: &[u8], name: &[u8]) -> Vec<u8> {
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(root, name)).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    decoder.read_opaque("lookup handle", 64).unwrap()
}

#[tokio::test]
async fn valid_rpc_call_survives_every_fragment_size() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let mut limits = ServerLimits::production_defaults();
    limits.max_fragments_per_record = 128;
    let server = start_server_with(vfs, limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;

    for fragment_size in 1..=96 {
        let xid = 1_000 + fragment_size as u32;
        let request = rpc_call(xid, 2, NFS_PROGRAM, NFS_VERSION, 0, &[], &Auth::Sys);
        let mut framed = Vec::new();
        let chunk_count = request.len().div_ceil(fragment_size);
        for (index, chunk) in request.chunks(fragment_size).enumerate() {
            framed.extend_from_slice(&record_header(chunk.len(), index + 1 == chunk_count));
            framed.extend_from_slice(chunk);
        }
        client.write_raw(&framed).await;
        match client.read_reply().await {
            RpcOutcome::Accepted {
                xid: reply_xid,
                status: 0,
                payload,
            } => {
                assert_eq!(reply_xid, xid);
                assert!(payload.is_empty());
            },
            other => panic!("fragment size {fragment_size} failed: {other:?}"),
        }
    }

    server.shutdown().await;
}

#[tokio::test]
async fn authentication_prefix_corpus_is_bounded_and_connection_recovers() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs).await;
    let mut client = RpcClient::connect(server.address).await;
    let body = auth_sys_body();

    for end in 0..body.len() {
        client.set_auth(Auth::Raw {
            flavor: 1,
            body: body[..end].to_vec(),
        });
        assert!(matches!(
            client.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await,
            RpcOutcome::Denied { reject_status: 1, .. }
        ));
    }
    client.set_auth(Auth::Sys);
    let (status, payload) = client.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn every_truncated_write_prefix_and_length_mismatch_is_rejected() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_write_size = 16;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs.clone(), limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    let mut valid = Encoder::new();
    valid.write_opaque(&file).unwrap();
    valid.write_u64(10);
    valid.write_u32(8);
    valid.write_u32(0);
    valid.write_opaque(b"12345678").unwrap();
    let valid = valid.into_bytes();
    for end in 0..valid.len() {
        let outcome = client.call(NFS_PROGRAM, NFS_VERSION, 7, &valid[..end]).await;
        match outcome {
            RpcOutcome::Accepted { status: 4, .. } => {},
            RpcOutcome::Accepted { status: 0, payload, .. } => {
                assert_ne!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 0, "prefix {end} succeeded");
            },
            other => panic!("write prefix {end} produced unexpected reply: {other:?}"),
        }
    }
    assert_eq!(vfs.call_count("write"), 0);

    for (declared, data) in [
        (0, b"x".as_slice()),
        (2, b"x".as_slice()),
        (17, b"12345678901234567".as_slice()),
    ] {
        let mut arguments = Encoder::new();
        arguments.write_opaque(&file).unwrap();
        arguments.write_u64(0);
        arguments.write_u32(declared);
        arguments.write_u32(0);
        arguments.write_opaque(data).unwrap();
        let outcome = client.call(NFS_PROGRAM, NFS_VERSION, 7, &arguments.into_bytes()).await;
        if data.len() > 16 {
            let payload = nfs_payload(outcome);
            let mut decoder = Decoder::new(&payload);
            assert_eq!(decoder.read_u32().unwrap(), 0);
            let _ = support::rpc::decode_wcc(&mut decoder);
            assert_eq!(decoder.read_u32().unwrap(), 16);
        } else {
            let payload = nfs_payload(outcome);
            assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 22);
        }
    }
    assert_eq!(vfs.call_count("write"), 1);
    assert_eq!(vfs.last_write().unwrap().data, b"1234567890123456");

    server.shutdown().await;
}

#[tokio::test]
async fn readdir_and_readdirplus_size_sweep_never_exceeds_client_limit() {
    let mut limits = ServerLimits::production_defaults();
    limits.max_readdir_response_size = 512;
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server_with(vfs, limits, AuthPolicy::AuthSys, PortmapperMode::Disabled).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;

    let directory_payload = nfs_payload(
        client
            .call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(&root, b"dir"))
            .await,
    );
    let mut decoder = Decoder::new(&directory_payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let directory = decoder.read_opaque("directory handle", 64).unwrap();

    for procedure in [16, 17] {
        let mut arguments = Encoder::new();
        arguments.write_opaque(&directory).unwrap();
        arguments.write_u64(0);
        arguments.write_fixed(&[0; 8]);
        if procedure == 17 {
            arguments.write_u32(0);
        }
        arguments.write_u32(20);
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, procedure, &arguments.into_bytes()).await);
        assert_eq!(payload.len(), 24);
        let mut decoder = Decoder::new(&payload);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert!(!decoder.read_bool().unwrap());
        assert_eq!(decoder.read_fixed::<8>().unwrap(), [9; 8]);
        assert!(!decoder.read_bool().unwrap());
        assert!(decoder.read_bool().unwrap());
        decoder.finish().unwrap();
    }

    for count in (16..=640).step_by(8) {
        let mut arguments = Encoder::new();
        arguments.write_opaque(&root).unwrap();
        arguments.write_u64(0);
        arguments.write_fixed(&[0; 8]);
        arguments.write_u32(count);
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 16, &arguments.into_bytes()).await);
        let status = u32::from_be_bytes(payload[..4].try_into().unwrap());
        if status == 0 {
            assert!(
                payload.len() - 4 <= count.min(512) as usize,
                "READDIR count {count} returned {} result-arm bytes",
                payload.len() - 4
            );
        } else {
            assert_eq!(status, 10005);
        }

        let mut plus = Encoder::new();
        plus.write_opaque(&root).unwrap();
        plus.write_u64(0);
        plus.write_fixed(&[0; 8]);
        plus.write_u32(count);
        plus.write_u32(count);
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 17, &plus.into_bytes()).await);
        let status = u32::from_be_bytes(payload[..4].try_into().unwrap());
        if status == 0 {
            assert!(
                payload.len() - 4 <= count.min(512) as usize,
                "READDIRPLUS count {count} returned {} result-arm bytes",
                payload.len() - 4
            );
        } else {
            assert_eq!(status, 10005);
        }
    }

    server.shutdown().await;
}

#[tokio::test]
async fn every_single_byte_handle_mutation_is_rejected_before_backend() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let handle = mount_root(&mut client, b"/").await;
    let baseline = vfs.call_count("getattr");

    for index in 0..handle.len() {
        let mut forged = handle.clone();
        forged[index] ^= 0x80;
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&forged)).await);
        assert_ne!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 0, "mutated byte {index} was accepted");
    }
    assert_eq!(vfs.call_count("getattr"), baseline);

    server.shutdown().await;
}
