mod support;

use std::sync::Arc;

use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::server::{AuthPolicy, ServerLimits};
use nfsembed::vfs::{ExportId, NfsError, Principal};
use support::rpc::{
    assert_nfs_status, encode_empty_set_attributes, mount_root, nfs_args_directory, nfs_args_handle, nfs_payload,
    start_server, start_server_with, Auth, RpcClient, RpcOutcome, MOUNT_PROGRAM, NFS_PROGRAM, NFS_VERSION,
};
use support::vfs::ConformanceVfs;

async fn lookup_handle(client: &mut RpcClient, root: &[u8], name: &[u8]) -> Vec<u8> {
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(root, name)).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    decoder.read_opaque("lookup handle", 64).unwrap()
}

fn valid_arguments(procedure: u32, root: &[u8], file: &[u8], link: &[u8], directory: &[u8]) -> Vec<u8> {
    match procedure {
        0 => Vec::new(),
        1 | 18 | 19 | 20 => nfs_args_handle(root),
        2 => {
            let mut out = Encoder::new();
            out.write_opaque(file).unwrap();
            encode_empty_set_attributes(&mut out);
            out.write_bool(false);
            out.into_bytes()
        },
        3 => nfs_args_directory(root, b"file"),
        4 => {
            let mut out = Encoder::new();
            out.write_opaque(file).unwrap();
            out.write_u32(0x3f);
            out.into_bytes()
        },
        5 => nfs_args_handle(link),
        6 => {
            let mut out = Encoder::new();
            out.write_opaque(file).unwrap();
            out.write_u64(0);
            out.write_u32(4);
            out.into_bytes()
        },
        7 => {
            let mut out = Encoder::new();
            out.write_opaque(file).unwrap();
            out.write_u64(0);
            out.write_u32(4);
            out.write_u32(2);
            out.write_opaque(b"data").unwrap();
            out.into_bytes()
        },
        8 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_opaque(b"new").unwrap();
            out.write_u32(0);
            encode_empty_set_attributes(&mut out);
            out.into_bytes()
        },
        9 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_opaque(b"newdir").unwrap();
            encode_empty_set_attributes(&mut out);
            out.into_bytes()
        },
        10 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_opaque(b"newlink").unwrap();
            encode_empty_set_attributes(&mut out);
            out.write_opaque(b"target").unwrap();
            out.into_bytes()
        },
        11 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_opaque(b"fifo").unwrap();
            out.write_u32(7);
            encode_empty_set_attributes(&mut out);
            out.into_bytes()
        },
        12 => nfs_args_directory(root, b"file"),
        13 => nfs_args_directory(root, b"dir"),
        14 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_opaque(b"old").unwrap();
            out.write_opaque(directory).unwrap();
            out.write_opaque(b"new").unwrap();
            out.into_bytes()
        },
        15 => {
            let mut out = Encoder::new();
            out.write_opaque(file).unwrap();
            out.write_opaque(root).unwrap();
            out.write_opaque(b"hardlink").unwrap();
            out.into_bytes()
        },
        16 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_u64(0);
            out.write_fixed(&[0; 8]);
            out.write_u32(4096);
            out.into_bytes()
        },
        17 => {
            let mut out = Encoder::new();
            out.write_opaque(root).unwrap();
            out.write_u64(0);
            out.write_fixed(&[0; 8]);
            out.write_u32(4096);
            out.write_u32(4096);
            out.into_bytes()
        },
        21 => {
            let mut out = Encoder::new();
            out.write_opaque(file).unwrap();
            out.write_u64(0);
            out.write_u32(4);
            out.into_bytes()
        },
        _ => panic!("no valid arguments for procedure {procedure}"),
    }
}

#[tokio::test]
async fn every_nfs_result_union_has_a_well_formed_failure_arm() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;
    let link = lookup_handle(&mut client, &root, b"link").await;
    let directory = lookup_handle(&mut client, &root, b"dir").await;

    let failures = [
        (1, "getattr", 4),
        (2, "setattr", 12),
        (3, "lookup", 92),
        (4, "access", 92),
        (5, "readlink", 92),
        (6, "read", 8),
        (7, "write", 12),
        (8, "create", 12),
        (9, "mkdir", 12),
        (10, "symlink", 12),
        (11, "mknod", 12),
        (12, "remove", 12),
        (13, "rmdir", 12),
        (14, "rename", 20),
        (15, "link", 16),
        (16, "readdir", 8),
        (17, "readdir", 8),
        (18, "fsstat", 8),
        (19, "fsinfo", 8),
        (20, "pathconf", 8),
        (21, "commit", 12),
    ];
    for (procedure, operation, expected_length) in failures {
        vfs.fail(operation, NfsError::Access);
        let arguments = valid_arguments(procedure, &root, &file, &link, &directory);
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, procedure, &arguments).await);
        assert_eq!(payload.len(), expected_length, "procedure {procedure} failure length");
        let mut decoder = Decoder::new(&payload);
        assert_eq!(decoder.read_u32().unwrap(), 13, "procedure {procedure} failure status");
        vfs.clear_failure(operation);
    }

    let arguments = valid_arguments(11, &root, &file, &link, &directory);
    vfs.fail("mknod", NfsError::NotSupported);
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 11, &arguments).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 10004);

    server.shutdown().await;
}

#[tokio::test]
async fn every_public_backend_error_and_device_number_crosses_tcp_exactly() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;

    for (error, status) in [
        (NfsError::Permission, 1),
        (NfsError::NotFound, 2),
        (NfsError::Io, 5),
        (NfsError::NoDeviceOrAddress, 6),
        (NfsError::Access, 13),
        (NfsError::Exists, 17),
        (NfsError::CrossDevice, 18),
        (NfsError::NoDevice, 19),
        (NfsError::NotDirectory, 20),
        (NfsError::IsDirectory, 21),
        (NfsError::Invalid, 22),
        (NfsError::FileTooLarge, 27),
        (NfsError::NoSpace, 28),
        (NfsError::ReadOnly, 30),
        (NfsError::TooManyLinks, 31),
        (NfsError::NameTooLong, 63),
        (NfsError::NotEmpty, 66),
        (NfsError::Quota, 69),
        (NfsError::Stale, 70),
        (NfsError::Remote, 71),
        (NfsError::NotSynchronized, 10002),
        (NfsError::BadCookie, 10003),
        (NfsError::NotSupported, 10004),
        (NfsError::TooSmall, 10005),
        (NfsError::ServerFault, 10006),
        (NfsError::BadType, 10007),
        (NfsError::Jukebox, 10008),
    ] {
        vfs.fail("getattr", error);
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root)).await);
        assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), status);
        vfs.clear_failure("getattr");
    }

    let device = lookup_handle(&mut client, &root, b"device").await;
    let payload = assert_nfs_status(client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&device)).await, 0);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let attributes = support::rpc::decode_attributes(&mut decoder);
    assert_eq!((attributes.rdev_major, attributes.rdev_minor), (12, 34));
    decoder.finish().unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn unsupported_rpc_call_verifiers_are_rejected() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs).await;
    let mut client = RpcClient::connect(server.address).await;
    for (flavor, body) in [(1, b"bad".as_slice()), (0, b"nonempty".as_slice())] {
        match client
            .call_with_verifier(970 + flavor, NFS_PROGRAM, NFS_VERSION, 0, &[], flavor, body)
            .await
        {
            RpcOutcome::Denied {
                reject_status: 1,
                details,
                ..
            } => assert_eq!(details, 3u32.to_be_bytes()),
            other => panic!("invalid verifier was accepted: {other:?}"),
        }
    }
    server.shutdown().await;
}

#[tokio::test]
async fn every_nfs_procedure_rejects_truncation_and_trailing_fields_at_rpc_layer() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;
    let link = lookup_handle(&mut client, &root, b"link").await;
    let directory = lookup_handle(&mut client, &root, b"dir").await;

    for procedure in 0..=21 {
        let outcome = client.call(NFS_PROGRAM, NFS_VERSION, procedure, &[0, 0, 0]).await;
        match outcome {
            RpcOutcome::Accepted { status: 4, payload, .. } => assert!(payload.is_empty()),
            other => panic!("procedure {procedure} accepted a truncated request: {other:?}"),
        }

        let mut trailing = valid_arguments(procedure, &root, &file, &link, &directory);
        trailing.extend_from_slice(&0u32.to_be_bytes());
        let outcome = client.call(NFS_PROGRAM, NFS_VERSION, procedure, &trailing).await;
        match outcome {
            RpcOutcome::Accepted { status: 4, payload, .. } => assert!(payload.is_empty()),
            other => panic!("procedure {procedure} accepted trailing fields: {other:?}"),
        }
    }

    server.shutdown().await;
}

#[tokio::test]
async fn invalid_discriminants_and_field_limits_are_rejected_without_backend_calls() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    let mut forged = file.clone();
    forged[10] ^= 0x80;
    assert!(matches!(
        client.call(NFS_PROGRAM, NFS_VERSION, 7, &nfs_args_handle(&forged)).await,
        RpcOutcome::Accepted { status: 4, .. }
    ));
    let mut forged_with_trailing = Encoder::new();
    forged_with_trailing.write_opaque(&forged).unwrap();
    forged_with_trailing.write_u64(0);
    forged_with_trailing.write_u32(0);
    forged_with_trailing.write_u32(0);
    forged_with_trailing.write_opaque(&[]).unwrap();
    forged_with_trailing.write_u32(0xfeed_beef);
    assert!(matches!(
        client
            .call(NFS_PROGRAM, NFS_VERSION, 7, &forged_with_trailing.into_bytes())
            .await,
        RpcOutcome::Accepted { status: 4, .. }
    ));
    assert_eq!(vfs.call_count("write"), 0);

    let mut invalid_bool = Encoder::new();
    invalid_bool.write_opaque(&file).unwrap();
    invalid_bool.write_u32(2);
    assert!(matches!(
        client.call(NFS_PROGRAM, NFS_VERSION, 2, &invalid_bool.into_bytes()).await,
        RpcOutcome::Accepted { status: 4, .. }
    ));

    let mut invalid_stability = Encoder::new();
    invalid_stability.write_opaque(&file).unwrap();
    invalid_stability.write_u64(0);
    invalid_stability.write_u32(0);
    invalid_stability.write_u32(3);
    assert!(matches!(
        client.call(NFS_PROGRAM, NFS_VERSION, 7, &invalid_stability.into_bytes()).await,
        RpcOutcome::Accepted { status: 4, .. }
    ));

    let mut invalid_create = Encoder::new();
    invalid_create.write_opaque(&root).unwrap();
    invalid_create.write_opaque(b"new").unwrap();
    invalid_create.write_u32(3);
    assert!(matches!(
        client.call(NFS_PROGRAM, NFS_VERSION, 8, &invalid_create.into_bytes()).await,
        RpcOutcome::Accepted { status: 4, .. }
    ));

    let long_name = vec![b'x'; 256];
    let payload = nfs_payload(
        client
            .call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(&root, &long_name))
            .await,
    );
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 63);

    let long_handle = vec![0; 65];
    assert!(matches!(
        client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&long_handle)).await,
        RpcOutcome::Accepted { status: 4, .. }
    ));

    assert_eq!(vfs.call_count("setattr"), 0);
    assert_eq!(vfs.call_count("write"), 0);
    assert_eq!(vfs.call_count("create"), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn rpc_version_program_version_and_procedure_mismatches_encode_ranges() {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs).await;
    let mut client = RpcClient::connect(server.address).await;

    let denied = client.call_with_rpc_version(77, 99, NFS_PROGRAM, NFS_VERSION, 0, &[]).await;
    match denied {
        RpcOutcome::Denied {
            xid: 77,
            reject_status: 0,
            details,
        } => assert_eq!(details, [2u32.to_be_bytes(), 2u32.to_be_bytes()].concat()),
        other => panic!("unexpected RPC mismatch reply: {other:?}"),
    }

    let (status, payload) = client.call(999_999, 1, 0, &[]).await.accepted();
    assert_eq!(status, 1);
    assert!(payload.is_empty());

    let (status, payload) = client.call(NFS_PROGRAM, 99, 0, &[]).await.accepted();
    assert_eq!(status, 2);
    assert_eq!(payload, [NFS_VERSION.to_be_bytes(), NFS_VERSION.to_be_bytes()].concat());

    let (status, payload) = client.call(NFS_PROGRAM, NFS_VERSION, 99, &[]).await.accepted();
    assert_eq!(status, 3);
    assert!(payload.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn auth_policies_parse_auth_sys_reject_wrong_flavors_and_support_anonymous() {
    let sys_vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let sys_server = start_server(sys_vfs.clone()).await;
    let mut sys_client = RpcClient::connect(sys_server.address).await;
    let mut oversized_auth = Encoder::new();
    oversized_auth.write_u32(0);
    oversized_auth.write_opaque(b"machine").unwrap();
    oversized_auth.write_u32(1);
    oversized_auth.write_u32(1);
    oversized_auth.write_u32(17);
    for _ in 0..17 {
        oversized_auth.write_u32(1);
    }
    sys_client.set_auth(Auth::Raw {
        flavor: 1,
        body: oversized_auth.into_bytes(),
    });
    assert!(matches!(
        sys_client.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await,
        RpcOutcome::Denied { reject_status: 1, .. }
    ));
    sys_client.set_auth(Auth::Raw {
        flavor: 99,
        body: Vec::new(),
    });
    assert!(matches!(
        sys_client.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await,
        RpcOutcome::Denied { reject_status: 1, .. }
    ));
    sys_client.set_auth(Auth::None);
    match sys_client.call(MOUNT_PROGRAM, 3, 0, &[]).await {
        RpcOutcome::Denied {
            reject_status: 1,
            details,
            ..
        } => assert_eq!(details, 5u32.to_be_bytes()),
        other => panic!("AUTH_NONE was not rejected: {other:?}"),
    }
    sys_client.set_auth(Auth::Sys);
    let root = mount_root(&mut sys_client, b"/").await;
    let _ = assert_nfs_status(sys_client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root)).await, 0);
    let context = sys_vfs.last_context("getattr").unwrap();
    support::vfs::assert_auth_sys(&context.principal);
    sys_server.shutdown().await;

    let anonymous_vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let anonymous_server =
        start_server_with(anonymous_vfs.clone(), ServerLimits::production_defaults(), AuthPolicy::Anonymous).await;
    let mut anonymous_client = RpcClient::connect(anonymous_server.address).await;
    anonymous_client.set_auth(Auth::None);
    let root = mount_root(&mut anonymous_client, b"/").await;
    let _ = assert_nfs_status(
        anonymous_client
            .call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root))
            .await,
        0,
    );
    assert_eq!(anonymous_vfs.last_context("getattr").unwrap().principal, Principal::Anonymous);
    anonymous_server.shutdown().await;
}
