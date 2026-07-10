mod support;

use std::sync::Arc;

use nfsserve::rpc::codec::{Decoder, Encoder};
use nfsserve::vfs::{
    CreateMode, ExportId, NfsTime, NodeType, Principal, SetTime, WriteResult as VfsWriteResult, WriteStability,
};

use support::rpc::{
    assert_nfs_status, decode_attributes, decode_post_attributes, decode_wcc, encode_empty_set_attributes, mount_root,
    nfs_args_directory, nfs_args_handle, nfs_payload, start_server, RpcClient, MOUNT_PROGRAM, MOUNT_VERSION,
    NFS_PROGRAM, NFS_VERSION,
};
use support::vfs::{assert_auth_sys, ConformanceVfs};

async fn setup() -> (Arc<ConformanceVfs>, support::rpc::RunningServer, RpcClient, Vec<u8>) {
    let vfs = Arc::new(ConformanceVfs::new(ExportId(1)));
    let server = start_server(vfs.clone()).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    (vfs, server, client, root)
}

async fn lookup_handle(client: &mut RpcClient, directory: &[u8], name: &[u8]) -> Vec<u8> {
    let payload = nfs_payload(
        client
            .call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(directory, name))
            .await,
    );
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let handle = decoder.read_opaque("lookup handle", 64).unwrap();
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert!(decode_post_attributes(&mut decoder).is_some());
    decoder.finish().unwrap();
    handle
}

fn encode_setattr(handle: &[u8]) -> Vec<u8> {
    encode_setattr_with_guard(
        handle,
        NfsTime {
            seconds: 14,
            nanoseconds: 15,
        },
    )
}

fn encode_setattr_with_guard(handle: &[u8], guard: NfsTime) -> Vec<u8> {
    let mut arguments = Encoder::new();
    arguments.write_opaque(handle).unwrap();
    arguments.write_bool(true);
    arguments.write_u32(0o600);
    arguments.write_bool(true);
    arguments.write_u32(2000);
    arguments.write_bool(false);
    arguments.write_bool(true);
    arguments.write_u64(5);
    arguments.write_u32(2);
    arguments.write_u32(100);
    arguments.write_u32(200);
    arguments.write_u32(1);
    arguments.write_bool(true);
    arguments.write_u32(guard.seconds as u32);
    arguments.write_u32(guard.nanoseconds);
    arguments.into_bytes()
}

fn encode_create(handle: &[u8], name: &[u8], mode: CreateMode) -> Vec<u8> {
    let mut arguments = Encoder::new();
    arguments.write_opaque(handle).unwrap();
    arguments.write_opaque(name).unwrap();
    match mode {
        CreateMode::Unchecked => {
            arguments.write_u32(0);
            encode_empty_set_attributes(&mut arguments);
        },
        CreateMode::Guarded => {
            arguments.write_u32(1);
            encode_empty_set_attributes(&mut arguments);
        },
        CreateMode::Exclusive { verifier } => {
            arguments.write_u32(2);
            arguments.write_fixed(&verifier);
        },
    }
    arguments.into_bytes()
}

fn decode_created(payload: &[u8], expected_length: usize) -> Vec<u8> {
    assert_eq!(payload.len(), expected_length);
    let mut decoder = Decoder::new(payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decoder.read_bool().unwrap());
    let handle = decoder.read_opaque("created handle", 64).unwrap();
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    decoder.finish().unwrap();
    handle
}

#[tokio::test]
async fn wave1_read_only_procedures_are_wire_correct_and_receive_identity() {
    let (vfs, server, mut client, root) = setup().await;

    let (rpc_status, null_payload) = client.call(NFS_PROGRAM, NFS_VERSION, 0, &[]).await.accepted();
    assert_eq!(rpc_status, 0);
    assert!(null_payload.is_empty());

    let getattr = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 1, &nfs_args_handle(&root)).await);
    assert_eq!(getattr.len(), 88);
    let mut decoder = Decoder::new(&getattr);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let attributes = decode_attributes(&mut decoder);
    assert_eq!(attributes.file_type, 2);
    assert_eq!(attributes.file_id, 1);
    decoder.finish().unwrap();

    let lookup = nfs_payload(
        client
            .call(NFS_PROGRAM, NFS_VERSION, 3, &nfs_args_directory(&root, b"file"))
            .await,
    );
    assert_eq!(lookup.len(), 232);
    let mut decoder = Decoder::new(&lookup);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let file = decoder.read_opaque("file handle", 64).unwrap();
    assert_eq!(decode_post_attributes(&mut decoder).unwrap().file_id, 2);
    assert_eq!(decode_post_attributes(&mut decoder).unwrap().file_id, 1);
    decoder.finish().unwrap();

    let mut access_args = Encoder::new();
    access_args.write_opaque(&file).unwrap();
    access_args.write_u32(u32::MAX);
    let access = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 4, &access_args.into_bytes()).await);
    assert_eq!(access.len(), 96);
    let mut decoder = Decoder::new(&access);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u32().unwrap(), 0x15);
    decoder.finish().unwrap();
    assert_eq!(vfs.last_access(), Some(0x3f));

    let link = lookup_handle(&mut client, &root, b"link").await;
    let readlink = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 5, &nfs_args_handle(&link)).await);
    assert_eq!(readlink.len(), 108);
    let mut decoder = Decoder::new(&readlink);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decode_post_attributes(&mut decoder).unwrap().file_type, 5);
    assert_eq!(decoder.read_opaque("link target", 1024).unwrap(), b"target/path");
    decoder.finish().unwrap();

    let mut read_args = Encoder::new();
    read_args.write_opaque(&file).unwrap();
    read_args.write_u64(6);
    read_args.write_u32(5);
    let read = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 6, &read_args.into_bytes()).await);
    assert_eq!(read.len(), 112);
    let mut decoder = Decoder::new(&read);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u32().unwrap(), 5);
    assert!(decoder.read_bool().unwrap());
    assert_eq!(decoder.read_opaque("read data", 1024).unwrap(), b"world");
    decoder.finish().unwrap();

    let context = vfs.last_context("read").unwrap();
    assert_auth_sys(&context.principal);
    assert_eq!(context.export_id, ExportId(1));
    assert_eq!(context.client_addr.ip(), server.address.ip());

    server.shutdown().await;
}

#[tokio::test]
async fn wave2_information_and_directory_procedures_are_exact_and_paginate() {
    let (vfs, server, mut client, root) = setup().await;

    let fsstat = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 18, &nfs_args_handle(&root)).await);
    assert_eq!(fsstat.len(), 144);
    let mut decoder = Decoder::new(&fsstat);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u64().unwrap(), 1_000_000);
    assert_eq!(decoder.read_u64().unwrap(), 500_000);
    assert_eq!(decoder.read_u64().unwrap(), 400_000);
    assert_eq!(decoder.read_u64().unwrap(), 10_000);
    assert_eq!(decoder.read_u64().unwrap(), 5_000);
    assert_eq!(decoder.read_u64().unwrap(), 4_000);
    assert_eq!(decoder.read_u32().unwrap(), 30);
    decoder.finish().unwrap();

    let fsinfo = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 19, &nfs_args_handle(&root)).await);
    assert_eq!(fsinfo.len(), 140);
    let mut decoder = Decoder::new(&fsinfo);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u32().unwrap(), 64 * 1024);
    assert_eq!(decoder.read_u32().unwrap(), 32 * 1024);
    assert_eq!(decoder.read_u32().unwrap(), 4096);
    assert_eq!(decoder.read_u32().unwrap(), 64 * 1024);
    assert_eq!(decoder.read_u32().unwrap(), 32 * 1024);
    assert_eq!(decoder.read_u32().unwrap(), 4096);
    assert_eq!(decoder.read_u32().unwrap(), 16 * 1024);
    assert_eq!(decoder.read_u64().unwrap(), 1 << 40);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decoder.read_u32().unwrap(), 1_000);
    assert_eq!(decoder.read_u32().unwrap(), 0x1b);
    decoder.finish().unwrap();

    let pathconf = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 20, &nfs_args_handle(&root)).await);
    assert_eq!(pathconf.len(), 116);
    let mut decoder = Decoder::new(&pathconf);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_u32().unwrap(), 32000);
    assert_eq!(decoder.read_u32().unwrap(), 255);
    assert!(decoder.read_bool().unwrap());
    assert!(decoder.read_bool().unwrap());
    assert!(!decoder.read_bool().unwrap());
    assert!(decoder.read_bool().unwrap());
    decoder.finish().unwrap();

    let mut readdir_args = Encoder::new();
    readdir_args.write_opaque(&root).unwrap();
    readdir_args.write_u64(0);
    readdir_args.write_fixed(&[0; 8]);
    readdir_args.write_u32(4096);
    let readdir = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 16, &readdir_args.into_bytes()).await);
    assert_eq!(readdir.len(), 192);
    let mut decoder = Decoder::new(&readdir);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_fixed::<8>().unwrap(), [9; 8]);
    let mut names = Vec::new();
    while decoder.read_bool().unwrap() {
        let _file_id = decoder.read_u64().unwrap();
        names.push(decoder.read_opaque("entry name", 255).unwrap());
        let _cookie = decoder.read_u64().unwrap();
    }
    assert!(decoder.read_bool().unwrap());
    decoder.finish().unwrap();
    assert_eq!(names, vec![b"file".to_vec(), b"link".to_vec(), b"dir".to_vec()]);

    let mut plus_args = Encoder::new();
    plus_args.write_opaque(&root).unwrap();
    plus_args.write_u64(1);
    plus_args.write_fixed(&[9; 8]);
    plus_args.write_u32(4096);
    plus_args.write_u32(4096);
    let plus = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 17, &plus_args.into_bytes()).await);
    assert_eq!(plus.len(), 452);
    let mut decoder = Decoder::new(&plus);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_fixed::<8>().unwrap(), [9; 8]);
    let mut plus_names = Vec::new();
    while decoder.read_bool().unwrap() {
        let _file_id = decoder.read_u64().unwrap();
        plus_names.push(decoder.read_opaque("entry name", 255).unwrap());
        let _cookie = decoder.read_u64().unwrap();
        assert!(decode_post_attributes(&mut decoder).is_some());
        assert!(decoder.read_bool().unwrap());
        assert_eq!(decoder.read_opaque("entry handle", 64).unwrap().len(), 45);
    }
    assert!(decoder.read_bool().unwrap());
    decoder.finish().unwrap();
    assert_eq!(plus_names, vec![b"link".to_vec(), b"dir".to_vec()]);
    assert_eq!(vfs.last_readdir().unwrap().0, 1);

    let mut bad_cookie = Encoder::new();
    bad_cookie.write_opaque(&root).unwrap();
    bad_cookie.write_u64(1);
    bad_cookie.write_fixed(&[7; 8]);
    bad_cookie.write_u32(4096);
    let payload = assert_nfs_status(client.call(NFS_PROGRAM, NFS_VERSION, 16, &bad_cookie.into_bytes()).await, 10003);
    assert_eq!(payload.len(), 8);

    server.shutdown().await;
}

#[tokio::test]
async fn fsinfo_properties_come_from_backend_capabilities() {
    let vfs = Arc::new(ConformanceVfs::read_only(ExportId(1)));
    let server = start_server(vfs).await;
    let mut client = RpcClient::connect(server.address).await;
    let root = mount_root(&mut client, b"/").await;
    let payload = assert_nfs_status(client.call(NFS_PROGRAM, NFS_VERSION, 19, &nfs_args_handle(&root)).await, 0);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    for _ in 0..7 {
        let _ = decoder.read_u32().unwrap();
    }
    let _max_file_size = decoder.read_u64().unwrap();
    let _time_seconds = decoder.read_u32().unwrap();
    let _time_nanoseconds = decoder.read_u32().unwrap();
    let properties = decoder.read_u32().unwrap();
    assert_eq!(properties & 0x0008, 0x0008);
    assert_eq!(properties & 0x0010, 0, "read-only backend advertised CANSETTIME");
    decoder.finish().unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn readdir_cookie_walk_reconstructs_a_multi_page_directory_without_duplicates() {
    let (_vfs, server, mut client, root) = setup().await;
    let mut cookie = 0;
    let mut verifier = [0; 8];
    let mut names = Vec::new();

    let mut reached_eof = false;
    for _ in 0..10 {
        let mut arguments = Encoder::new();
        arguments.write_opaque(&root).unwrap();
        arguments.write_u64(cookie);
        arguments.write_fixed(&verifier);
        arguments.write_u32(136);
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 16, &arguments.into_bytes()).await);
        assert!(payload.len() <= 136);
        let mut decoder = Decoder::new(&payload);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert!(decode_post_attributes(&mut decoder).is_some());
        verifier = decoder.read_fixed().unwrap();
        while decoder.read_bool().unwrap() {
            let _file_id = decoder.read_u64().unwrap();
            names.push(decoder.read_opaque("entry", 255).unwrap());
            cookie = decoder.read_u64().unwrap();
        }
        let eof = decoder.read_bool().unwrap();
        decoder.finish().unwrap();
        if eof {
            reached_eof = true;
            break;
        }
    }

    assert!(reached_eof, "directory pagination did not terminate");
    assert_eq!(names, vec![b"file".to_vec(), b"link".to_vec(), b"dir".to_vec()]);
    server.shutdown().await;
}

#[tokio::test]
async fn wave3_mutations_return_atomic_wcc_and_preserve_create_modes() {
    let (vfs, server, mut client, root) = setup().await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    let mismatched = nfs_payload(
        client
            .call(
                NFS_PROGRAM,
                NFS_VERSION,
                2,
                &encode_setattr_with_guard(
                    &file,
                    NfsTime {
                        seconds: 99,
                        nanoseconds: 0,
                    },
                ),
            )
            .await,
    );
    assert_eq!(u32::from_be_bytes(mismatched[..4].try_into().unwrap()), 10002);

    let setattr = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 2, &encode_setattr(&file)).await);
    assert_eq!(setattr.len(), 120);
    let mut decoder = Decoder::new(&setattr);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    decoder.finish().unwrap();

    for (index, mode) in [
        CreateMode::Unchecked,
        CreateMode::Guarded,
        CreateMode::Exclusive { verifier: [5; 8] },
    ]
    .into_iter()
    .enumerate()
    {
        let payload = nfs_payload(
            client
                .call(NFS_PROGRAM, NFS_VERSION, 8, &encode_create(&root, format!("new{index}").as_bytes(), mode))
                .await,
        );
        let _created = decode_created(&payload, 264);
        assert_eq!(vfs.last_create_mode(), Some(mode));
    }

    let mut mkdir_args = Encoder::new();
    mkdir_args.write_opaque(&root).unwrap();
    mkdir_args.write_opaque(b"newdir").unwrap();
    encode_empty_set_attributes(&mut mkdir_args);
    let mkdir = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 9, &mkdir_args.into_bytes()).await);
    let _directory = decode_created(&mkdir, 264);

    let mut symlink_args = Encoder::new();
    symlink_args.write_opaque(&root).unwrap();
    symlink_args.write_opaque(b"newlink").unwrap();
    encode_empty_set_attributes(&mut symlink_args);
    symlink_args.write_opaque(b"destination").unwrap();
    let symlink = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 10, &symlink_args.into_bytes()).await);
    let _symlink = decode_created(&symlink, 264);

    for (procedure, name) in [(12, b"file".as_slice()), (13, b"dir".as_slice())] {
        let payload = nfs_payload(
            client
                .call(NFS_PROGRAM, NFS_VERSION, procedure, &nfs_args_directory(&root, name))
                .await,
        );
        assert_eq!(payload.len(), 120);
        let mut decoder = Decoder::new(&payload);
        assert_eq!(decoder.read_u32().unwrap(), 0);
        assert_eq!(decode_wcc(&mut decoder), (true, true));
        decoder.finish().unwrap();
    }

    let directory = lookup_handle(&mut client, &root, b"dir").await;
    let mut rename_args = Encoder::new();
    rename_args.write_opaque(&root).unwrap();
    rename_args.write_opaque(b"old").unwrap();
    rename_args.write_opaque(&directory).unwrap();
    rename_args.write_opaque(b"new").unwrap();
    let rename = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 14, &rename_args.into_bytes()).await);
    assert_eq!(rename.len(), 236);
    let mut decoder = Decoder::new(&rename);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    decoder.finish().unwrap();

    let context = vfs.last_context("setattr").unwrap();
    assert_auth_sys(&context.principal);
    assert_eq!(context.export_id, ExportId(1));

    server.shutdown().await;
}

#[tokio::test]
async fn nfspath_values_are_bounded_by_transport_capacity_not_name_max() {
    let (vfs, server, mut client, root) = setup().await;
    let long_target = vec![b'x'; 4096];

    let mut symlink_args = Encoder::new();
    symlink_args.write_opaque(&root).unwrap();
    symlink_args.write_opaque(b"longlink").unwrap();
    encode_empty_set_attributes(&mut symlink_args);
    symlink_args.write_opaque(&long_target).unwrap();
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 10, &symlink_args.into_bytes()).await);
    assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 0);
    assert_eq!(vfs.last_symlink_target(), Some(long_target.clone()));

    vfs.set_readlink_target(long_target.clone());
    let link = lookup_handle(&mut client, &root, b"link").await;
    let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 5, &nfs_args_handle(&link)).await);
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decoder.read_opaque("long symlink target", 8192).unwrap(), long_target);
    decoder.finish().unwrap();

    server.shutdown().await;
}

#[tokio::test]
async fn wave4_write_commit_link_and_mknod_are_complete() {
    let (vfs, server, mut client, root) = setup().await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    let mut write_args = Encoder::new();
    write_args.write_opaque(&file).unwrap();
    write_args.write_u64(7);
    write_args.write_u32(4);
    write_args.write_u32(0);
    write_args.write_opaque(b"data").unwrap();
    let write = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 7, &write_args.into_bytes()).await);
    assert_eq!(write.len(), 136);
    let mut decoder = Decoder::new(&write);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    assert_eq!(decoder.read_u32().unwrap(), 4);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    let write_verifier = decoder.read_fixed::<8>().unwrap();
    decoder.finish().unwrap();
    assert_eq!(
        vfs.last_write().unwrap(),
        support::vfs::WriteObservation {
            object: support::vfs::FILE,
            offset: 7,
            data: b"data".to_vec(),
            requested: WriteStability::Unstable,
        }
    );

    let mut commit_args = Encoder::new();
    commit_args.write_opaque(&file).unwrap();
    commit_args.write_u64(7);
    commit_args.write_u32(4);
    let commit = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 21, &commit_args.into_bytes()).await);
    assert_eq!(commit.len(), 128);
    let mut decoder = Decoder::new(&commit);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    assert_eq!(decoder.read_fixed::<8>().unwrap(), write_verifier);
    decoder.finish().unwrap();

    let mut link_args = Encoder::new();
    link_args.write_opaque(&file).unwrap();
    link_args.write_opaque(&root).unwrap();
    link_args.write_opaque(b"hardlink").unwrap();
    let link = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 15, &link_args.into_bytes()).await);
    assert_eq!(link.len(), 208);
    let mut decoder = Decoder::new(&link);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decode_post_attributes(&mut decoder).is_some());
    assert_eq!(decode_wcc(&mut decoder), (true, true));
    decoder.finish().unwrap();

    let mut mknod_args = Encoder::new();
    mknod_args.write_opaque(&root).unwrap();
    mknod_args.write_opaque(b"block-device").unwrap();
    mknod_args.write_u32(3);
    encode_empty_set_attributes(&mut mknod_args);
    mknod_args.write_u32(0x1234_5678);
    mknod_args.write_u32(0x9abc_def0);
    let mknod = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 11, &mknod_args.into_bytes()).await);
    let _node = decode_created(&mknod, 264);
    assert_eq!(
        vfs.last_mknod(),
        Some(NodeType::BlockDevice {
            major: 0x1234_5678,
            minor: 0x9abc_def0,
        })
    );

    assert_eq!(vfs.call_count("write"), 1);
    assert_eq!(vfs.call_count("commit"), 1);
    assert_eq!(vfs.call_count("link"), 1);
    assert_eq!(vfs.call_count("mknod"), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn write_never_claims_weaker_or_impossible_backend_completion() {
    let (vfs, server, mut client, root) = setup().await;
    let file = lookup_handle(&mut client, &root, b"file").await;

    for (requested, backend, backend_count, expected_status) in [
        (WriteStability::Unstable, WriteStability::DataSync, 4, 0),
        (WriteStability::DataSync, WriteStability::DataSync, 4, 0),
        (WriteStability::FileSync, WriteStability::DataSync, 4, 10006),
        (WriteStability::Unstable, WriteStability::Unstable, 0, 10006),
        (WriteStability::Unstable, WriteStability::FileSync, 5, 10006),
    ] {
        vfs.set_write_result(Some(VfsWriteResult {
            count: backend_count,
            committed: backend,
        }));
        let mut arguments = Encoder::new();
        arguments.write_opaque(&file).unwrap();
        arguments.write_u64(0);
        arguments.write_u32(4);
        arguments.write_u32(match requested {
            WriteStability::Unstable => 0,
            WriteStability::DataSync => 1,
            WriteStability::FileSync => 2,
        });
        arguments.write_opaque(b"data").unwrap();
        let payload = nfs_payload(client.call(NFS_PROGRAM, NFS_VERSION, 7, &arguments.into_bytes()).await);
        assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), expected_status);
        if expected_status == 0 {
            let mut decoder = Decoder::new(&payload);
            assert_eq!(decoder.read_u32().unwrap(), 0);
            let _ = decode_wcc(&mut decoder);
            assert_eq!(decoder.read_u32().unwrap(), 4);
            assert_eq!(
                decoder.read_u32().unwrap(),
                match backend {
                    WriteStability::Unstable => 0,
                    WriteStability::DataSync => 1,
                    WriteStability::FileSync => 2,
                }
            );
        }
    }
    vfs.set_write_result(None);
    server.shutdown().await;
}

#[tokio::test]
async fn mount_v3_all_procedures_have_correct_void_and_list_shapes() {
    let (_vfs, server, mut client, _root) = setup().await;

    let (status, payload) = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 0, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty());

    let (status, dump) = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 2, &[]).await.accepted();
    assert_eq!(status, 0);
    let mut decoder = Decoder::new(&dump);
    assert!(decoder.read_bool().unwrap());
    assert!(!decoder.read_opaque("mount host", 255).unwrap().is_empty());
    assert_eq!(decoder.read_opaque("mount path", 1024).unwrap(), b"/");
    assert!(!decoder.read_bool().unwrap());
    decoder.finish().unwrap();

    let (status, exports) = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 5, &[]).await.accepted();
    assert_eq!(status, 0);
    let mut decoder = Decoder::new(&exports);
    assert!(decoder.read_bool().unwrap());
    assert_eq!(decoder.read_opaque("export", 1024).unwrap(), b"/");
    assert!(!decoder.read_bool().unwrap());
    assert!(!decoder.read_bool().unwrap());
    decoder.finish().unwrap();

    let mut unmount = Encoder::new();
    unmount.write_opaque(b"/").unwrap();
    let (status, payload) = client
        .call(MOUNT_PROGRAM, MOUNT_VERSION, 3, &unmount.into_bytes())
        .await
        .accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty(), "UMNT must return void");

    let (status, payload) = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 4, &[]).await.accepted();
    assert_eq!(status, 0);
    assert!(payload.is_empty(), "UMNTALL must return void");

    let (status, dump) = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 2, &[]).await.accepted();
    assert_eq!(status, 0);
    let mut decoder = Decoder::new(&dump);
    assert!(!decoder.read_bool().unwrap());
    decoder.finish().unwrap();

    server.shutdown().await;
}

#[test]
fn public_vfs_types_represent_time_and_identity_semantics() {
    let time = SetTime::ClientTime(NfsTime {
        seconds: 10,
        nanoseconds: 20,
    });
    assert_ne!(time, SetTime::ServerTime);
    let principal = Principal::Anonymous;
    assert_ne!(
        principal,
        Principal::AuthSys {
            uid: 0,
            gid: 0,
            supplementary_gids: Vec::new(),
            machine_name: Vec::new(),
        }
    );
}
