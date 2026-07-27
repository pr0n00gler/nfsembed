#![allow(dead_code)]

use nfsembed::nfs4 as wire;
use nfsembed::rpc::codec::{DecodeError, Decoder, Encoder};

#[path = "support/nfs4.rs"]
mod nfs4;

use nfs4::{
    decode_compound_reply_header, decode_status_only_reply, encode_status_only_reply, CompoundRequest, Nfs4Operation,
    OpaqueAuth, StableHow, StateId, StatusOnlyResult, MAX_COMPOUND_OPERATIONS, NFS4ERR_MINOR_VERS_MISMATCH,
    NFS4ERR_OP_ILLEGAL, NFS4_OK, NFS4_PROC_COMPOUND, NFS4_VERSION, NFS_PROGRAM, OP_GETATTR, OP_GETFH, OP_ILLEGAL,
    OP_LOOKUP, OP_PUTROOTFH, OP_WRITE,
};

#[derive(Debug)]
struct WireCase<T> {
    name: &'static str,
    value: T,
    bytes: Vec<u8>,
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_bool(bytes: &mut Vec<u8>, value: bool) {
    push_u32(bytes, u32::from(value));
}

fn push_opaque(bytes: &mut Vec<u8>, value: &[u8]) {
    push_u32(bytes, u32::try_from(value.len()).unwrap());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

fn push_bitmap(bytes: &mut Vec<u8>, words: &[u32]) {
    push_u32(bytes, u32::try_from(words.len()).unwrap());
    for word in words {
        push_u32(bytes, *word);
    }
}

fn push_state_id(bytes: &mut Vec<u8>, state_id: wire::StateId) {
    push_u32(bytes, state_id.sequence_id);
    bytes.extend_from_slice(&state_id.other);
}

fn push_file_attributes(bytes: &mut Vec<u8>, attributes: &wire::FileAttributes) {
    push_bitmap(bytes, &attributes.mask);
    push_opaque(bytes, &attributes.values);
}

fn push_lock_owner(bytes: &mut Vec<u8>, owner: &wire::LockOwner) {
    push_u64(bytes, owner.client_id);
    push_opaque(bytes, &owner.owner);
}

fn push_lock_denied(bytes: &mut Vec<u8>, denied: &wire::LockDenied) {
    push_u64(bytes, denied.offset);
    push_u64(bytes, denied.length);
    push_u32(bytes, denied.lock_type as u32);
    push_lock_owner(bytes, &denied.owner);
}

fn push_ace(bytes: &mut Vec<u8>, ace: &wire::NfsAce) {
    push_u32(bytes, ace.ace_type);
    push_u32(bytes, ace.flags);
    push_u32(bytes, ace.access_mask);
    push_opaque(bytes, &ace.who);
}

fn push_change_info(bytes: &mut Vec<u8>, change: wire::ChangeInfo) {
    push_bool(bytes, change.atomic);
    push_u64(bytes, change.before);
    push_u64(bytes, change.after);
}

fn encoded_operation(opcode: u32, encode: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, opcode);
    encode(&mut bytes);
    bytes
}

fn encoded_compound_args(tag: &[u8], minor_version: u32, operations: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_opaque(&mut bytes, tag);
    push_u32(&mut bytes, minor_version);
    push_u32(&mut bytes, u32::try_from(operations.len()).unwrap());
    for operation in operations {
        bytes.extend_from_slice(operation);
    }
    bytes
}

fn encoded_compound_res(status: wire::NfsStatus, tag: &[u8], operations: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, status.code());
    push_opaque(&mut bytes, tag);
    push_u32(&mut bytes, u32::try_from(operations.len()).unwrap());
    for operation in operations {
        bytes.extend_from_slice(operation);
    }
    bytes
}

fn encoded_callback_args(tag: &[u8], minor_version: u32, callback_identifier: u32, operations: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_opaque(&mut bytes, tag);
    push_u32(&mut bytes, minor_version);
    push_u32(&mut bytes, callback_identifier);
    push_u32(&mut bytes, u32::try_from(operations.len()).unwrap());
    for operation in operations {
        bytes.extend_from_slice(operation);
    }
    bytes
}

fn sample_state_id() -> wire::StateId {
    wire::StateId {
        sequence_id: 0x0102_0304,
        other: [0xa5; wire::NFS4_OTHER_SIZE],
    }
}

fn sample_file_attributes() -> wire::FileAttributes {
    wire::FileAttributes {
        mask: vec![0x0000_0011, 0x8000_0000],
        values: vec![0xde, 0xad, 0xbe],
    }
}

fn sample_lock_owner() -> wire::LockOwner {
    wire::LockOwner {
        client_id: 0x0102_0304_0506_0708,
        owner: b"lock".to_vec(),
    }
}

fn argument_wire_cases() -> Vec<WireCase<wire::ArgOp>> {
    let state_id = sample_state_id();
    let attributes = sample_file_attributes();
    let lock_owner = sample_lock_owner();
    let file_handle = wire::NfsFileHandle::new(vec![0xfa, 0xce, 0x01]).unwrap();
    let mut cases = Vec::new();

    cases.push(WireCase {
        name: "ACCESS",
        value: wire::ArgOp::Access(wire::AccessArgs { access: 0x35 }),
        bytes: encoded_operation(3, |bytes| push_u32(bytes, 0x35)),
    });
    cases.push(WireCase {
        name: "CLOSE",
        value: wire::ArgOp::Close(wire::CloseArgs {
            sequence_id: 7,
            open_state_id: state_id,
        }),
        bytes: encoded_operation(4, |bytes| {
            push_u32(bytes, 7);
            push_state_id(bytes, state_id);
        }),
    });
    cases.push(WireCase {
        name: "COMMIT",
        value: wire::ArgOp::Commit(wire::CommitArgs {
            offset: 0x0102_0304_0506_0708,
            count: 0x1122_3344,
        }),
        bytes: encoded_operation(5, |bytes| {
            push_u64(bytes, 0x0102_0304_0506_0708);
            push_u32(bytes, 0x1122_3344);
        }),
    });
    cases.push(WireCase {
        name: "CREATE",
        value: wire::ArgOp::Create(wire::CreateArgs {
            object_type: wire::CreateType::Directory,
            name: b"dir".to_vec(),
            attributes: attributes.clone(),
        }),
        bytes: encoded_operation(6, |bytes| {
            push_u32(bytes, wire::NfsFileType::Directory.code());
            push_opaque(bytes, b"dir");
            push_file_attributes(bytes, &attributes);
        }),
    });
    cases.push(WireCase {
        name: "DELEGPURGE",
        value: wire::ArgOp::DelegPurge(wire::DelegPurgeArgs {
            client_id: 0x1112_1314_1516_1718,
        }),
        bytes: encoded_operation(7, |bytes| push_u64(bytes, 0x1112_1314_1516_1718)),
    });
    cases.push(WireCase {
        name: "DELEGRETURN",
        value: wire::ArgOp::DelegReturn(wire::DelegReturnArgs {
            delegation_state_id: state_id,
        }),
        bytes: encoded_operation(8, |bytes| push_state_id(bytes, state_id)),
    });
    cases.push(WireCase {
        name: "GETATTR",
        value: wire::ArgOp::GetAttr(wire::GetAttrArgs {
            requested_attributes: vec![0x0102_0304, 0xa0b0_c0d0],
        }),
        bytes: encoded_operation(9, |bytes| push_bitmap(bytes, &[0x0102_0304, 0xa0b0_c0d0])),
    });
    cases.push(WireCase {
        name: "GETFH",
        value: wire::ArgOp::GetFh,
        bytes: encoded_operation(10, |_| {}),
    });
    cases.push(WireCase {
        name: "LINK",
        value: wire::ArgOp::Link(wire::LinkArgs {
            new_name: b"new".to_vec(),
        }),
        bytes: encoded_operation(11, |bytes| push_opaque(bytes, b"new")),
    });
    cases.push(WireCase {
        name: "LOCK",
        value: wire::ArgOp::Lock(wire::LockArgs {
            lock_type: wire::LockType::BlockingWrite,
            reclaim: true,
            offset: 0x0102_0304_0506_0708,
            length: 0x1112_1314_1516_1718,
            locker: wire::Locker::New(wire::OpenToLockOwner {
                open_sequence_id: 9,
                open_state_id: state_id,
                lock_sequence_id: 10,
                lock_owner: lock_owner.clone(),
            }),
        }),
        bytes: encoded_operation(12, |bytes| {
            push_u32(bytes, wire::LockType::BlockingWrite as u32);
            push_bool(bytes, true);
            push_u64(bytes, 0x0102_0304_0506_0708);
            push_u64(bytes, 0x1112_1314_1516_1718);
            push_bool(bytes, true);
            push_u32(bytes, 9);
            push_state_id(bytes, state_id);
            push_u32(bytes, 10);
            push_lock_owner(bytes, &lock_owner);
        }),
    });
    cases.push(WireCase {
        name: "LOCKT",
        value: wire::ArgOp::LockTest(wire::LockTestArgs {
            lock_type: wire::LockType::Read,
            offset: 11,
            length: 12,
            owner: lock_owner.clone(),
        }),
        bytes: encoded_operation(13, |bytes| {
            push_u32(bytes, wire::LockType::Read as u32);
            push_u64(bytes, 11);
            push_u64(bytes, 12);
            push_lock_owner(bytes, &lock_owner);
        }),
    });
    cases.push(WireCase {
        name: "LOCKU",
        value: wire::ArgOp::LockUnlock(wire::LockUnlockArgs {
            lock_type: wire::LockType::Write,
            sequence_id: 13,
            lock_state_id: state_id,
            offset: 14,
            length: 15,
        }),
        bytes: encoded_operation(14, |bytes| {
            push_u32(bytes, wire::LockType::Write as u32);
            push_u32(bytes, 13);
            push_state_id(bytes, state_id);
            push_u64(bytes, 14);
            push_u64(bytes, 15);
        }),
    });
    cases.push(WireCase {
        name: "LOOKUP",
        value: wire::ArgOp::Lookup(wire::LookupArgs { name: b"etc".to_vec() }),
        bytes: encoded_operation(15, |bytes| push_opaque(bytes, b"etc")),
    });
    cases.push(WireCase {
        name: "LOOKUPP",
        value: wire::ArgOp::LookupParent,
        bytes: encoded_operation(16, |_| {}),
    });
    cases.push(WireCase {
        name: "NVERIFY",
        value: wire::ArgOp::NotVerify(wire::NotVerifyArgs {
            attributes: attributes.clone(),
        }),
        bytes: encoded_operation(17, |bytes| push_file_attributes(bytes, &attributes)),
    });
    cases.push(WireCase {
        name: "OPEN",
        value: wire::ArgOp::Open(wire::OpenArgs {
            sequence_id: 16,
            share_access: wire::OPEN4_SHARE_ACCESS_BOTH,
            share_deny: wire::OPEN4_SHARE_DENY_WRITE,
            owner: wire::OpenOwner {
                client_id: 0x2122_2324_2526_2728,
                owner: b"open".to_vec(),
            },
            how: wire::OpenHow::NoCreate,
            claim: wire::OpenClaim::Null(b"file".to_vec()),
        }),
        bytes: encoded_operation(18, |bytes| {
            push_u32(bytes, 16);
            push_u32(bytes, wire::OPEN4_SHARE_ACCESS_BOTH);
            push_u32(bytes, wire::OPEN4_SHARE_DENY_WRITE);
            push_u64(bytes, 0x2122_2324_2526_2728);
            push_opaque(bytes, b"open");
            push_u32(bytes, 0);
            push_u32(bytes, 0);
            push_opaque(bytes, b"file");
        }),
    });
    cases.push(WireCase {
        name: "OPENATTR",
        value: wire::ArgOp::OpenAttr(wire::OpenAttrArgs { create_directory: true }),
        bytes: encoded_operation(19, |bytes| push_bool(bytes, true)),
    });
    cases.push(WireCase {
        name: "OPEN_CONFIRM",
        value: wire::ArgOp::OpenConfirm(wire::OpenConfirmArgs {
            open_state_id: state_id,
            sequence_id: 17,
        }),
        bytes: encoded_operation(20, |bytes| {
            push_state_id(bytes, state_id);
            push_u32(bytes, 17);
        }),
    });
    cases.push(WireCase {
        name: "OPEN_DOWNGRADE",
        value: wire::ArgOp::OpenDowngrade(wire::OpenDowngradeArgs {
            open_state_id: state_id,
            sequence_id: 18,
            share_access: wire::OPEN4_SHARE_ACCESS_READ,
            share_deny: wire::OPEN4_SHARE_DENY_NONE,
        }),
        bytes: encoded_operation(21, |bytes| {
            push_state_id(bytes, state_id);
            push_u32(bytes, 18);
            push_u32(bytes, wire::OPEN4_SHARE_ACCESS_READ);
            push_u32(bytes, wire::OPEN4_SHARE_DENY_NONE);
        }),
    });
    cases.push(WireCase {
        name: "PUTFH",
        value: wire::ArgOp::PutFh(wire::PutFhArgs {
            object: file_handle.clone(),
        }),
        bytes: encoded_operation(22, |bytes| push_opaque(bytes, file_handle.as_bytes())),
    });
    cases.push(WireCase {
        name: "PUTPUBFH",
        value: wire::ArgOp::PutPublicFh,
        bytes: encoded_operation(23, |_| {}),
    });
    cases.push(WireCase {
        name: "PUTROOTFH",
        value: wire::ArgOp::PutRootFh,
        bytes: encoded_operation(24, |_| {}),
    });
    cases.push(WireCase {
        name: "READ",
        value: wire::ArgOp::Read(wire::ReadArgs {
            state_id,
            offset: 0x3132_3334_3536_3738,
            count: 0x4142_4344,
        }),
        bytes: encoded_operation(25, |bytes| {
            push_state_id(bytes, state_id);
            push_u64(bytes, 0x3132_3334_3536_3738);
            push_u32(bytes, 0x4142_4344);
        }),
    });
    cases.push(WireCase {
        name: "READDIR",
        value: wire::ArgOp::ReadDir(wire::ReadDirArgs {
            cookie: 0x5152_5354_5556_5758,
            cookie_verifier: [0x61; wire::NFS4_VERIFIER_SIZE],
            directory_count: 0x7172_7374,
            max_count: 0x8182_8384,
            requested_attributes: vec![0x9192_9394],
        }),
        bytes: encoded_operation(26, |bytes| {
            push_u64(bytes, 0x5152_5354_5556_5758);
            bytes.extend_from_slice(&[0x61; wire::NFS4_VERIFIER_SIZE]);
            push_u32(bytes, 0x7172_7374);
            push_u32(bytes, 0x8182_8384);
            push_bitmap(bytes, &[0x9192_9394]);
        }),
    });
    cases.push(WireCase {
        name: "READLINK",
        value: wire::ArgOp::ReadLink,
        bytes: encoded_operation(27, |_| {}),
    });
    cases.push(WireCase {
        name: "REMOVE",
        value: wire::ArgOp::Remove(wire::RemoveArgs {
            target: b"gone".to_vec(),
        }),
        bytes: encoded_operation(28, |bytes| push_opaque(bytes, b"gone")),
    });
    cases.push(WireCase {
        name: "RENAME",
        value: wire::ArgOp::Rename(wire::RenameArgs {
            old_name: b"old".to_vec(),
            new_name: b"new".to_vec(),
        }),
        bytes: encoded_operation(29, |bytes| {
            push_opaque(bytes, b"old");
            push_opaque(bytes, b"new");
        }),
    });
    cases.push(WireCase {
        name: "RENEW",
        value: wire::ArgOp::Renew(wire::RenewArgs {
            client_id: 0x6162_6364_6566_6768,
        }),
        bytes: encoded_operation(30, |bytes| push_u64(bytes, 0x6162_6364_6566_6768)),
    });
    cases.push(WireCase {
        name: "RESTOREFH",
        value: wire::ArgOp::RestoreFh,
        bytes: encoded_operation(31, |_| {}),
    });
    cases.push(WireCase {
        name: "SAVEFH",
        value: wire::ArgOp::SaveFh,
        bytes: encoded_operation(32, |_| {}),
    });
    cases.push(WireCase {
        name: "SECINFO",
        value: wire::ArgOp::SecInfo(wire::SecInfoArgs {
            name: b"secure".to_vec(),
        }),
        bytes: encoded_operation(33, |bytes| push_opaque(bytes, b"secure")),
    });
    cases.push(WireCase {
        name: "SETATTR",
        value: wire::ArgOp::SetAttr(wire::SetAttrArgs {
            state_id,
            attributes: attributes.clone(),
        }),
        bytes: encoded_operation(34, |bytes| {
            push_state_id(bytes, state_id);
            push_file_attributes(bytes, &attributes);
        }),
    });
    cases.push(WireCase {
        name: "SETCLIENTID",
        value: wire::ArgOp::SetClientId(wire::SetClientIdArgs {
            client: wire::NfsClientId {
                verifier: [0x71; wire::NFS4_VERIFIER_SIZE],
                id: b"client".to_vec(),
            },
            callback: wire::CallbackClient {
                program: 0x4000_0042,
                location: wire::ClientAddress {
                    netid: b"tcp".to_vec(),
                    address: b"127.0.0.1.8.1".to_vec(),
                },
            },
            callback_identifier: 0x8182_8384,
        }),
        bytes: encoded_operation(35, |bytes| {
            bytes.extend_from_slice(&[0x71; wire::NFS4_VERIFIER_SIZE]);
            push_opaque(bytes, b"client");
            push_u32(bytes, 0x4000_0042);
            push_opaque(bytes, b"tcp");
            push_opaque(bytes, b"127.0.0.1.8.1");
            push_u32(bytes, 0x8182_8384);
        }),
    });
    cases.push(WireCase {
        name: "SETCLIENTID_CONFIRM",
        value: wire::ArgOp::SetClientIdConfirm(wire::SetClientIdConfirmArgs {
            client_id: 0x9192_9394_9596_9798,
            confirmation: [0xa1; wire::NFS4_VERIFIER_SIZE],
        }),
        bytes: encoded_operation(36, |bytes| {
            push_u64(bytes, 0x9192_9394_9596_9798);
            bytes.extend_from_slice(&[0xa1; wire::NFS4_VERIFIER_SIZE]);
        }),
    });
    cases.push(WireCase {
        name: "VERIFY",
        value: wire::ArgOp::Verify(wire::VerifyArgs {
            attributes: attributes.clone(),
        }),
        bytes: encoded_operation(37, |bytes| push_file_attributes(bytes, &attributes)),
    });
    cases.push(WireCase {
        name: "WRITE",
        value: wire::ArgOp::Write(wire::WriteArgs {
            state_id,
            offset: 0xa1a2_a3a4_a5a6_a7a8,
            stability: wire::StableHow::DataSync,
            data: vec![0xb1, 0xb2, 0xb3],
        }),
        bytes: encoded_operation(38, |bytes| {
            push_state_id(bytes, state_id);
            push_u64(bytes, 0xa1a2_a3a4_a5a6_a7a8);
            push_u32(bytes, wire::StableHow::DataSync as u32);
            push_opaque(bytes, &[0xb1, 0xb2, 0xb3]);
        }),
    });
    cases.push(WireCase {
        name: "RELEASE_LOCKOWNER",
        value: wire::ArgOp::ReleaseLockOwner(wire::ReleaseLockOwnerArgs {
            lock_owner: lock_owner.clone(),
        }),
        bytes: encoded_operation(39, |bytes| push_lock_owner(bytes, &lock_owner)),
    });
    cases.push(WireCase {
        name: "ILLEGAL",
        value: wire::ArgOp::Illegal {
            requested_opcode: wire::OpNum::Illegal.code(),
        },
        bytes: encoded_operation(wire::OpNum::Illegal.code(), |_| {}),
    });
    cases
}

fn success_result_wire_cases() -> Vec<WireCase<wire::ResOp>> {
    let state_id = sample_state_id();
    let attributes = sample_file_attributes();
    let change = wire::ChangeInfo {
        atomic: true,
        before: 0x0102_0304_0506_0708,
        after: 0x1112_1314_1516_1718,
    };
    let file_handle = wire::NfsFileHandle::new(vec![0xfa, 0xce, 0x01]).unwrap();
    let mut cases = Vec::new();

    cases.push(WireCase {
        name: "ACCESS",
        value: wire::ResOp::Access(wire::NfsResult::Ok(wire::AccessOk {
            supported: 0x3f,
            access: 0x21,
        })),
        bytes: encoded_operation(3, |bytes| {
            push_u32(bytes, 0);
            push_u32(bytes, 0x3f);
            push_u32(bytes, 0x21);
        }),
    });
    cases.push(WireCase {
        name: "CLOSE",
        value: wire::ResOp::Close(wire::NfsResult::Ok(state_id)),
        bytes: encoded_operation(4, |bytes| {
            push_u32(bytes, 0);
            push_state_id(bytes, state_id);
        }),
    });
    cases.push(WireCase {
        name: "COMMIT",
        value: wire::ResOp::Commit(wire::NfsResult::Ok(wire::CommitOk {
            write_verifier: [0x21; wire::NFS4_VERIFIER_SIZE],
        })),
        bytes: encoded_operation(5, |bytes| {
            push_u32(bytes, 0);
            bytes.extend_from_slice(&[0x21; wire::NFS4_VERIFIER_SIZE]);
        }),
    });
    cases.push(WireCase {
        name: "CREATE",
        value: wire::ResOp::Create(wire::NfsResult::Ok(wire::CreateOk {
            change_info: change,
            attributes_set: vec![0x0102_0304],
        })),
        bytes: encoded_operation(6, |bytes| {
            push_u32(bytes, 0);
            push_change_info(bytes, change);
            push_bitmap(bytes, &[0x0102_0304]);
        }),
    });
    cases.push(WireCase {
        name: "DELEGPURGE",
        value: wire::ResOp::DelegPurge(wire::NfsStatus::Ok),
        bytes: encoded_operation(7, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "DELEGRETURN",
        value: wire::ResOp::DelegReturn(wire::NfsStatus::Ok),
        bytes: encoded_operation(8, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "GETATTR",
        value: wire::ResOp::GetAttr(wire::NfsResult::Ok(attributes.clone())),
        bytes: encoded_operation(9, |bytes| {
            push_u32(bytes, 0);
            push_file_attributes(bytes, &attributes);
        }),
    });
    cases.push(WireCase {
        name: "GETFH",
        value: wire::ResOp::GetFh(wire::NfsResult::Ok(file_handle.clone())),
        bytes: encoded_operation(10, |bytes| {
            push_u32(bytes, 0);
            push_opaque(bytes, file_handle.as_bytes());
        }),
    });
    cases.push(WireCase {
        name: "LINK",
        value: wire::ResOp::Link(wire::NfsResult::Ok(wire::LinkOk { change_info: change })),
        bytes: encoded_operation(11, |bytes| {
            push_u32(bytes, 0);
            push_change_info(bytes, change);
        }),
    });
    cases.push(WireCase {
        name: "LOCK",
        value: wire::ResOp::Lock(wire::LockResult::Ok(state_id)),
        bytes: encoded_operation(12, |bytes| {
            push_u32(bytes, 0);
            push_state_id(bytes, state_id);
        }),
    });
    cases.push(WireCase {
        name: "LOCKT",
        value: wire::ResOp::LockTest(wire::LockTestResult::Ok),
        bytes: encoded_operation(13, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "LOCKU",
        value: wire::ResOp::LockUnlock(wire::NfsResult::Ok(state_id)),
        bytes: encoded_operation(14, |bytes| {
            push_u32(bytes, 0);
            push_state_id(bytes, state_id);
        }),
    });
    cases.push(WireCase {
        name: "LOOKUP",
        value: wire::ResOp::Lookup(wire::NfsStatus::Ok),
        bytes: encoded_operation(15, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "LOOKUPP",
        value: wire::ResOp::LookupParent(wire::NfsStatus::Ok),
        bytes: encoded_operation(16, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "NVERIFY",
        value: wire::ResOp::NotVerify(wire::NfsStatus::Ok),
        bytes: encoded_operation(17, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "OPEN",
        value: wire::ResOp::Open(wire::NfsResult::Ok(wire::OpenOk {
            state_id,
            change_info: change,
            result_flags: wire::OPEN4_RESULT_CONFIRM,
            attributes_set: vec![0x10],
            delegation: wire::OpenDelegation::None,
        })),
        bytes: encoded_operation(18, |bytes| {
            push_u32(bytes, 0);
            push_state_id(bytes, state_id);
            push_change_info(bytes, change);
            push_u32(bytes, wire::OPEN4_RESULT_CONFIRM);
            push_bitmap(bytes, &[0x10]);
            push_u32(bytes, wire::OpenDelegationType::None as u32);
        }),
    });
    cases.push(WireCase {
        name: "OPENATTR",
        value: wire::ResOp::OpenAttr(wire::NfsStatus::Ok),
        bytes: encoded_operation(19, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "OPEN_CONFIRM",
        value: wire::ResOp::OpenConfirm(wire::NfsResult::Ok(state_id)),
        bytes: encoded_operation(20, |bytes| {
            push_u32(bytes, 0);
            push_state_id(bytes, state_id);
        }),
    });
    cases.push(WireCase {
        name: "OPEN_DOWNGRADE",
        value: wire::ResOp::OpenDowngrade(wire::NfsResult::Ok(state_id)),
        bytes: encoded_operation(21, |bytes| {
            push_u32(bytes, 0);
            push_state_id(bytes, state_id);
        }),
    });
    cases.push(WireCase {
        name: "PUTFH",
        value: wire::ResOp::PutFh(wire::NfsStatus::Ok),
        bytes: encoded_operation(22, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "PUTPUBFH",
        value: wire::ResOp::PutPublicFh(wire::NfsStatus::Ok),
        bytes: encoded_operation(23, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "PUTROOTFH",
        value: wire::ResOp::PutRootFh(wire::NfsStatus::Ok),
        bytes: encoded_operation(24, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "READ",
        value: wire::ResOp::Read(wire::NfsResult::Ok(wire::ReadOk {
            eof: true,
            data: vec![0x31, 0x32, 0x33],
        })),
        bytes: encoded_operation(25, |bytes| {
            push_u32(bytes, 0);
            push_bool(bytes, true);
            push_opaque(bytes, &[0x31, 0x32, 0x33]);
        }),
    });
    cases.push(WireCase {
        name: "READDIR",
        value: wire::ResOp::ReadDir(wire::NfsResult::Ok(wire::ReadDirOk {
            cookie_verifier: [0x41; wire::NFS4_VERIFIER_SIZE],
            entries: vec![wire::DirectoryEntry {
                cookie: 0x5152_5354_5556_5758,
                name: b"entry".to_vec(),
                attributes: attributes.clone(),
            }],
            eof: true,
        })),
        bytes: encoded_operation(26, |bytes| {
            push_u32(bytes, 0);
            bytes.extend_from_slice(&[0x41; wire::NFS4_VERIFIER_SIZE]);
            push_bool(bytes, true);
            push_u64(bytes, 0x5152_5354_5556_5758);
            push_opaque(bytes, b"entry");
            push_file_attributes(bytes, &attributes);
            push_bool(bytes, false);
            push_bool(bytes, true);
        }),
    });
    cases.push(WireCase {
        name: "READLINK",
        value: wire::ResOp::ReadLink(wire::NfsResult::Ok(wire::ReadLinkOk {
            link: b"target".to_vec(),
        })),
        bytes: encoded_operation(27, |bytes| {
            push_u32(bytes, 0);
            push_opaque(bytes, b"target");
        }),
    });
    cases.push(WireCase {
        name: "REMOVE",
        value: wire::ResOp::Remove(wire::NfsResult::Ok(wire::RemoveOk { change_info: change })),
        bytes: encoded_operation(28, |bytes| {
            push_u32(bytes, 0);
            push_change_info(bytes, change);
        }),
    });
    cases.push(WireCase {
        name: "RENAME",
        value: wire::ResOp::Rename(wire::NfsResult::Ok(wire::RenameOk {
            source_change_info: change,
            target_change_info: wire::ChangeInfo {
                atomic: false,
                before: 0x6162_6364_6566_6768,
                after: 0x7172_7374_7576_7778,
            },
        })),
        bytes: encoded_operation(29, |bytes| {
            push_u32(bytes, 0);
            push_change_info(bytes, change);
            push_change_info(
                bytes,
                wire::ChangeInfo {
                    atomic: false,
                    before: 0x6162_6364_6566_6768,
                    after: 0x7172_7374_7576_7778,
                },
            );
        }),
    });
    cases.push(WireCase {
        name: "RENEW",
        value: wire::ResOp::Renew(wire::NfsStatus::Ok),
        bytes: encoded_operation(30, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "RESTOREFH",
        value: wire::ResOp::RestoreFh(wire::NfsStatus::Ok),
        bytes: encoded_operation(31, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "SAVEFH",
        value: wire::ResOp::SaveFh(wire::NfsStatus::Ok),
        bytes: encoded_operation(32, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "SECINFO",
        value: wire::ResOp::SecInfo(wire::NfsResult::Ok(vec![
            wire::SecurityInfo::Other(1),
            wire::SecurityInfo::RpcSecGss(wire::RpcSecGssInfo {
                oid: vec![0x2a, 0x86, 0x48],
                qop: 0,
                service: wire::RpcGssService::Integrity,
            }),
        ])),
        bytes: encoded_operation(33, |bytes| {
            push_u32(bytes, 0);
            push_u32(bytes, 2);
            push_u32(bytes, 1);
            push_u32(bytes, wire::RPCSEC_GSS);
            push_opaque(bytes, &[0x2a, 0x86, 0x48]);
            push_u32(bytes, 0);
            push_u32(bytes, wire::RpcGssService::Integrity as u32);
        }),
    });
    cases.push(WireCase {
        name: "SETATTR",
        value: wire::ResOp::SetAttr(wire::SetAttrResult {
            status: wire::NfsStatus::Ok,
            attributes_set: vec![0x0102_0304],
        }),
        bytes: encoded_operation(34, |bytes| {
            push_u32(bytes, 0);
            push_bitmap(bytes, &[0x0102_0304]);
        }),
    });
    cases.push(WireCase {
        name: "SETCLIENTID",
        value: wire::ResOp::SetClientId(wire::SetClientIdResult::Ok(wire::SetClientIdOk {
            client_id: 0x8182_8384_8586_8788,
            confirmation: [0x91; wire::NFS4_VERIFIER_SIZE],
        })),
        bytes: encoded_operation(35, |bytes| {
            push_u32(bytes, 0);
            push_u64(bytes, 0x8182_8384_8586_8788);
            bytes.extend_from_slice(&[0x91; wire::NFS4_VERIFIER_SIZE]);
        }),
    });
    cases.push(WireCase {
        name: "SETCLIENTID_CONFIRM",
        value: wire::ResOp::SetClientIdConfirm(wire::NfsStatus::Ok),
        bytes: encoded_operation(36, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "VERIFY",
        value: wire::ResOp::Verify(wire::NfsStatus::Ok),
        bytes: encoded_operation(37, |bytes| push_u32(bytes, 0)),
    });
    cases.push(WireCase {
        name: "WRITE",
        value: wire::ResOp::Write(wire::NfsResult::Ok(wire::WriteOk {
            count: 0xa1a2_a3a4,
            committed: wire::StableHow::FileSync,
            write_verifier: [0xb1; wire::NFS4_VERIFIER_SIZE],
        })),
        bytes: encoded_operation(38, |bytes| {
            push_u32(bytes, 0);
            push_u32(bytes, 0xa1a2_a3a4);
            push_u32(bytes, wire::StableHow::FileSync as u32);
            bytes.extend_from_slice(&[0xb1; wire::NFS4_VERIFIER_SIZE]);
        }),
    });
    cases.push(WireCase {
        name: "RELEASE_LOCKOWNER",
        value: wire::ResOp::ReleaseLockOwner(wire::NfsStatus::Ok),
        bytes: encoded_operation(39, |bytes| push_u32(bytes, 0)),
    });

    cases
}

fn legal_error_result(opcode: wire::OpNum) -> wire::ResOp {
    let status = wire::NfsStatus::ServerFault;
    match opcode {
        wire::OpNum::Access => wire::ResOp::Access(wire::NfsResult::Err(status)),
        wire::OpNum::Close => wire::ResOp::Close(wire::NfsResult::Err(status)),
        wire::OpNum::Commit => wire::ResOp::Commit(wire::NfsResult::Err(status)),
        wire::OpNum::Create => wire::ResOp::Create(wire::NfsResult::Err(status)),
        wire::OpNum::DelegPurge => wire::ResOp::DelegPurge(status),
        wire::OpNum::DelegReturn => wire::ResOp::DelegReturn(status),
        wire::OpNum::GetAttr => wire::ResOp::GetAttr(wire::NfsResult::Err(status)),
        wire::OpNum::GetFh => wire::ResOp::GetFh(wire::NfsResult::Err(status)),
        wire::OpNum::Link => wire::ResOp::Link(wire::NfsResult::Err(status)),
        wire::OpNum::Lock => wire::ResOp::Lock(wire::LockResult::Err(status)),
        wire::OpNum::LockTest => wire::ResOp::LockTest(wire::LockTestResult::Err(status)),
        wire::OpNum::LockUnlock => wire::ResOp::LockUnlock(wire::NfsResult::Err(status)),
        wire::OpNum::Lookup => wire::ResOp::Lookup(status),
        wire::OpNum::LookupParent => wire::ResOp::LookupParent(status),
        wire::OpNum::NotVerify => wire::ResOp::NotVerify(status),
        wire::OpNum::Open => wire::ResOp::Open(wire::NfsResult::Err(status)),
        wire::OpNum::OpenAttr => wire::ResOp::OpenAttr(status),
        wire::OpNum::OpenConfirm => wire::ResOp::OpenConfirm(wire::NfsResult::Err(status)),
        wire::OpNum::OpenDowngrade => wire::ResOp::OpenDowngrade(wire::NfsResult::Err(status)),
        wire::OpNum::PutFh => wire::ResOp::PutFh(status),
        wire::OpNum::PutPublicFh => wire::ResOp::PutPublicFh(status),
        wire::OpNum::PutRootFh => wire::ResOp::PutRootFh(status),
        wire::OpNum::Read => wire::ResOp::Read(wire::NfsResult::Err(status)),
        wire::OpNum::ReadDir => wire::ResOp::ReadDir(wire::NfsResult::Err(status)),
        wire::OpNum::ReadLink => wire::ResOp::ReadLink(wire::NfsResult::Err(status)),
        wire::OpNum::Remove => wire::ResOp::Remove(wire::NfsResult::Err(status)),
        wire::OpNum::Rename => wire::ResOp::Rename(wire::NfsResult::Err(status)),
        wire::OpNum::Renew => wire::ResOp::Renew(status),
        wire::OpNum::RestoreFh => wire::ResOp::RestoreFh(status),
        wire::OpNum::SaveFh => wire::ResOp::SaveFh(status),
        wire::OpNum::SecInfo => wire::ResOp::SecInfo(wire::NfsResult::Err(status)),
        wire::OpNum::SetAttr => wire::ResOp::SetAttr(wire::SetAttrResult {
            status,
            attributes_set: Vec::new(),
        }),
        wire::OpNum::SetClientId => wire::ResOp::SetClientId(wire::SetClientIdResult::Err(status)),
        wire::OpNum::SetClientIdConfirm => wire::ResOp::SetClientIdConfirm(status),
        wire::OpNum::Verify => wire::ResOp::Verify(status),
        wire::OpNum::Write => wire::ResOp::Write(wire::NfsResult::Err(status)),
        wire::OpNum::ReleaseLockOwner => wire::ResOp::ReleaseLockOwner(status),
        wire::OpNum::Illegal => wire::ResOp::Illegal(wire::NfsStatus::OperationIllegal),
    }
}

#[test]
fn encodes_a_compound_request_as_canonical_xdr() {
    let request = CompoundRequest::new(b"raw")
        .with_operation(Nfs4Operation::putrootfh())
        .with_operation(Nfs4Operation::lookup(b"etc").unwrap())
        .with_operation(Nfs4Operation::getfh());

    assert_eq!(
        request.encode().unwrap(),
        vec![
            0, 0, 0, 3, b'r', b'a', b'w', 0, // tag
            0, 0, 0, 0, // minor version
            0, 0, 0, 3, // operation count
            0, 0, 0, 24, // PUTROOTFH
            0, 0, 0, 15, // LOOKUP
            0, 0, 0, 3, b'e', b't', b'c', 0, // component
            0, 0, 0, 10, // GETFH
        ]
    );
}

#[test]
fn public_codec_matches_exact_argument_wire_for_every_nfs40_operation() {
    let limits = wire::DecodeLimits::default();
    let cases = argument_wire_cases();
    assert_eq!(cases.len(), 38);

    for case in cases {
        let arguments = wire::CompoundArgs {
            tag: b"arg".to_vec(),
            minor_version: 0,
            operations: vec![case.value],
        };
        let expected = encoded_compound_args(b"arg", 0, &[case.bytes]);
        let encoded = wire::encode_compound_args(&arguments).unwrap();
        assert_eq!(encoded, expected, "{} request wire", case.name);
        assert_eq!(
            wire::decode_compound_args(&encoded, limits).unwrap(),
            arguments,
            "{} request round trip",
            case.name
        );
    }
}

#[test]
fn public_codec_matches_exact_success_wire_for_operations_3_through_39() {
    let limits = wire::DecodeLimits::default();
    let cases = success_result_wire_cases();
    assert_eq!(cases.len(), 37);

    for case in cases {
        assert_eq!(case.value.status(), wire::NfsStatus::Ok, "{}", case.name);
        assert!(
            wire::legal_errors::is_legal_operation_status(case.value.opnum().code(), case.value.status()),
            "{} success must be legal",
            case.name
        );
        let response = wire::CompoundRes::from_operations(b"ok".to_vec(), vec![case.value]);
        let expected = encoded_compound_res(wire::NfsStatus::Ok, b"ok", &[case.bytes]);
        let encoded = wire::encode_compound_res(&response).unwrap();
        assert_eq!(encoded, expected, "{} success wire", case.name);
        assert_eq!(wire::decode_compound_res(&encoded, limits).unwrap(), response, "{} success round trip", case.name);
    }
}

#[test]
fn public_codec_matches_exact_legal_error_wire_for_every_nfs40_result() {
    let limits = wire::DecodeLimits::default();
    let mut opcodes = (3..=39)
        .map(|opcode| wire::OpNum::from_code(opcode).unwrap())
        .collect::<Vec<_>>();
    opcodes.push(wire::OpNum::Illegal);

    for opcode in opcodes {
        let result = legal_error_result(opcode);
        let status = result.status();
        assert!(
            wire::legal_errors::is_legal_operation_status(opcode.code(), status),
            "{opcode:?} must use a legal RFC 7530 error"
        );

        let response = wire::CompoundRes::from_operations(b"err".to_vec(), vec![result]);
        let expected_operation = encoded_operation(opcode.code(), |bytes| {
            push_u32(bytes, status.code());
            if opcode == wire::OpNum::SetAttr {
                push_bitmap(bytes, &[]);
            }
        });
        let expected = encoded_compound_res(status, b"err", &[expected_operation]);
        let encoded = wire::encode_compound_res(&response).unwrap();
        assert_eq!(encoded, expected, "{opcode:?} legal-error wire");
        assert_eq!(wire::decode_compound_res(&encoded, limits).unwrap(), response, "{opcode:?} legal-error round trip");
    }
}

#[test]
fn public_codec_matches_exact_callback_argument_wire() {
    let state_id = sample_state_id();
    let file_handle = wire::NfsFileHandle::new(vec![0xca, 0x11]).unwrap();
    let arguments = wire::CallbackCompoundArgs {
        tag: b"cb".to_vec(),
        minor_version: 0,
        callback_identifier: 0x0102_0304,
        operations: vec![
            wire::CallbackArgOp::GetAttr(wire::CallbackGetAttrArgs {
                file_handle: file_handle.clone(),
                requested_attributes: vec![0x1112_1314],
            }),
            wire::CallbackArgOp::Recall(wire::CallbackRecallArgs {
                state_id,
                truncate: true,
                file_handle: file_handle.clone(),
            }),
            wire::CallbackArgOp::Illegal {
                requested_opcode: wire::CallbackOpNum::Illegal.code(),
            },
        ],
    };
    let expected = encoded_callback_args(
        b"cb",
        0,
        0x0102_0304,
        &[
            encoded_operation(wire::CallbackOpNum::GetAttr.code(), |bytes| {
                push_opaque(bytes, file_handle.as_bytes());
                push_bitmap(bytes, &[0x1112_1314]);
            }),
            encoded_operation(wire::CallbackOpNum::Recall.code(), |bytes| {
                push_state_id(bytes, state_id);
                push_bool(bytes, true);
                push_opaque(bytes, file_handle.as_bytes());
            }),
            encoded_operation(wire::CallbackOpNum::Illegal.code(), |_| {}),
        ],
    );

    let encoded = wire::encode_callback_compound_args(&arguments).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(wire::decode_callback_compound_args(&encoded, wire::DecodeLimits::default()).unwrap(), arguments);
}

#[test]
fn public_codec_matches_exact_callback_success_and_legal_error_wire() {
    let attributes = sample_file_attributes();
    let success_cases = [
        WireCase {
            name: "CB_GETATTR",
            value: wire::CallbackResOp::GetAttr(wire::NfsResult::Ok(attributes.clone())),
            bytes: encoded_operation(wire::CallbackOpNum::GetAttr.code(), |bytes| {
                push_u32(bytes, wire::NfsStatus::Ok.code());
                push_file_attributes(bytes, &attributes);
            }),
        },
        WireCase {
            name: "CB_RECALL",
            value: wire::CallbackResOp::Recall(wire::NfsStatus::Ok),
            bytes: encoded_operation(wire::CallbackOpNum::Recall.code(), |bytes| {
                push_u32(bytes, wire::NfsStatus::Ok.code());
            }),
        },
    ];
    for case in success_cases {
        let response = wire::CallbackCompoundRes::from_operations(b"cb-ok".to_vec(), vec![case.value]);
        let expected = encoded_compound_res(wire::NfsStatus::Ok, b"cb-ok", &[case.bytes]);
        let encoded = wire::encode_callback_compound_res(&response).unwrap();
        assert_eq!(encoded, expected, "{} success wire", case.name);
        assert_eq!(
            wire::decode_callback_compound_res(&encoded, wire::DecodeLimits::default()).unwrap(),
            response,
            "{} success round trip",
            case.name
        );
    }

    let error_cases = [
        (
            wire::CallbackOpNum::GetAttr,
            wire::CallbackResOp::GetAttr(wire::NfsResult::Err(wire::NfsStatus::BadHandle)),
            wire::NfsStatus::BadHandle,
        ),
        (
            wire::CallbackOpNum::Recall,
            wire::CallbackResOp::Recall(wire::NfsStatus::BadStateId),
            wire::NfsStatus::BadStateId,
        ),
        (
            wire::CallbackOpNum::Illegal,
            wire::CallbackResOp::Illegal(wire::NfsStatus::OperationIllegal),
            wire::NfsStatus::OperationIllegal,
        ),
    ];
    for (opcode, result, status) in error_cases {
        assert!(wire::legal_errors::is_legal_callback_status(opcode.code(), status));
        let response = wire::CallbackCompoundRes::from_operations(b"cb-err".to_vec(), vec![result]);
        let expected_operation = encoded_operation(opcode.code(), |bytes| push_u32(bytes, status.code()));
        let expected = encoded_compound_res(status, b"cb-err", &[expected_operation]);
        let encoded = wire::encode_callback_compound_res(&response).unwrap();
        assert_eq!(encoded, expected, "{opcode:?} legal-error wire");
        assert_eq!(
            wire::decode_callback_compound_res(&encoded, wire::DecodeLimits::default()).unwrap(),
            response,
            "{opcode:?} legal-error round trip"
        );
    }
}

#[test]
fn public_codec_matches_exact_special_result_union_arms() {
    let denied = wire::LockDenied {
        offset: 0x0102_0304_0506_0708,
        length: 0x1112_1314_1516_1718,
        lock_type: wire::LockType::Write,
        owner: sample_lock_owner(),
    };
    let lock_cases = [
        (
            wire::ResOp::Lock(wire::LockResult::Denied(denied.clone())),
            encoded_operation(wire::OpNum::Lock.code(), |bytes| {
                push_u32(bytes, wire::NfsStatus::Denied.code());
                push_lock_denied(bytes, &denied);
            }),
        ),
        (
            wire::ResOp::LockTest(wire::LockTestResult::Denied(denied.clone())),
            encoded_operation(wire::OpNum::LockTest.code(), |bytes| {
                push_u32(bytes, wire::NfsStatus::Denied.code());
                push_lock_denied(bytes, &denied);
            }),
        ),
    ];
    for (result, expected_operation) in lock_cases {
        let response = wire::CompoundRes::from_operations(b"denied".to_vec(), vec![result]);
        let expected = encoded_compound_res(wire::NfsStatus::Denied, b"denied", &[expected_operation]);
        let encoded = wire::encode_compound_res(&response).unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(wire::decode_compound_res(&encoded, wire::DecodeLimits::default()).unwrap(), response);
    }

    let address = wire::ClientAddress {
        netid: b"tcp".to_vec(),
        address: b"192.0.2.1.8.1".to_vec(),
    };
    let response = wire::CompoundRes::from_operations(
        b"in-use".to_vec(),
        vec![wire::ResOp::SetClientId(wire::SetClientIdResult::ClientIdInUse(
            address.clone(),
        ))],
    );
    let expected_operation = encoded_operation(wire::OpNum::SetClientId.code(), |bytes| {
        push_u32(bytes, wire::NfsStatus::ClientIdInUse.code());
        push_opaque(bytes, &address.netid);
        push_opaque(bytes, &address.address);
    });
    let expected = encoded_compound_res(wire::NfsStatus::ClientIdInUse, b"in-use", &[expected_operation]);
    let encoded = wire::encode_compound_res(&response).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(wire::decode_compound_res(&encoded, wire::DecodeLimits::default()).unwrap(), response);

    let state_id = sample_state_id();
    let change = wire::ChangeInfo {
        atomic: true,
        before: 1,
        after: 2,
    };
    let permissions = wire::NfsAce {
        ace_type: 0,
        flags: 1,
        access_mask: 0x001f_01ff,
        who: b"OWNER@".to_vec(),
    };
    let delegation_cases = [
        (
            wire::OpenDelegation::Read(wire::OpenReadDelegation {
                state_id,
                recall: false,
                permissions: permissions.clone(),
            }),
            encoded_operation(wire::OpNum::Open.code(), |bytes| {
                push_u32(bytes, wire::NfsStatus::Ok.code());
                push_state_id(bytes, state_id);
                push_change_info(bytes, change);
                push_u32(bytes, 0);
                push_bitmap(bytes, &[]);
                push_u32(bytes, wire::OpenDelegationType::Read as u32);
                push_state_id(bytes, state_id);
                push_bool(bytes, false);
                push_ace(bytes, &permissions);
            }),
        ),
        (
            wire::OpenDelegation::Write(wire::OpenWriteDelegation {
                state_id,
                recall: true,
                space_limit: wire::SpaceLimit::Blocks {
                    block_count: 3,
                    bytes_per_block: 4096,
                },
                permissions: permissions.clone(),
            }),
            encoded_operation(wire::OpNum::Open.code(), |bytes| {
                push_u32(bytes, wire::NfsStatus::Ok.code());
                push_state_id(bytes, state_id);
                push_change_info(bytes, change);
                push_u32(bytes, 0);
                push_bitmap(bytes, &[]);
                push_u32(bytes, wire::OpenDelegationType::Write as u32);
                push_state_id(bytes, state_id);
                push_bool(bytes, true);
                push_u32(bytes, 2);
                push_u32(bytes, 3);
                push_u32(bytes, 4096);
                push_ace(bytes, &permissions);
            }),
        ),
    ];
    for (delegation, expected_operation) in delegation_cases {
        let response = wire::CompoundRes::from_operations(
            b"deleg".to_vec(),
            vec![wire::ResOp::Open(wire::NfsResult::Ok(wire::OpenOk {
                state_id,
                change_info: change,
                result_flags: 0,
                attributes_set: Vec::new(),
                delegation,
            }))],
        );
        let expected = encoded_compound_res(wire::NfsStatus::Ok, b"deleg", &[expected_operation]);
        let encoded = wire::encode_compound_res(&response).unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(wire::decode_compound_res(&encoded, wire::DecodeLimits::default()).unwrap(), response);
    }
}

#[test]
fn every_operation_fixture_rejects_truncation_and_noncanonical_padding() {
    let limits = wire::DecodeLimits::default();

    for case in argument_wire_cases() {
        let mut encoded = encoded_compound_args(b"", 0, &[case.bytes]);
        encoded.pop();
        assert!(wire::decode_compound_args(&encoded, limits).is_err(), "{} truncated request must fail", case.name);
    }

    for case in success_result_wire_cases() {
        let mut encoded = encoded_compound_res(wire::NfsStatus::Ok, b"", &[case.bytes]);
        encoded.pop();
        assert!(wire::decode_compound_res(&encoded, limits).is_err(), "{} truncated response must fail", case.name);
    }

    let mut invalid_tag_padding = encoded_compound_args(b"x", 0, &[]);
    invalid_tag_padding[5] = 1;
    assert_eq!(wire::decode_compound_args(&invalid_tag_padding, limits), Err(DecodeError::InvalidPadding));

    let mut trailing = encoded_compound_args(b"", 0, &[]);
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(wire::decode_compound_args(&trailing, limits), Err(DecodeError::TrailingBytes));
}

#[test]
fn public_predecoder_enforces_all_collection_and_payload_bounds() {
    let limits = wire::DecodeLimits {
        max_tag_bytes: 1,
        ..wire::DecodeLimits::default()
    };
    let oversized_tag = encoded_compound_args(b"xx", 0, &[]);
    assert!(matches!(
        wire::decode_compound_args(&oversized_tag, limits),
        Err(DecodeError::LimitExceeded {
            field: "NFSv4 COMPOUND tag",
            actual: 2,
            limit: 1,
        })
    ));

    let limits = wire::DecodeLimits {
        max_operations: 1,
        ..wire::DecodeLimits::default()
    };
    let mut oversized_operation_count = encoded_compound_args(b"", 0, &[]);
    oversized_operation_count[8..12].copy_from_slice(&2u32.to_be_bytes());
    assert!(matches!(
        wire::decode_compound_args(&oversized_operation_count, limits),
        Err(DecodeError::LimitExceeded {
            field: "NFSv4 operations",
            actual: 2,
            limit: 1,
        })
    ));

    let limits = wire::DecodeLimits {
        max_bitmap_words: 1,
        ..wire::DecodeLimits::default()
    };
    let getattr = encoded_operation(wire::OpNum::GetAttr.code(), |bytes| {
        push_bitmap(bytes, &[1, 2]);
    });
    assert!(matches!(
        wire::decode_compound_args(&encoded_compound_args(b"", 0, &[getattr]), limits),
        Err(DecodeError::LimitExceeded {
            field: "NFSv4 bitmap words",
            actual: 2,
            limit: 1,
        })
    ));

    let limits = wire::DecodeLimits {
        max_io_bytes: 2,
        ..wire::DecodeLimits::default()
    };
    let write = encoded_operation(wire::OpNum::Write.code(), |bytes| {
        push_state_id(bytes, sample_state_id());
        push_u64(bytes, 0);
        push_u32(bytes, wire::StableHow::Unstable as u32);
        push_opaque(bytes, b"abc");
    });
    assert!(matches!(
        wire::decode_compound_args(&encoded_compound_args(b"", 0, &[write]), limits),
        Err(DecodeError::LimitExceeded {
            field: "NFSv4 WRITE data",
            actual: 3,
            limit: 2,
        })
    ));

    let limits = wire::DecodeLimits {
        max_directory_entries: 0,
        ..wire::DecodeLimits::default()
    };
    let attributes = sample_file_attributes();
    let readdir = encoded_operation(wire::OpNum::ReadDir.code(), |bytes| {
        push_u32(bytes, wire::NfsStatus::Ok.code());
        bytes.extend_from_slice(&[0; wire::NFS4_VERIFIER_SIZE]);
        push_bool(bytes, true);
        push_u64(bytes, 1);
        push_opaque(bytes, b"x");
        push_file_attributes(bytes, &attributes);
        push_bool(bytes, false);
        push_bool(bytes, true);
    });
    assert!(matches!(
        wire::decode_compound_res(&encoded_compound_res(wire::NfsStatus::Ok, b"", &[readdir]), limits),
        Err(DecodeError::LimitExceeded {
            field: "NFSv4 directory entries",
            actual: 1,
            limit: 0,
        })
    ));
}

#[test]
fn malformed_union_discriminants_and_booleans_are_rejected() {
    let limits = wire::DecodeLimits::default();

    let invalid_lock_type = encoded_operation(wire::OpNum::LockTest.code(), |bytes| {
        push_u32(bytes, 99);
        push_u64(bytes, 0);
        push_u64(bytes, 0);
        push_lock_owner(bytes, &sample_lock_owner());
    });
    assert!(matches!(
        wire::decode_compound_args(&encoded_compound_args(b"", 0, &[invalid_lock_type]), limits),
        Err(DecodeError::InvalidDiscriminant {
            kind: "nfs_lock_type4",
            value: 99,
        })
    ));

    let invalid_stability = encoded_operation(wire::OpNum::Write.code(), |bytes| {
        push_state_id(bytes, sample_state_id());
        push_u64(bytes, 0);
        push_u32(bytes, 99);
        push_opaque(bytes, b"");
    });
    assert!(matches!(
        wire::decode_compound_args(&encoded_compound_args(b"", 0, &[invalid_stability]), limits),
        Err(DecodeError::InvalidDiscriminant {
            kind: "stable_how4",
            value: 99,
        })
    ));

    let invalid_bool = encoded_operation(wire::OpNum::OpenAttr.code(), |bytes| push_u32(bytes, 2));
    assert_eq!(
        wire::decode_compound_args(&encoded_compound_args(b"", 0, &[invalid_bool]), limits),
        Err(DecodeError::InvalidBoolean(2))
    );

    let invalid_response_opcode = encoded_operation(99, |bytes| push_u32(bytes, wire::NfsStatus::Ok.code()));
    assert!(matches!(
        wire::decode_compound_res(&encoded_compound_res(wire::NfsStatus::Ok, b"", &[invalid_response_opcode]), limits),
        Err(DecodeError::InvalidDiscriminant {
            kind: "nfs_opnum4",
            value: 99,
        })
    ));

    let unknown_request_opcode = encoded_operation(99, |_| {});
    let decoded =
        wire::decode_compound_args(&encoded_compound_args(b"", 0, &[unknown_request_opcode]), limits).unwrap();
    assert_eq!(decoded.operations, vec![wire::ArgOp::Illegal { requested_opcode: 99 }]);
}

#[test]
fn minor_version_and_compound_status_invariants_have_exact_wire_shapes() {
    let arguments = wire::CompoundArgs {
        tag: b"minor".to_vec(),
        minor_version: 1,
        operations: vec![wire::ArgOp::PutRootFh],
    };
    let expected_arguments =
        encoded_compound_args(b"minor", 1, &[encoded_operation(wire::OpNum::PutRootFh.code(), |_| {})]);
    let encoded = wire::encode_compound_args(&arguments).unwrap();
    assert_eq!(encoded, expected_arguments);
    assert_eq!(wire::decode_compound_args(&encoded, wire::DecodeLimits::default()).unwrap(), arguments);

    let mismatch = wire::CompoundRes {
        status: wire::NfsStatus::MinorVersionMismatch,
        tag: b"minor".to_vec(),
        operations: Vec::new(),
    };
    let encoded = wire::encode_compound_res(&mismatch).unwrap();
    assert_eq!(encoded, encoded_compound_res(wire::NfsStatus::MinorVersionMismatch, b"minor", &[]));
    assert_eq!(wire::decode_compound_res(&encoded, wire::DecodeLimits::default()).unwrap(), mismatch);

    let stopped = wire::CompoundRes::from_operations(
        b"stop".to_vec(),
        vec![
            wire::ResOp::PutRootFh(wire::NfsStatus::Ok),
            wire::ResOp::Lookup(wire::NfsStatus::NotFound),
        ],
    );
    assert_eq!(stopped.status, wire::NfsStatus::NotFound);
    assert_eq!(stopped.operations.len(), 2);

    let empty = wire::CompoundRes::from_operations(b"empty".to_vec(), Vec::new());
    assert_eq!(empty.status, wire::NfsStatus::Ok);
    assert!(empty.operations.is_empty());
}

#[test]
fn emits_rpc_version_two_nfs_version_four_compound_calls() {
    let request = CompoundRequest::new(b"rpc").with_operation(Nfs4Operation::putrootfh());
    let call = request.encode_rpc_call(0x0102_0304, &OpaqueAuth::none()).unwrap();
    let mut decoder = Decoder::new(&call);

    assert_eq!(decoder.read_u32().unwrap(), 0x0102_0304);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decoder.read_u32().unwrap(), 2);
    assert_eq!(decoder.read_u32().unwrap(), NFS_PROGRAM);
    assert_eq!(decoder.read_u32().unwrap(), NFS4_VERSION);
    assert_eq!(decoder.read_u32().unwrap(), NFS4_PROC_COMPOUND);
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decoder.read_opaque("credential", 0).unwrap().is_empty());
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert!(decoder.read_opaque("verifier", 0).unwrap().is_empty());
    assert_eq!(&call[decoder.position()..], request.encode().unwrap());
}

#[test]
fn encodes_bitmap_stateid_and_write_payloads_without_server_types() {
    let request = CompoundRequest::new(b"ops")
        .with_operation(Nfs4Operation::getattr(&[0x8000_0010, 7]).unwrap())
        .with_operation(
            Nfs4Operation::write(
                StateId {
                    sequence_id: 9,
                    other: [0xab; 12],
                },
                0x0102_0304_0506_0708,
                StableHow::FileSync,
                b"abc",
            )
            .unwrap(),
        );
    let encoded = request.encode().unwrap();
    let mut decoder = Decoder::new(&encoded);

    assert_eq!(decoder.read_opaque("tag", 16).unwrap(), b"ops");
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decoder.read_u32().unwrap(), 2);
    assert_eq!(decoder.read_u32().unwrap(), OP_GETATTR);
    assert_eq!(decoder.read_u32().unwrap(), 2);
    assert_eq!(decoder.read_u32().unwrap(), 0x8000_0010);
    assert_eq!(decoder.read_u32().unwrap(), 7);
    assert_eq!(decoder.read_u32().unwrap(), OP_WRITE);
    assert_eq!(decoder.read_u32().unwrap(), 9);
    assert_eq!(decoder.read_fixed::<12>().unwrap(), [0xab; 12]);
    assert_eq!(decoder.read_u64().unwrap(), 0x0102_0304_0506_0708);
    assert_eq!(decoder.read_u32().unwrap(), StableHow::FileSync as u32);
    assert_eq!(decoder.read_opaque("write data", 3).unwrap(), b"abc");
    decoder.finish().unwrap();
}

#[test]
fn parses_status_only_operation_results_and_empty_minor_version_errors() {
    let illegal = encode_status_only_reply(
        NFS4ERR_OP_ILLEGAL,
        b"bad-op",
        &[StatusOnlyResult {
            operation: OP_ILLEGAL,
            status: NFS4ERR_OP_ILLEGAL,
        }],
    )
    .unwrap();
    let (header, results) = decode_status_only_reply(&illegal).unwrap();
    assert_eq!(header.status, NFS4ERR_OP_ILLEGAL);
    assert_eq!(header.tag, b"bad-op");
    assert_eq!(
        results,
        vec![StatusOnlyResult {
            operation: OP_ILLEGAL,
            status: NFS4ERR_OP_ILLEGAL,
        }]
    );

    let mismatch = encode_status_only_reply(NFS4ERR_MINOR_VERS_MISMATCH, b"minor", &[]).unwrap();
    let (header, results) = decode_status_only_reply(&mismatch).unwrap();
    assert_eq!(header.status, NFS4ERR_MINOR_VERS_MISMATCH);
    assert_eq!(header.result_count, 0);
    assert!(results.is_empty());
}

#[test]
fn reply_envelope_enforces_fixture_bounds_and_canonical_padding() {
    let mut too_many = Encoder::new();
    too_many.write_u32(NFS4_OK);
    too_many.write_opaque(b"limit").unwrap();
    too_many.write_u32(u32::try_from(MAX_COMPOUND_OPERATIONS + 1).unwrap());
    assert!(matches!(
        decode_compound_reply_header(&too_many.into_bytes()),
        Err(DecodeError::LimitExceeded {
            field: "NFSv4 COMPOUND results",
            actual,
            limit: MAX_COMPOUND_OPERATIONS,
        }) if actual == MAX_COMPOUND_OPERATIONS + 1
    ));

    let invalid_padding = [
        0, 0, 0, 0, // status
        0, 0, 0, 1, b'x', 1, 0, 0, // non-zero tag padding
        0, 0, 0, 0, // result count
    ];
    assert_eq!(decode_compound_reply_header(&invalid_padding), Err(DecodeError::InvalidPadding));
}

#[test]
fn opcode_constants_match_the_rfc_compound_discriminants() {
    assert_eq!(OP_PUTROOTFH, 24);
    assert_eq!(OP_LOOKUP, 15);
    assert_eq!(OP_GETFH, 10);
    assert_eq!(OP_ILLEGAL, 10_044);
}
