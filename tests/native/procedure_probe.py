#!/usr/bin/env python3
"""Exercise NFSv3/MOUNTv3 procedures and read-only mutation statuses."""

import socket
import struct
import sys


NFS_PROGRAM = 100003
NFS_VERSION = 3
MOUNT_PROGRAM = 100005
MOUNT_VERSION = 3


def u32(value):
    return struct.pack(">I", value)


def u64(value):
    return struct.pack(">Q", value)


def opaque(value):
    padding = (-len(value)) % 4
    return u32(len(value)) + value + bytes(padding)


def read_u32(data, offset):
    if offset + 4 > len(data):
        raise RuntimeError("truncated RPC reply")
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def read_opaque(data, offset):
    length, offset = read_u32(data, offset)
    end = offset + length
    if end > len(data):
        raise RuntimeError("truncated RPC opaque value")
    return data[offset:end], end + ((-length) % 4)


class RpcClient:
    def __init__(self, host, port):
        self.socket = socket.create_connection((host, port), timeout=10)
        self.socket.settimeout(10)
        self.xid = 1000

    def close(self):
        self.socket.close()

    def receive_exact(self, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = self.socket.recv(remaining)
            if not chunk:
                raise RuntimeError("RPC connection closed during reply")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def receive_record(self):
        fragments = []
        while True:
            marker = struct.unpack(">I", self.receive_exact(4))[0]
            fragments.append(self.receive_exact(marker & 0x7FFFFFFF))
            if marker & 0x80000000:
                return b"".join(fragments)

    def call(self, program, version, procedure, arguments=b""):
        self.xid += 1
        body = b"".join(
            [
                u32(self.xid),
                u32(0),
                u32(2),
                u32(program),
                u32(version),
                u32(procedure),
                u32(0),
                u32(0),
                u32(0),
                u32(0),
                arguments,
            ]
        )
        self.socket.sendall(u32(0x80000000 | len(body)) + body)
        reply = self.receive_record()
        offset = 0
        xid, offset = read_u32(reply, offset)
        message_type, offset = read_u32(reply, offset)
        reply_status, offset = read_u32(reply, offset)
        if xid != self.xid or message_type != 1 or reply_status != 0:
            raise RuntimeError(f"invalid RPC reply header for procedure {procedure}")
        _verifier_flavor, offset = read_u32(reply, offset)
        _verifier, offset = read_opaque(reply, offset)
        accept_status, offset = read_u32(reply, offset)
        if accept_status != 0:
            raise RuntimeError(f"RPC procedure {procedure} failed with accept status {accept_status}")
        return reply[offset:]


def directory_operation(handle, name):
    return opaque(handle) + opaque(name)


def empty_set_attributes():
    return u32(0) * 6


def status(payload):
    value, _offset = read_u32(payload, 0)
    return value


def mount_root(client):
    mount_reply = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, opaque(b"/"))
    mount_status, offset = read_u32(mount_reply, 0)
    if mount_status != 0:
        raise RuntimeError(f"MOUNT returned status {mount_status}")
    root, _offset = read_opaque(mount_reply, offset)
    return root


def verify_read_only(client):
    root = mount_root(client)
    lookup = client.call(NFS_PROGRAM, NFS_VERSION, 3, directory_operation(root, b"file"))
    if status(lookup) != 0:
        raise RuntimeError(f"read-only LOOKUP returned status {status(lookup)}")
    file_handle, _offset = read_opaque(lookup, 4)
    handle = opaque(file_handle)
    mutations = [
        ("SETATTR", 2, handle + empty_set_attributes() + u32(0)),
        ("WRITE", 7, handle + u64(0) + u32(1) + u32(0) + opaque(b"x")),
        ("CREATE", 8, directory_operation(root, b"read-only-probe-file") + u32(0) + empty_set_attributes()),
        ("MKDIR", 9, directory_operation(root, b"read-only-probe-dir") + empty_set_attributes()),
        (
            "SYMLINK",
            10,
            directory_operation(root, b"read-only-probe-link") + empty_set_attributes() + opaque(b"file"),
        ),
        ("MKNOD", 11, directory_operation(root, b"read-only-probe-fifo") + u32(7) + empty_set_attributes()),
        ("REMOVE", 12, directory_operation(root, b"file")),
        ("RMDIR", 13, directory_operation(root, b"dir")),
        ("RENAME", 14, directory_operation(root, b"file") + directory_operation(root, b"renamed-file")),
        ("LINK", 15, handle + directory_operation(root, b"read-only-probe-hardlink")),
        ("COMMIT", 21, handle + u64(0) + u32(0)),
    ]
    for name, procedure, arguments in mutations:
        result = client.call(NFS_PROGRAM, NFS_VERSION, procedure, arguments)
        result_status = status(result)
        if result_status != 30:
            raise RuntimeError(f"read-only {name} returned status {result_status}, expected 30")
    print("verified read-only mutation statuses over NFSv3 wire")


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: procedure_probe.py SERVER_HOST SERVER_PORT [read-only]")
    client = RpcClient(sys.argv[1], int(sys.argv[2]))
    if len(sys.argv) == 4:
        if sys.argv[3] != "read-only":
            raise SystemExit(f"unknown probe profile: {sys.argv[3]}")
        try:
            verify_read_only(client)
        finally:
            client.close()
        return
    nfs_covered = set()
    mount_covered = set()
    try:
        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 0)
        mount_covered.add(0)
        mount_reply = client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, opaque(b"/"))
        mount_covered.add(1)
        status, offset = read_u32(mount_reply, 0)
        if status != 0:
            raise RuntimeError(f"MOUNT returned status {status}")
        root, _offset = read_opaque(mount_reply, offset)

        def nfs(procedure, arguments=b""):
            payload = client.call(NFS_PROGRAM, NFS_VERSION, procedure, arguments)
            if procedure != 0 and len(payload) < 4:
                raise RuntimeError(f"NFS procedure {procedure} returned a truncated result")
            nfs_covered.add(procedure)
            return payload

        handle = opaque(root)
        nfs(0)
        nfs(1, handle)
        nfs(2, handle + empty_set_attributes() + u32(0))
        nfs(3, directory_operation(root, b"file"))
        nfs(4, handle + u32(0x3F))
        nfs(5, handle)
        nfs(6, handle + u64(0) + u32(0))
        nfs(7, handle + u64(0) + u32(0) + u32(0) + opaque(b""))
        nfs(8, directory_operation(root, b"probe-file") + u32(0) + empty_set_attributes())
        nfs(9, directory_operation(root, b"probe-dir") + empty_set_attributes())
        nfs(
            10,
            directory_operation(root, b"probe-link") + empty_set_attributes() + opaque(b"probe-file"),
        )
        nfs(11, directory_operation(root, b"probe-fifo") + u32(7) + empty_set_attributes())
        nfs(
            14,
            directory_operation(root, b"probe-file") + directory_operation(root, b"probe-renamed"),
        )
        nfs(15, handle + directory_operation(root, b"probe-hardlink"))
        nfs(16, handle + u64(0) + bytes(8) + u32(4096))
        nfs(17, handle + u64(0) + bytes(8) + u32(4096) + u32(16384))
        nfs(18, handle)
        nfs(19, handle)
        nfs(20, handle)
        nfs(21, handle + u64(0) + u32(0))
        nfs(12, directory_operation(root, b"probe-renamed"))
        nfs(12, directory_operation(root, b"probe-link"))
        nfs(12, directory_operation(root, b"probe-fifo"))
        nfs(13, directory_operation(root, b"probe-dir"))

        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 2)
        mount_covered.add(2)
        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 5)
        mount_covered.add(5)
        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 3, opaque(b"/"))
        mount_covered.add(3)
        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 1, opaque(b"/"))
        client.call(MOUNT_PROGRAM, MOUNT_VERSION, 4)
        mount_covered.add(4)

        if nfs_covered != set(range(22)):
            raise RuntimeError(f"incomplete NFS procedure coverage: {sorted(nfs_covered)}")
        if mount_covered != set(range(6)):
            raise RuntimeError(f"incomplete MOUNT procedure coverage: {sorted(mount_covered)}")
        print("covered NFSv3 procedures 0-21 and MOUNTv3 procedures 0-5")
    finally:
        client.close()


if __name__ == "__main__":
    main()
