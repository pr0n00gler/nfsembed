Embedded Rust NFSv3 Server
==========================

`nfsserve` is an embeddable NFSv3-over-TCP server driven by an
application-provided virtual filesystem. The application owns the Tokio
runtime, listener, process lifecycle, signal handling, and operating-system
mount execution.

> Note: this is a fork of https://github.com/huggingface/nfsserve project with more tests + a lot of improvements.

The production target is native Linux and macOS NFSv3 clients using:

```text
vers=3,tcp,port=<port>,mountport=<port>
```

Usage
=====

Implement `vfs::VirtualFileSystem`, then construct a server without creating a
runtime or binding a socket inside the library:

```rust,ignore
use nfsserve::{AuthPolicy, NfsServer, ServerLimits};
use tokio::net::TcpListener;

let server = NfsServer::builder(vfs)
    .export_name("virtual-fs")
    .limits(ServerLimits::production_defaults())
    .auth_policy(AuthPolicy::AuthSys)
    .build()?;

let listener = TcpListener::bind("127.0.0.1:0").await?;
let handle = server.start(listener).await?;
let mount_info = handle.mount_info();

// The embedding application performs the OS mount.

handle.shutdown().await?;
handle.wait().await?;
```

Applications that want complete task ownership can use
`server.serve(listener, shutdown_signal).await` instead.

The VFS receives a `RequestContext` containing the authenticated principal,
client address, and export ID. Object keys are wrapped in server-instance and
export-scoped authenticated file handles; backends never parse raw NFS handles.
Additional independent exports can be added with
`NfsServerBuilder::add_export`; `ServerHandle::mount_infos` reports the bound
mount data for every configured export.

Scope
=====

The crate implements NFSv3 and MOUNTv3 over TCP. Optional minimal portmapper
support is disabled by default. NFSv4, UDP, NLM, ACL side protocols,
RPCSEC_GSS, mount execution, privilege elevation, and process lifecycle are
outside its scope. Backend operations that are unavailable return the NFS-level
`NFS3ERR_NOTSUPP` result.

End-to-end tests
================

The repository includes a public-API TCP certification harness covering every
NFSv3 procedure, MOUNTv3, replay, authentication, limits, lifecycle,
adversarial inputs, observability, strict documentation and package builds, and
cargo-fuzz smoke sessions. Run the full CI gate with:

```sh
./tests/run_ci.sh
```

See [`tests/README.md`](tests/README.md) for the coverage matrix and the
network-disabled Linux container command. Privileged Linux/macOS native-client
and automatically coordinated cross-host runners live under
[`tests/native`](tests/native). Their persistent certification filesystem
verifies mutation state, pagination, reconnect, restart, concurrency,
read-only behavior, and case policy through real kernel clients.

Relevant RFCs
=============
 - XDR is the message format: RFC 1014. https://datatracker.ietf.org/doc/html/rfc1014
 - SUN RPC is the RPC wire format: RFC 1057 https://datatracker.ietf.org/doc/html/rfc1057
 - NFS is at RFC 1813 https://datatracker.ietf.org/doc/html/rfc1813
 - NFS Mount Protocol is at RFC 1813 Appendix I. https://datatracker.ietf.org/doc/html/rfc1813#appendix-I
 - PortMapper is at RFC 1057 Appendix A https://datatracker.ietf.org/doc/html/rfc1057#appendix-A

Basic Source Layout
===================

 - `server/`: builder, transport-aware limits, lifecycle handle, deadline-bound VFS execution, and byte-budgeted connection tasks.
 - `rpc/`: bounded XDR primitives, authentication, and TCP record marking.
 - `nfs3/`: NFSv3 types, procedure identities, and codec surface.
 - `mount3/`: MOUNTv3 types and export matching.
 - `portmap/`: optional minimal portmapper support.
 - `vfs/`: request context, object and mutation types, and the VFS contract.
 - `replay/`: count-, byte-, TTL-, and XID-generation-bounded duplicate-request reply cache.
 - `handles/`: authenticated, instance-scoped file-handle encoding.

The pre-1.0 implementation remains available only to the `demo` feature for
example migration.


More More Details Than Necessary
================================
The basic way a message works is:
1. We read a collection of fragments off a TCP stream 
(a 4 byte length header followed by a bunch of bytes)
2. We assemble the fragments into a record
3. The Record is of a SUN RPC message type.
4. A message tells us 3 pieces of information,
     - The RPC Program (just an integer denoting
      a protocol "class". For instance NFS protocol is 100003, the Portmapper protocol is 100000).
     - The version of the RPC program (ex: 3 = NFSv3, 4 = NFSv4, etc)
     - The method invoked (Which NFS method to call) (See for instance nfs.rs top comment for the list)
5. Continuing to decode the message will give us the arguments of the method
6. And we take the method response, wrap it around a record and return it. 

Portmapper
----------
First, lets get portmapper out of the way. This is a *very* old mechanism which
is rarely used anymore. The portmapper is a daemon which runs on a machine running
on port 111. When NFS, or other RPC services start, they register with the 
portmapper service with the port they are listening on (Say NFS on 2049). 
Then when another machine wants to connect to NFS, they first ask the port mapper
on 111 to ask about which port NFS is listening on, then connects to the returned 
port.

We do not strictly need to implement this protocol as this is pretty much
unused these days (NFSv4 does not use the portmapper for instance). If `-o port` and `-o mountport`
are specified, Linux and Mac's builtin NFS client do not need it either.
But this was useful for debugging and testing as libnfs seems to require a
portmapper, but it annoyingly hardcodes it to 111. I modified the source to
change it to 12000 for testing and implemented the one `PMAPPROC_GETPORT`
method so I can test with libnfs.


NFS Basics
==========
The way NFS works is that every file system object (dir/file/symlink) has 2
ways in which it can be addressed:

1. `fileid3: u64` . A 64-bit integer. Equivalent to an inode number.
2. `nfs_fh3`: A variable opaque object up to 64 bytes long.

Basically anytime the client tries to access any information about an object,
it needs an `nfs_fh3`. The purpose of the `nfs_fh3` serves 2 purposes:

 - Allow server to cache additional query information in the handle that may exceed
 64-bit. For instance if the server has multiple exports on different disk volumes,
 I may need a few more bits to identify the disk volume.
 - Allow client to identify when server has "restarted" and thus client has to
 clear all caches. the `nfs_fh3` handle should contain a token that is unique
 to when the NFS server first started up which allows the server to check that
 the handle is still valid. If the server has restarted, all previous handles
 will therefore be "expired" and any usage of them should trigger a handle expiry
 error informing the clients to expunge all caches.


However, the only way to obtain an `nfs_fh3` for a file is via directory traversal.
i.e. There is a lookup method 
`LOOKUP(directory's handle, filename of file/dir in directory)` 
which returns the handle for the filename.

For instance to get the handle of a file "dir/a.txt", I first need the handle
for the directory "dir/", then query `LOOKUP(handle, "a.txt")`.

The question is then, how do I get my first handle? That is what the MOUNT
protocol addresses.

Mount
-----
The MOUNT protocol provides a list of "exports", (in the simplest case. Just "/")
and the client will request to MNT("/") which will return the handle of this 
root directory.

The server maintains a bounded mount table per instance and implements `MNT`,
`DUMP`, `UMNT`, `UMNTALL`, and `EXPORT`. Unmount procedures return the void
MOUNTv3 result required by the protocol.

NFS
---
The NFS protocol itself is pretty straightforward with most annoyances
due to handling of the XDR messaging format (in paticular with optional,
lists, etc).

What is nice is that the design of NFS is completely stateless. It is mostly
sit down and implement all the methods that are hit and test them against a 
client.
