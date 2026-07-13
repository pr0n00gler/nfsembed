Embedded Rust NFSv3 Server
==========================

`nfsserve` is an embeddable NFSv3-over-TCP server driven by an
application-provided virtual filesystem. The application owns the Tokio
runtime, listener, process lifecycle, signal handling, and operating-system
mount execution.

The production target is native Linux and macOS NFSv3 clients using:

```text
vers=3,tcp,port=<port>,mountport=<port>
```

> Note: this is a fork of https://github.com/huggingface/nfsserve project with more tests + a lot of improvements.

What changed in the fork
===================

The fork is a breaking, production-oriented refactor of the original `nfsserve` crate.
It preserves the useful protocol definitions and interoperability knowledge,
but replaces the public server lifecycle, VFS contract, wire codec, transport,
retransmission handling, file handles, and test strategy. It is an evolution of
the existing crate rather than a clean-room rewrite.

The high-level API changes are:

| original | fork | Why it changed |
| --- | --- | --- |
| Implement `NFSFileSystem` | Implement `VirtualFileSystem` | The backend can now express identity, atomic mutations, write durability, directory cookies, and all NFSv3 procedures. |
| Create an `NFSTcpListener` that owns its listener and runs forever | Give an application-owned `TcpListener` to `NfsServer::start` or `NfsServer::serve` | The embedding application owns the Tokio runtime, sockets, task placement, shutdown signal, and process lifecycle. |
| Identify backend objects with a bare integer | Return an `ObjectKey { file_id, generation }` | Reused backend IDs can be distinguished and protected inside authenticated NFS handles. |
| Return operation-specific values and let handlers fetch attributes separately | Return `MutationResult<T>` with atomic before/after WCC data | NFS weak-cache-consistency replies no longer race separate `getattr` calls. |
| Treat duplicate XIDs as requests to drop | Wait for or replay the original encoded reply | Client retransmissions now have correct at-most-once behavior for mutations. |
| Keep the host-filesystem demo in the main API | Keep it behind the non-default `demo` feature | The production contract is platform-neutral and does not define policy through a sample host backend. |

Embedded lifecycle
------------------

`NfsServer`, `NfsServerBuilder`, `ServerHandle`, and `MountInfo` replace the old
run-forever listener API. The refactored lifecycle provides:

* `start(listener)` for a managed server task and `serve(listener, signal)` for
  callers that want to own the server future;
* idempotent shutdown and waitable termination;
* a configurable graceful-shutdown deadline;
* cancellation and joining of connection and request tasks;
* the actual bound address and ports, including listeners bound to port zero;
* typed startup and fatal server errors without `process::exit`;
* multiple independent server instances and multiple exports in one process;
* no global Tokio runtime, signal handler, logger, metrics exporter, file-handle
  generation, or replay state.

The library still does not mount filesystems, elevate privileges, install
signals, or manage a daemon. Those remain responsibilities of the embedding
application.

Virtual filesystem contract
---------------------------

The new `VirtualFileSystem` trait is a complete NFSv3 backend boundary:

* Every permission-sensitive operation receives a `RequestContext` containing
  the authenticated `Principal`, client address, and `ExportId`.
* AUTH_SYS exposes UID, primary GID, supplementary groups, and the machine name;
  anonymous access remains an explicit policy choice.
* `ObjectKey` separates backend identity from the opaque NFS file handle.
* `MutationResult<T>` carries atomic before/after weak-cache-consistency data.
* `CreateMode` represents unchecked, guarded, and exclusive creation, including
  the exclusive verifier.
* `WriteStability`, `WriteResult`, and `commit` represent unstable, data-sync,
  and file-sync durability without claiming stronger persistence than the
  backend achieved.
* Directory enumeration uses opaque cookies and verifiers. The backend returns
  a page, while the protocol layer performs exact XDR-size truncation.
* `fsstat`, `fsinfo`, and `pathconf` values come from the backend and are clamped
  to what the configured RPC transport can actually carry.
* Read-only capability is enforced consistently across data and namespace
  mutations. Unsupported operations return `NFS3ERR_NOTSUPP` instead of RPC
  `PROC_UNAVAIL`.
* Request futures are cancelled at the configured deadline. Backend mutations
  must therefore be cancellation-safe and must not detach untracked work.

The trait covers `GETATTR`, `SETATTR`, `LOOKUP`, `ACCESS`, `READLINK`, `READ`,
`WRITE`, `CREATE`, `MKDIR`, `SYMLINK`, `MKNOD`, `REMOVE`, `RMDIR`, `RENAME`,
`LINK`, `READDIR`, `READDIRPLUS`, `FSSTAT`, `FSINFO`, `PATHCONF`, and `COMMIT`.

Typed and bounded protocol implementation
-----------------------------------------

The manual response-building paths were replaced with typed NFSv3 and MOUNTv3
argument/result unions. A handler constructs one complete result and the codec
encodes it once, including every legal success and failure arm. This removes
the malformed partial-response paths that existed around WCC data, attributes,
MOUNT replies, and several error branches.

The new RPC/XDR layer:

* bounds records, fragments, fragment counts, opaque fields, strings, arrays,
  AUTH_SYS groups, file handles, names, symlink targets, and transfer sizes;
* reserves aggregate memory before allocating record or reply bodies;
* uses checked arithmetic and rejects trailing or truncated arguments;
* rejects non-canonical booleans and invalid enum/union discriminants;
* returns decoding errors instead of allocating from unchecked wire lengths or
  panicking on network-controlled input;
* correctly emits RPC version/program/procedure mismatch ranges, authentication
  failures, garbage-argument replies, and `SYSTEM_ERR`.

All 22 NFSv3 procedures and all six MOUNTv3 procedures are implemented. MOUNT
uses a bounded per-server mount table and component-aware export matching.
Minimal portmapper `GETPORT` support is optional and disabled by default; it
returns zero for unsupported program/version/transport combinations and never
registers with the operating-system portmapper.

Resource hardening and request deadlines
----------------------------------------

`ServerLimits` makes resource policy explicit. It bounds connections,
per-connection queued requests, global in-flight executions, RPC record and
fragment sizes, aggregate request and reply buffers, replay entries and bytes,
mount-table entries, transfer sizes, and directory responses.

The connection path now uses bounded channels and semaphores rather than
unrestricted spawning. One absolute request deadline covers queueing, reply
budget acquisition, replay waiting, execution capacity, and the VFS future.
Idle reads and socket write progress have independent limits. Slow readers are
disconnected, completed connection tasks are reaped, and buffer permits remain
owned by detached tracked executions until their request/reply memory is gone.
No server lock is held while awaiting application VFS code.

Replay and file-handle safety
-----------------------------

The old seen-XID tracker was replaced by a per-server reply cache. Its request
fingerprint includes program, version, procedure, principal identity, and a
digest of the arguments. Exact in-flight duplicates wait; exact completed
duplicates receive the cached bytes; a changed fingerprint is treated as XID
reuse. Concurrent XID generations, cancellation, lost socket replies, capacity,
TTL, and retained reply bytes are all handled explicitly.

NFS file handles now contain a format version, server-instance identity, export
identity, backend file ID, backend generation, and keyed integrity tag while
remaining within the 64-byte NFSv3 limit. Forged handles, cross-export handles,
and handles from a previous server start are rejected before reaching the VFS.
The server-instance write verifier also changes across restarts.

Observability and certification
-------------------------------

The production path emits `tracing` spans/events for procedure, XID, client,
duration, protocol status, byte counts, replay decisions, rejection reasons,
timeouts, cancellations, and active resource counts. It never installs a
subscriber and avoids logging file data, raw authentication buffers, complete
packets, or pathnames at normal levels.

The test suite was expanded from basic behavior checks into release gates:

* public-API TCP tests cover every NFSv3 and MOUNTv3 procedure, every result
  union, AUTH_SYS, WCC, durability, pagination, replay, handles, lifecycle,
  limits, observability, and multiple exports;
* adversarial suites sweep fragmentation, truncated inputs, field limits,
  invalid discriminants, forged handles, directory response sizes, slow
  readers, connection churn, and bounded-memory/concurrency behavior;
* seven cargo-fuzz targets exercise RPC/XDR, authentication, record marking,
  handles, WRITE, READDIR/READDIRPLUS, and replay transitions;
* Linux and macOS kernel clients run read-write, restart, lost-reply, read-only,
  and case-policy profiles, with same-host and cross-host CI runners;
* CI checks formatting, strict Clippy, tests with default and all features,
  rustdoc warnings, crate packaging, an older supported Rust toolchain, fuzz
  smoke sessions, and native interoperability.

Migration checklist
-------------------

Applications moving from the original `nfsserve` version should:

1. Replace `NFSFileSystem` with `VirtualFileSystem` and use `ObjectKey` rather
   than exposing raw numeric IDs as NFS handles.
2. Update mutations to return `MutationResult<T>` atomically and implement the
   requested create, write-stability, `COMMIT`, cookie/verifier, and filesystem
   information semantics that the backend supports.
3. Make authorization decisions from `RequestContext` and select an explicit
   `AuthPolicy`.
4. Construct `NfsServer` with the desired exports and `ServerLimits`, bind a
   Tokio `TcpListener` in the application, then call `start` or `serve`.
5. Use `MountInfo` to construct the platform mount command; do not expect the
   library to mount, elevate privileges, or manage signals.
6. Make backend futures cancellation-safe because the server drops them when
   the request deadline expires.
7. Keep using the old demo API only temporarily with `--features demo`; there
   is no automatic adapter from `NFSFileSystem` to the production VFS contract.

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

Performance benchmarks
======================

Criterion benchmarks cover large RPC opaque values, zero-copy WRITE decoding,
segmented READ reply assembly and replay cloning, fragmented record I/O,
READDIR response truncation, full replay-cache hits, and authenticated
file-handle encoding and verification. Run them with:

```sh
cargo bench --bench performance
```

To compare a change against a saved local baseline:

```sh
cargo bench --bench performance -- --save-baseline before
cargo bench --bench performance -- --baseline before
```

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
