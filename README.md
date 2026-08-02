# nfsembed

`nfsembed` is an embeddable Rust NFS server. The application owns the Tokio
runtime, TCP listeners, shutdown policy, backend storage, and operating-system
mounting; the library owns bounded RPC processing, protocol state, replay
handling, and authenticated filehandles.

Version 0.2.0 is a source-breaking architecture shared by NFSv3 and NFSv4.0.
Every server explicitly selects `ProtocolSet::V3`, `ProtocolSet::V4`, or
`ProtocolSet::V3AndV4`. NFSv3 remains supported.
Applications upgrading from an earlier release should follow
[MIGRATION.md](MIGRATION.md).

> **NFSv4.0 development status:** the repository contains the 0.2 protocol,
> state, recovery, RPCSEC_GSS, callback, delegation, location, and migration
> architecture. It does not claim complete RFC 7530 interoperability or a
> release-ready NFSv4.0 implementation until the acceptance gates in
> [Tests and release status](#tests-and-release-status) pass. In particular,
> full Kerberos interoperability, kernel-client, pynfs, recovery,
> delegation-race, and multi-server certification remain release gates. Select
> NFSv4 in production only after
> validating the exact capabilities and security modes your deployment uses.

This project is an independent fork of
[huggingface/nfsserve](https://github.com/huggingface/nfsserve), based on
upstream commit `c00c3614184bc79010c0aa3b69c2cdde1c5fca77`. It is not
API-compatible with or endorsed by that project.

The minimum supported Rust version is 1.96.

## Protocol and transport scope

- NFSv3 and NFSv4.0 server protocols over TCP.
- NFSv3 MOUNT and optional minimal portmapper v2 discovery. MOUNT is never
  exposed for an NFSv4-only server.
- NFSv4 `NULL` and `COMPOUND`, operations 3–39 and `ILLEGAL`, callback
  procedures, and attributes 0–55.
- `AUTH_NONE`, `AUTH_SYS`, and RPCSEC_GSS Kerberos services `krb5`, `krb5i`,
  and `krb5p`. RPCSEC_GSS uses the cross-platform Rust `sspi` provider rather
  than a host GSS library.
- Optional ACL, named-attribute, quota, delegation, persistent-filehandle,
  location, migration, and trunking behavior, advertised only when the export
  and server configuration provide the required semantics.

NFSv4.1 and later, NFS over UDP, SCTP, NLM, AUTH_DH, client APIs, mount
execution, privilege elevation, and process supervision are out of scope.
Portmapper may listen on TCP and UDP for discovery, but NFS traffic remains
TCP-only.

## Public server API

`NfsServer::builder` requires an explicit protocol set. Each export supplies a
stable `ExportId`, canonical pseudo-filesystem path, unique `FileSystemId`,
ordered `SecurityPolicy`, filehandle policy, and a VFS whose declared
capabilities are truthful.

```rust,ignore
use std::sync::Arc;

use nfsembed::{
    ExportConfig, ExportId, FileHandlePolicy, FileSystemId, Nfs4Config,
    NfsServer, NumericIdentityMapper, ProtocolSet, SecurityPolicy,
    ServerLimits, ServerSockets, VirtualFileSystem,
};
use tokio::net::TcpListener;

let vfs: Arc<dyn VirtualFileSystem> = application_vfs();

let export = ExportConfig::new(
    ExportId(1),
    "/data",
    FileSystemId::new(0x4e46_5345, 1),
    SecurityPolicy::auth_sys(),
    FileHandlePolicy::Volatile,
);

let nfs4 = Nfs4Config::in_memory(
    Arc::new(NumericIdentityMapper::new("example.test")),
    None,
);

let server = NfsServer::builder(ProtocolSet::V3AndV4)
    .add_export(export, vfs)
    .nfs4(nfs4)
    .limits(ServerLimits::default())
    .build()?;

let nfs = TcpListener::bind("127.0.0.1:0").await?;
let mount = TcpListener::bind("127.0.0.1:0").await?;
let sockets = ServerSockets::new(nfs).with_mount_listener(mount);
let handle = server.start(sockets).await?;

for endpoint in handle.endpoint_infos() {
    println!(
        "{:?} {} export={} nfs={} mount={:?}",
        endpoint.version,
        endpoint.address,
        endpoint.export_path,
        endpoint.nfs_port,
        endpoint.mount_port,
    );
}

handle.shutdown().await?;
handle.wait().await?;
```

Use `add_export_owned` for a statically typed backend. `ServerSockets` can hold
multiple caller-bound NFS TCP listeners with `with_nfs_listener`; all listeners
on one `NfsServer` share client, lease, replay, open, lock, and delegation
state. A dedicated MOUNTv3 listener is optional. `serve` accepts the same
socket bundle and an application-owned shutdown future when the caller wants
to own the top-level server future.

`EndpointInfo` is version-neutral and reports the protocol version, bound
address, export path, NFS port, and optional MOUNT port. Use
`NfsServerHandle::endpoint_infos` to inspect every listener/export endpoint.

### NFSv3-only configuration

NFSv3 does not require `Nfs4Config`:

```rust,ignore
let server = NfsServer::builder(ProtocolSet::V3)
    .add_export(
        ExportConfig::new(
            ExportId(1),
            "/",
            FileSystemId::new(0x4e46_5345, 1),
            SecurityPolicy::auth_sys(),
            FileHandlePolicy::Volatile,
        ),
        vfs,
    )
    .auth_policy(AuthPolicy::AuthSysOrAnonymous)
    .build()?;
```

`auth_policy` controls the legacy NFSv3 authentication choice. The ordered
per-export `SecurityPolicy` is also used to advertise MOUNT authentication
flavors. Minimal portmapper discovery can be attached with
`ServerSockets::with_portmapper`; the application must bind the portmapper
sockets itself.

## Unified VFS contract

Applications implement `VirtualFileSystem` for both protocol versions.
`RequestContext` includes the authenticated `Principal`, client address,
`ExportId`, `ProtocolVersion`, and an optional confirmed NFSv4 client ID.
`Principal::Gss` carries the canonical GSS identity, mechanism, exact
RPCSEC_GSS version, and negotiated service. The version is retained because an
NFSv4 callback must use the security flavor of the original `SETCLIENTID`.

The shared contract uses:

- `ObjectKey { file_id, generation }` for backend object identity;
- signed `NfsTime { seconds, nanos }`;
- authoritative monotonic `change_id` values and atomic `ChangeInfo`;
- atomic mutation results with NFSv4 `ChangeInfo` kept independent from
  optional NFSv3 WCC snapshots;
- explicit unstable/data-sync/file-sync write stability;
- opaque directory cookies and verifiers;
- canonical `NfsError` values independently mapped to legal NFSv3 and NFSv4
  statuses.

NFSv4 exports must override `nfs4_capabilities`. All NFSv4 exports require
`lookup_parent` and `authoritative_change_ids`. A read-write NFSv4 export also
requires atomic OPEN, retained access to pinned objects after unlink or
rename, and `durable_non_write_mutations`. The latter promises that every
successful non-WRITE mutation is stable before its future returns. The builder
rejects a backend that cannot provide these mandatory semantics.

Optional flags (`acls`, `named_attributes`, `quotas`, `delegations`,
`persistent_object_ids`, and `fs_locations`) must be enabled only when the
corresponding VFS methods are implemented with the documented atomicity and
durability. Unsupported optional attributes are omitted; they must not be
advertised with fabricated values. Authorization, including lookup/create/open
authorization, remains an atomic backend responsibility.

## NFSv4 namespace and recovery

Export paths form a synthetic NFSv4 pseudo-filesystem. Nested exports overlay
the trie and may have different ordered security policies. The default public
filehandle points at `/`; `Nfs4Config::with_public_filehandle_path` selects a
different canonical namespace path.

`Nfs4Config` has two explicit recovery modes:

- `Nfs4Config::in_memory` keeps state only for the running process. A restart
  rejects reclaim with `NFS4ERR_NO_GRACE`; persistent handles and persistent
  delegations are unavailable.
- `Nfs4Config::durable` uses an application-provided, exclusively fenced
  `StableStateStore`. The store must implement recovery, compare-and-swap
  commits, durable flush, and checkpoint semantics. Durable mode is required
  for reclaim, persistent filehandles, migration state continuity, and
  persistent delegations.

The default lease and grace durations are 90 seconds. The default callback
attempt timeout is five seconds. The server persists state that must survive a
crash before acknowledging the corresponding grant.

Choose a deployment-unique `StableScope`; do not let independent active
servers open the same scope unless they genuinely share fenced state and are
configured as one logical server identity.

## Security, callbacks, and delegations

An export's `SecurityPolicy` is ordered. `SECINFO` preserves that order and
namespace traversal enforces the selected flavor. Kerberos policies require
`Nfs4Config::with_kerberos_credentials`, using either a service keytab path or
keytab bytes. The RPCSEC_GSS implementation maintains bounded context and
sequence windows, verifies MICs, supports privacy wrapping, and rejects
replays. Channel protection additionally requires a
`ChannelBindingProvider` for the already-secured lower-layer connection.

Delegations are disabled by default. Enabling
`DelegationPolicy::Conservative` requires:

- a `CallbackConnector`;
- a backend that truthfully declares delegation support;
- a callback path successfully probed with `CB_NULL`;
- backend eligibility and, for write delegations, space reservation;
- durable fenced recovery plus stable object identities when `persistent` is
  true.

Callbacks use client-selected authentication. Recall attempts are bounded by
the configured per-attempt timeout and continue according to lease policy.
Real-KDC service levels, authenticated callbacks, tamper/replay behavior, and
delegation conflicts are mandatory release tests, not optional evidence.

## Locations, migration, and trunking

`Nfs4FsLocations` and VFS location state describe present, replicated, absent,
or moved filesystems. Applications own placement decisions and file-data
replication.

When configured with a `MigrationCoordinator`, `NfsServerHandle` exposes
`prepare_migration`, `import_migration`, `commit_migration`, and
`abort_migration`. Migration is fenced and two-phase: quiesce and drain the
source, transfer a bounded versioned protocol-state bundle, validate and stage
it at the destination, then commit or abort. A `MigrationBundle` contains
protocol state and handle identity, never file contents. Source and destination
backends must agree on fsid and persistent object identity.

Endpoints are trunked across processes only when explicitly configured with
the same persistent server identity and genuinely shared, exclusively fenced
state. Matching addresses or DNS names alone never establish trunking.

## Resource bounds and lifecycle

`ServerLimits` and `Nfs4Limits` bound connections, in-flight work, RPC records,
fragments, request/reply memory, replay state, COMPOUND operations, attributes,
state tables, callbacks, and transfer sizes. The server fully decodes and
validates a bounded COMPOUND before executing it, executes operations in order,
and stops at the first failure.

Mutating VFS work that has begun is completed in tracked server work even if a
connection disappears, so backends must provide the requested durability and
must not detach untracked side effects. No registry-wide lock is held across a
VFS await.

The crate does not install a runtime, signal handler, logger, metrics exporter,
or daemon. Dropping or shutting down `NfsServerHandle` stops all listeners
owned by that server instance.

## Tests and release status

Local repository gates use Docker Compose:

```sh
make test
make check
make nfs4-fixtures
make test-gss
make test-pynfs SERVER=host.docker.internal EXPORT=/
```

`make test-gss` automatically starts the isolated test KDC and requires the
portable RPCSEC_GSS v1/v2 initiator/acceptor integration test to pass before it
stops the KDC.

Every local Python, JavaScript, or TypeScript script and test must run inside a
Docker container. This applies to existing and future tooling. CI may execute
the same pinned commands directly on its runner. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [tests/README.md](tests/README.md).

NFSv4.0 release acceptance requires exact wire coverage for every operation
and callback, legal-error coverage, attributes 0–55, state/replay model tests,
fresh-process durable recovery, all three Kerberos service levels, callback
and delegation races, pynfs, Linux/macOS mounts, Windows-hosted wire testing,
multi-server migration/trunking tests, adversarial resource-limit tests, and no
NFSv3 regressions. Until those gates pass, the presence of a module or wire
codec is not a conformance claim.

The native-client harness keeps the full NFSv3 regression gate and adds a
Linux/macOS NFSv4.0 kernel-client baseline. See
[tests/native/README.md](tests/native/README.md) for that baseline's exact
coverage and the still-pending NFSv4 release matrix.

## Source layout

- `src/server/`: protocol selection, configuration, socket lifecycle,
  connection processing, endpoints, and migration control.
- `src/rpc/`: bounded XDR/RPC records, segmented replies, authentication, and
  RPCSEC_GSS.
- `src/nfs3/`, `src/mount3/`, `src/portmap/`: NFSv3 and discovery protocols.
- `src/nfs4/`: NFSv4 codecs, COMPOUND execution, namespace, attributes,
  state/recovery, callbacks, delegations, and locations.
- `src/vfs/`: the version-neutral backend contract and durable-state,
  identity-mapping, and migration extension points.
- `src/replay/`, `src/handles/`: duplicate-request handling and authenticated
  volatile/persistent handles.
- `vendor/xdr/`: licensed authoritative XDR source components.

## Specifications

- [RFC 1813](https://www.rfc-editor.org/rfc/rfc1813): NFSv3 and MOUNTv3
- [RFC 7530](https://www.rfc-editor.org/rfc/rfc7530): NFSv4.0 protocol
- [RFC 7531](https://www.rfc-editor.org/rfc/rfc7531): NFSv4.0 XDR
- [RFC 2203](https://www.rfc-editor.org/rfc/rfc2203) and
  [RFC 5403](https://www.rfc-editor.org/rfc/rfc5403): RPCSEC_GSS
- [RFC 7931](https://www.rfc-editor.org/rfc/rfc7931): NFSv4.0 migration
- [RFC 8587](https://www.rfc-editor.org/rfc/rfc8587): NFS multi-server
  namespace and trunking

The local `rfc7530.txt` is a development reference. Generated Rust codecs and
licensed XDR components are maintained with `make generate-xdr` and verified
with `make check-xdr`.
