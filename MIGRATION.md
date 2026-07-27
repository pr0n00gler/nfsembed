# Migrating to nfsembed 0.2.0

Version 0.2.0 is intentionally source-breaking. It replaces version-specific
server entrypoints with one architecture shared by NFSv3 and NFSv4.0. There is
no automatic adapter for the old filesystem trait or server builder.

This guide describes API migration. It is not an NFSv4 conformance claim; see
[README.md](README.md#tests-and-release-status) for the remaining release
gates.

## 1. Select protocols explicitly

The old builder inferred NFSv3 from its entrypoint. The new builder's first
argument is mandatory:

```rust,ignore
let server = NfsServer::builder(ProtocolSet::V3)
    // exports and limits
    .build()?;
```

Choose exactly one of:

- `ProtocolSet::V3`
- `ProtocolSet::V4`
- `ProtocolSet::V3AndV4`

There is no default. A selection containing NFSv4 requires `.nfs4(...)`;
supplying `Nfs4Config` to a v3-only builder is rejected.

## 2. Replace implicit export configuration

Each backend is registered with `ExportConfig`:

```rust,ignore
let export = ExportConfig::new(
    ExportId(7),
    "/projects",
    FileSystemId::new(0x4e46_5345, 7),
    SecurityPolicy::auth_sys(),
    FileHandlePolicy::Volatile,
);

let server = NfsServer::builder(ProtocolSet::V3)
    .add_export(export, Arc::new(vfs))
    .build()?;
```

Replace old export-name or path builder calls with one configuration per
backend. Within one server, export IDs, paths, and fsids must be unique. NFSv4
paths are canonical absolute pseudo-filesystem paths; nested paths form
overlays in the synthetic namespace.

The constructor deliberately has no derived fsid or policy defaults. Choose
and persist every identity and policy deliberately, including in development,
so a later deployment cannot silently change wire-visible identity,
authentication ordering, or filehandle lifetime.

## 3. Pass a socket bundle

`start` and `serve` now consume `ServerSockets`, not a bare listener:

```rust,ignore
let nfs = TcpListener::bind("0.0.0.0:2049").await?;
let sockets = ServerSockets::new(nfs);
let handle = server.start(sockets).await?;
```

Add another NFS endpoint with `with_nfs_listener`. All NFS listeners in the
bundle share server state.

For v3, attach an optional dedicated MOUNT TCP listener with
`with_mount_listener` and optional caller-bound portmapper sockets with
`with_portmapper`. MOUNT is not accepted for an NFSv4-only server. The
application still owns socket binding, privileged ports, runtime, signals,
mount commands, and process lifecycle.

Use `handle.endpoint_infos()` to discover bound endpoints. `EndpointInfo`
replaces version-specific mount metadata and contains `version`, `address`,
`export_path`, `nfs_port`, and `mount_port`.

Version 0.2 does not retain compatibility shims for the replaced entrypoints:

- Replace `ServerHandle` with `NfsServerHandle`.
- Replace builder `.nfs4_config(config)` with `.nfs4(config)`.
- Replace builder `.portmapper(...)`, `start_with_portmapper`, and
  `serve_with_portmapper` with caller-owned `PortmapperSockets` attached via
  `ServerSockets::with_portmapper`.
- Replace endpoint `.server_addr` with `.address`.
- Replace `MountInfo`, `mount_info`, `mount_infos`, and `endpoints` with
  `EndpointInfo` and `endpoint_infos`.

## 4. Update the VFS implementation

`VirtualFileSystem` is now the version-neutral backend contract. Existing
NFSv3 backends can migrate first by returning `None` from
`nfs4_capabilities` (the default), then add NFSv4 semantics separately.

Review every implementation for these contract changes:

- `RequestContext` now includes `protocol` and optional NFSv4 `client_id` in
  addition to principal, client address, and export ID.
- `Principal` includes
  `Gss { canonical_name, mechanism, version, service }`; match with `..` when
  the backend does not need RPCSEC_GSS version-specific policy.
- `NfsTime.seconds` is signed and nanoseconds must be in the valid wire range.
- Backend change values are monotonic `ChangeId`s. Namespace mutations set
  `MutationResult::change_info` explicitly to authoritative
  `ChangeInfo { before, after, atomic }`; NFSv3 WCC `before`/`after` snapshots
  are independent and must not be used to infer NFSv4 atomicity.
- WRITE reports the durability actually reached; COMMIT remains explicit.
- Successful non-WRITE mutations on read-write NFSv4 exports are durable
  before return and advertise `durable_non_write_mutations`.
- Canonical `NfsError` values are mapped independently to each protocol's
  legal status set.
- Permission-sensitive lookup, create, and OPEN decisions remain atomic
  backend operations.

A read-only NFSv4 backend must provide `lookup_parent` and authoritative change
IDs. A read-write backend must additionally implement atomic `nfs4_open`,
`retain_open_object`, and `release_open_object`, preserving access to pinned
objects after unlink or rename, and promise durable non-WRITE mutations.
`Nfs4OpenRequest::access` carries the read/write access that `nfs4_open` must
authorize in that same atomic operation; share-deny reservations remain
server-managed protocol state.

Optional VFS capabilities are promises:

| Capability | Required backend behavior |
| --- | --- |
| `acls` | Canonical ACL reads plus atomic ACL inheritance/mode synchronization |
| `named_attributes` | Named-attribute directory objects and ordinary object operations on them |
| `quotas` | Truthful quota values for the addressed filesystem/object |
| `delegations` | Atomic eligibility checks and write-space reservation/release |
| `persistent_object_ids` | Stable object identity and resolution across restart/migration |
| `fs_locations` | Present, replicated, absent, and moved location state |

Do not enable a flag while relying on a default `NotSupported` method.
Unsupported optional attributes are intentionally omitted.

## 5. Configure NFSv4 identity and recovery

An ephemeral configuration is explicit:

```rust,ignore
let nfs4 = Nfs4Config::in_memory(
    Arc::new(NumericIdentityMapper::new("example.test")),
    None,
);

let server = NfsServer::builder(ProtocolSet::V4)
    .add_export(export, Arc::new(vfs))
    .nfs4(nfs4)
    .build()?;
```

`InMemoryRejectReclaims` does not represent crash recovery. After restart it
rejects reclaim, changes boot-scoped handle identity, and cannot support
persistent delegations or persistent filehandles.

For reclaim and continuity, implement `StableStateStore` and use
`Nfs4Config::durable`. The store must:

- exclusively fence one `StableScope`;
- return a versioned recovery snapshot;
- atomically compare-and-swap batches;
- make acknowledged state durable;
- checkpoint without losing the fence.

Choose a stable scope per logical server. Persist store data, server/export
identity, and backend persistent object identity together. A persistent
filehandle policy without durable NFSv4 configuration is rejected.

Defaults are a 90-second lease, 90-second grace interval, five-second callback
attempt timeout, disabled delegations, and `/` as the public-filehandle path.
Override them with `Nfs4Config` methods only after considering client retry and
recovery behavior.

## 6. Move security policy to each export

For NFSv4, `SecurityPolicy` is an ordered list used by namespace traversal and
`SECINFO`. Configure `AUTH_NONE`, `AUTH_SYS`, and/or RPCSEC_GSS per export.
Nested export edges may change policy.

Any RPCSEC_GSS policy requires `KerberosCredentials` in `Nfs4Config`. Provide a
service principal and keytab path or keytab bytes. Integrity and privacy are
negotiated as the matching RPCSEC_GSS service. Channel protection additionally
requires an application `ChannelBindingProvider`.

The old NFSv3 `AuthPolicy` remains available for v3 requests. Do not mistake it
for NFSv4 per-edge security configuration.

## 7. Opt in to callbacks and delegations

Delegations are disabled unless `DelegationPolicy::Conservative` is selected.
Before enabling it:

1. Implement and configure `CallbackConnector`.
2. Declare VFS delegation support only after implementing atomic eligibility.
3. Implement delegated write-space reservation and release.
4. Decide bounded read/write delegation counts.
5. Use durable recovery and persistent object IDs if `persistent` is true.

Only clients with a successfully probed callback path are eligible. Deployment
acceptance must cover authenticated callbacks, recall retry, conflict delay,
return, expiry/revocation, crash recovery, and delegated size/change updates.

## 8. Add locations and migration deliberately

Namespace location reporting does not move file contents. The application
continues to own file-data replication and placement.

Implement `MigrationCoordinator` and pass it to `Nfs4Config` to enable
fenced migration control. The server handle then supports:

1. `prepare_migration` on the source;
2. transport of the returned bounded `MigrationBundle` by the application;
3. `import_migration` on the destination;
4. `commit_migration` on both coordinated halves, or `abort_migration`.

The bundle contains protocol state and handle identity, not file data. Source
and destination require compatible fsid, backend object identity, stable-store
schema, and lease policy.

Do not infer trunking from DNS or addresses. Cross-process endpoints are one
logical server only when explicitly configured with the same persistent
identity and genuinely shared, exclusively fenced state.

## 9. Revalidate resource and cancellation assumptions

Carry old limit customizations into `ServerLimits` and review the separate
`Nfs4Limits`. NFSv4 adds bounded COMPOUND decoding, attribute buffers, client
and owner state, opens, locks, replay records, callbacks, and delegations.

Once a mutating backend call starts, the server tracks it to completion and
caches/persists the result even when the connection is cancelled. Backend
methods must not detach untracked side effects and must honor their advertised
durability. Test lost replies and retransmission independently from NFSv4 owner
seqid replay.

## 10. Run the migration gates

All supported local commands route scripting-language tooling through Docker:

```sh
make tooling-policy
make test
make nfs4-fixtures
make test-gss
make check
```

If enabling NFSv4, also run the relevant pynfs, real-KDC, durable restart,
callback/delegation, native mount, and multi-server suites described in
[tests/README.md](tests/README.md). Passing the NFSv3 regression suite alone
does not validate an NFSv4 deployment.
