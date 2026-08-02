# Test and certification matrix

The test tree separates three kinds of evidence:

1. public-API NFSv3 regression tests;
2. NFSv4/RPCSEC_GSS unit, model, fuzz, and exact-wire tests;
3. external interoperability and privileged native-client certification.

Passing one layer does not imply that the others pass. In particular, the
presence of NFSv4 codecs and fixtures is not an RFC 7530 release claim.

## Current repository suites

| Suite | Coverage |
| --- | --- |
| `e2e_protocol.rs` | Successful public-wire results for all NFSv3 and MOUNTv3 procedures, AUTH_SYS context, WCC, create modes, write durability, cookies, and pagination |
| `e2e_errors.rs` | NFSv3 result-union failure shapes, truncation and trailing data, invalid discriminants, RPC mismatch ranges, field limits, and authentication policy |
| `e2e_runtime.rs` | Replay behavior, authenticated handle isolation, exports, portmapper, transport limits, request/reply budgets, timeouts, concurrency, lifecycle, reconnect, read-only, and case policy |
| `e2e_adversarial.rs` | Fragmentation, authentication prefixes, WRITE input shape, READDIR sizing, and handle-forgery corpora |
| `e2e_observability.rs` | Stable tracing fields/events and checks against sensitive payload leakage |
| `e2e_load.rs` | Sustained multi-connection load, completion and operation thresholds, and Linux RSS-growth bounds |
| `nfs4_fixtures.rs` | Server-independent golden NFSv4.0 RPC/COMPOUND envelopes, stateids, bitmaps, WRITE operands, bounds, and canonical padding |
| library unit/model tests | NFSv4 codecs and legal errors, pseudo-filesystem and attributes, stateids, owners, shares, locks, leases, stable journal, callbacks, delegations, locations, migration bundles, and RPCSEC_GSS |
| `tooling_policy.rs` and `check_local_tooling.sh` | Docker services, immutable tooling inputs, and prevention of host-side local scripting-runtime entrypoints |
| `fuzz/` | RPC/XDR, authentication, records, handles, WRITE, READDIR, replay, NFSv4 COMPOUND/callback, and RPCSEC_GSS targets |
| `native/` | Privileged NFSv3 kernel-client regressions plus a Linux/macOS NFSv4.0 baseline; see the remaining matrix below |

## Local commands

All supported local repository gates use digest-pinned Docker Compose services.
This also keeps scripting-language tests inside their required container
boundary.

```sh
make compose-config
make test
make nfs4-fixtures
make test-gss
make tooling-policy
make check
```

`make check` runs formatting, strict Clippy, configured feature tests,
rustdoc/package checks, tooling policy, and bounded fuzz smoke sessions. CI may
invoke `tests/run_ci.sh` directly after installing the pinned toolchains.

Every local Python, JavaScript, or TypeScript script and test must run inside a
Docker container. CI may execute the identical pinned command directly on its
runner. Do not turn the CI exception into a local shortcut.

## XDR conformance

RFC 7531 and RPCSEC_GSS v2 XDR components are regenerated and compared inside
the tools service:

```sh
make generate-xdr
make check-xdr
```

The checked-in generated Rust codecs and golden vectors must change together.
Malformed union, bitmap, array, UTF-8, and length cases belong next to the
successful vectors for the same type.

## pynfs

The pynfs image is pinned to the immutable commit in
`tests/docker/pynfs.Dockerfile`. Its validation compiles the complete checkout
except for the pinned revision's two unfinished, server-only NFSv4.0 modules;
the NFSv4.0 client and conformance runner do not use those modules. The smoke
test also loads the conformance runner's command-line interface. Build and
validate the client without a server:

The image applies the checked-in
`tests/docker/pynfs-lock24-rfc7530.patch` after verifying the immutable
revision. The upstream `LOCK24` case sends the new-lock-owner arm a second
time after byte-range locking state has already been established and expects
success. RFC 7530 section 16.10 instead requires `NFS4ERR_BAD_SEQID` except
for an exact replay, so the local patch corrects only that expectation and
keeps the server's owner sequencing conformant.

```sh
make pynfs-smoke
```

Run selected NFSv4.0 tests against an available endpoint:

```sh
make test-pynfs SERVER=host.docker.internal EXPORT=/ PYNFS_TESTS=all
```

The container converts pynfs's machine-readable failure count into its exit
status, so the Make target fails when any selected test fails.

The certification server accepts `NFSEMBED_CERT_LEASE_SECONDS` to shorten
lease-driven conformance cases without changing the library's 90-second
production default. Keep the grace interval equal to that test lease; the
example configures both together.

Record the server configuration, recovery mode, export capability set, and
security flavor with results. Resolve failures against the RFC and verified
errata; do not change legal errors or advertised capabilities merely to match a
client expectation.

## Kerberos

The private `NFSEMBED.TEST` realm is provided by the unexposed Heimdal `kdc`
service. It emits canonical `EncASRepPart` encoding for the portable `sspi`
decoder:

```sh
make kdc-up
make kdc-status
make test-gss
make kdc-down
```

`make test-gss` starts the KDC, runs the RPCSEC_GSS unit/wire suite and the
non-skippable real-KDC integration test, then stops the KDC without deleting
its state. The integration test establishes portable `sspi` initiator and
acceptor contexts for RPCSEC_GSS v1 and v2, checks bidirectional MICs,
integrity-only and privacy wraps, rejects tampered tokens, and deletes every
context.

For pynfs with a client ticket:

```sh
make pynfs-with-kdc SERVER=host.docker.internal EXPORT=/ PYNFS_TESTS=all
```

The unit and wire suite is only one layer. Release acceptance also requires
real-KDC establishment and continuation, `krb5`/`krb5i`/`krb5p`, tampering,
sequence replay, channel binding, context expiry, callback authentication,
`SECINFO`, and `WRONGSEC`.

## NFSv4.0 acceptance gaps

NFSv4.0 remains a development implementation until all of these are automated
and passing:

- exact successful and legal-error wire vectors for operations 3–39,
  `ILLEGAL`, both callbacks, and attributes 0–55;
- COMPOUND predecode, stop-on-error, minor-version, READDIR accounting, UTF-8,
  malformed union/bitmap/array, and RFC 7530 section 13.2 allowlist tests;
- state/replay model tests for seqid wrap, owner replay, special stateids,
  shares, lock splitting/merging, grace, lease expiry, unlink/rename while
  open, callback races, revocation, and capacity exhaustion;
- fresh-process clean/unclean recovery against a durable fenced store,
  including reclaim, handle continuity, and persistent delegations;
- all Kerberos service levels through the real test KDC;
- callback reachability, recall retry, conflict delay, delegated-space, and
  persistent-delegation recovery tests;
- referrals, replication locations, migration success/abort, source fencing,
  `MOVED`, handle/state continuity, and same-/cross-process trunking tests;
- pynfs, Linux and macOS NFSv4.0 mounts, and a Windows-hosted server exercised
  by the wire suite and a cross-host Linux client;
- adversarial load/fuzz assertions that every configured memory, state,
  callback, and COMPOUND limit is honored;
- all existing Linux, macOS, and Windows NFSv3 regressions.

Until that matrix passes, test reports should name the exact passing subset and
must not describe the crate as fully RFC 7530 conformant.

## Native clients

The current `tests/native/` harness certifies NFSv3/MOUNTv3 on Linux, macOS,
and Windows, including cross-host helpers, and runs a Linux/macOS NFSv4.0
kernel-client baseline. The baseline does not yet constitute the complete
NFSv4.0 native acceptance matrix. See [native/README.md](native/README.md) for
current coverage and prerequisites.
