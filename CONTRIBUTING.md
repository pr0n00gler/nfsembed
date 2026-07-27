# Contributing

## Local execution policy

Docker Compose is the required local boundary for every Python, JavaScript, or
TypeScript script and test, including one-off maintenance, fixture, fuzz, and
reporting utilities. Do not add documentation, a Make recipe, or a shell
helper that launches one of those runtimes directly on a contributor's host.
Rust and shell-only work may run on the host.

The repository's supported local gates are:

```sh
make compose-config
make test
make check
make tooling-policy
```

The `tools` service runs Rust gates and XDR maintenance. The
`script-runner` service is the boundary used by scripts that need a scripting
runtime. Local native-test helpers route their wire probe through that service.

CI may run the same scripting commands directly after installing the pinned
dependencies. That exception is CI-only: container and direct-CI paths must use
the same versions, lockfiles, fixtures, and command arguments.

`make tooling-policy` runs a shell/Rust policy check over local entrypoints,
Make recipes, and contributor documentation. New scripting-language source
files must not be executable.

## Before submitting a change

Run the complete repository gate:

```sh
make check
```

For focused work, use the relevant containerized target:

```sh
make nfs4-fixtures
make test-gss
make check-xdr
```

`make check` covers formatting, strict Clippy, tests with the configured
features, rustdoc/package checks, the local tooling policy, and bounded fuzz
smoke sessions. Do not weaken a resource limit or remove an error-arm test to
make an interoperability suite pass; reconcile the result with the governing
RFC first.

## NFSv4 development rules

NFSv4 support is not release-claimed merely because an operation has a codec
or executor branch. Changes must preserve these invariants:

- Decode and validate the entire bounded COMPOUND before starting execution.
- Execute operations in order, stop at the first failure, and use only errors
  legal for that operation.
- Keep NFSv3 status mapping independent from NFSv4 status mapping.
- Never advertise an optional attribute or feature unless the export's VFS
  provides its required semantics.
- Do not hold a registry-wide state lock across a VFS or callback await.
- Reserve replay/state capacity before side effects. Once a mutation starts,
  its tracked completion and replay result must survive connection
  cancellation.
- Persist recoverable state before acknowledging a grant.
- Treat the local `rfc7530.txt` as a development reference. Only licensed XDR
  components, generated codecs, and derived conformance metadata belong in
  distributable sources.

Tests that need malformed or exact wire data should remain at the raw RPC/XDR
boundary. `tests/support/nfs4.rs` intentionally does not depend on internal
executor types.

## XDR generation

The authoritative NFSv4.0 XDR is RFC 7531. RPCSEC_GSS v2 XDR comes from RFC
5403. Their required Simplified BSD notices must remain next to vendored
components and generated output.

Regenerate and verify inside the tools container:

```sh
make generate-xdr
make check-xdr
```

`make check-xdr` performs regenerate-and-diff checks and runs the applicable
codec conformance tests. Review generated changes rather than editing generated
code to hide a mismatch.

## pynfs

The interoperability image checks out pynfs at the immutable commit recorded in
`tests/docker/pynfs.Dockerfile`. Its smoke test compiles the complete checkout
except for that revision's two unfinished, server-only NFSv4.0 modules; the
NFSv4.0 client and conformance runner do not use them. The smoke test also
loads the runner's command-line interface and does not require a server:

```sh
make pynfs-smoke
```

Run a selected NFSv4.0 suite against an available endpoint with:

```sh
make test-pynfs SERVER=host.docker.internal EXPORT=/ PYNFS_TESTS=all
```

The wrapper requests a machine-readable pynfs report and exits nonzero when
the selected suite reports a failure.

pynfs is a conformance aid, not the protocol specification. Classify each
failure against RFC 7530, RFC 7531, and verified errata. A passing subset is
not an NFSv4 release claim.

## Isolated Kerberos realm

The `kdc` service creates the test-only `NFSEMBED.TEST` realm and keytabs for
the server and client principals. It publishes no host ports and its
credentials are intentionally disposable. The image uses Heimdal with
canonical `EncASRepPart` encoding so the portable `sspi` decoder exercises its
strict Kerberos path.

```sh
make kdc-up
make kdc-status
make kdc-logs
make kdc-down
```

Never reuse the test principals, passwords, database, or keytabs outside the
isolated test environment. `make pynfs-with-kdc` combines that realm with the
containerized pynfs client:

```sh
make pynfs-with-kdc SERVER=host.docker.internal EXPORT=/ PYNFS_TESTS=all
```

`make test-gss` starts the isolated KDC, runs the RPCSEC_GSS unit/wire suite
and the ignored-by-default real-KDC test, and stops the KDC without deleting
its state. The real-KDC test must not be silently skipped: it establishes
portable `sspi` initiator/acceptor contexts for RPCSEC_GSS v1 and v2, checks
bidirectional MIC, integrity-only and privacy protection, rejects tampering,
and deletes the contexts. Full NFS `krb5`/`krb5i`/`krb5p`, replay, channel
binding, expiry, callbacks, `SECINFO`, and `WRONGSEC` remain separate mandatory
release gates.

## Durable recovery and multi-server testing

Durable tests must open an exclusive `StableScope` through a fenced fake or
production-equivalent store and start a fresh process for restart scenarios.
Cover clean and unclean restart, compare-and-swap conflicts, reclaim, handle
continuity, revocation, and persistent delegation state. An in-process
reinitialization is not a substitute for a crash-recovery test.

Migration tests must use distinct source and destination server instances and
exercise prepare, import, commit, and abort. The bundle transfers protocol
state and handle identity only. Tests must separately establish compatible
backend object identity and file-data placement.

Trunking tests must distinguish same-process shared state from cross-process
shared and fenced state. Common addresses, hostnames, or namespace locations do
not by themselves prove server identity.

## Native clients

Privileged native-client certification lives under `tests/native/`. Its
automated workload contains the NFSv3 regression matrix and a Linux/macOS
NFSv4.0 kernel-client baseline. The remaining NFSv4.0 profiles are release
gates and must not be reported as covered by the baseline.

Local Linux, macOS, and Windows helpers route their scripting-language probe
through Docker. CI is allowed to use its installed runtime directly. See
[tests/native/README.md](tests/native/README.md) for privileges, platform
coverage, and cross-host helpers.

## Updating pinned tooling

Base images are pinned by readable version and digest. pynfs, the Rust
toolchain, the nightly toolchain, fuzz tooling, and scripting dependencies are
also pinned. Update the Dockerfiles, `compose.yaml`, lockfiles, documentation,
and policy assertions together, then run:

```sh
make compose-config
make tooling-policy
make check
```
