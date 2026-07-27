# Native-client certification

The native harness contains the NFSv3/MOUNTv3 regression gate and a
Linux/macOS NFSv4.0 kernel-client workload. The NFSv4 workload is a baseline,
not yet the complete release matrix described below.

## Current NFSv3 coverage

`run_local.sh` starts the persistent embedded certification filesystem and
mounts it with the Linux or macOS kernel NFSv3 client. It verifies:

- large reads and multi-request stable writes;
- create, mkdir, rename, link, remove, and post-operation namespace state;
- multi-page enumeration of a 512-entry directory;
- concurrent creates, reconnect, graceful shutdown, and in-process restart;
- rotated volatile handles after restart and lost-reply handling;
- read-only and case-policy profiles;
- an exact wire probe of all 22 NFSv3 and all six MOUNTv3 procedure numbers.

After the v3 profiles, the same runner starts a v4-only server and runs the
NFSv4.0 baseline described below.

Mounting and unmounting require the platform's normal elevated privileges.
Local runs also require Docker because the wire probe is a scripting-language
test and is routed through the digest-pinned `script-runner` service.

```sh
./tests/native/run_local.sh
```

The Linux-container helper runs the same client workload in the repository's
native image:

```sh
./tests/native/run_linux_container.sh
```

## Windows NFSv3 client

`run_windows.ps1` performs same-host certification with Microsoft Client for
NFS. It starts the standalone TCP/UDP portmapper on port 111 and deliberately
omits explicit NFS and MOUNT ports from the Windows mount, so discovery is part
of the test.

Run it from an elevated PowerShell session with Docker Desktop after installing
Client for NFS:

```powershell
Install-WindowsFeature -Name NFS-Client
Set-Service -Name NfsClnt -StartupType Automatic
Start-Service -Name NfsClnt
.\tests\native\run_windows.ps1
```

The runner verifies that Client for NFS uses TCP because NFS-over-UDP is out of
scope. Its profile covers discovery, 32 KiB transfer negotiation, a 2 MiB read,
multi-request writes, namespace changes, enumeration, reconnect, restart, lost
reply, read-only behavior, and case-sensitive/case-insensitive lookup. The
mirror profile additionally covers NTFS spelling, timestamp and read-only
mapping, reserved names, non-empty directories, pagination, and reconnect
persistence.

The local wire probe runs in Docker. CI may use the matching pinned runtime
installed by the workflow.

## Cross-host NFSv3 helpers

From macOS, run the Linux-host/Linux-client cell in the local Docker VM:

```sh
./tests/native/run_linux_container.sh
```

Use the Lima client for a macOS server and Linux client:

```sh
./tests/native/run_macos_server_linux_client_lima.sh
```

For a separately started certification server, invoke the client helper on the
other operating system:

```sh
./tests/native/client.sh SERVER_ADDRESS NFS_PORT PROFILE MOUNT_PORT
```

The native workflow runs Linux, macOS, and Windows same-host NFSv3 cells.
Cross-host helpers remain available for macOS-server/Linux-client and
Linux-server/macOS-client coverage.

## NFSv4.0 kernel-client baseline

`certification_server` reads `NFSEMBED_PROTOCOL` as `v3`, `v4`, or
`v3-and-v4`. The v4 selections install an explicit in-memory `Nfs4Config`,
numeric identity mapper, volatile filehandles, and AUTH_SYS security policy.
Its ready file contains the NFS port followed by the dedicated MOUNTv3 port
when v3 is enabled; v4-only mode reports only the NFS port.
For example, start a fixed-port v4-only server in one terminal:

```sh
NFSEMBED_PROTOCOL=v4 cargo run --locked --example certification_server -- \
  0.0.0.0:20490 /tmp/nfsembed-v4-ready /tmp/nfsembed-v4-shutdown read-write
```

Then run the kernel-client workload from Linux or macOS and stop the server:

```sh
./tests/native/client_nfs4.sh 127.0.0.1 20490
touch /tmp/nfsembed-v4-shutdown
```

The workload pins NFSv4.0 and TCP, traverses the pseudo-root export, exercises
large reads, OPEN/create, CLOSE, rename and unlink while open, hard links,
symbolic links, advisory byte-range locking when the platform lock utility is
available, READDIR pagination, and a disconnect/remount. Mounting and
unmounting require the platform's normal elevated privileges.

Run the same workload with `NFSEMBED_PROTOCOL=v3-and-v4` to certify shared
v3/v4 server state. The server logs the selected protocol, security flavor,
recovery mode, export, and capability profile.

## Required NFSv4.0 native matrix

The remaining NFSv4 release profiles stay separate from the NFSv3 runner:

- pseudo-root traversal, nested exports, `PUTROOTFH`, public-filehandle
  traversal, and per-edge security changes;
- stateful OPEN/CLOSE/LOCK behavior, restart grace and reclaim, unlink/rename
  while open, and lease expiry;
- `AUTH_SYS` plus real-KDC `krb5`, `krb5i`, and `krb5p`;
- callback probing, delegation recall/return/revocation, and restart recovery
  for persistent delegations;
- referrals and migration continuity between independent source and
  destination processes;
- a Windows-hosted server exercised by the complete wire suite and a
  cross-host Linux NFSv4.0 client.

Each new profile must report the selected protocol, security flavor, stable
recovery mode, export capabilities, and exact test subset. Until all required
cells pass, native NFSv3 results must not be presented as NFSv4 evidence.
