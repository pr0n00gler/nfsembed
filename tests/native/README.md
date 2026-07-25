# Native NFSv3 certification

`run_local.sh` launches the crate's persistent embedded certification
filesystem and mounts it with the Linux or macOS kernel NFSv3 client. The suite
verifies large reads, stable write data, post-create/rename/link namespace
state, a 512-entry multi-page directory, concurrent creates, reconnects, an
in-process server restart with rotated handles, graceful shutdown, a read-only
profile, case policy, and an explicit wire probe of all 22 NFSv3 and all six
MOUNTv3 procedure numbers. It requires passwordless privilege escalation for
mount operations.

```sh
./tests/native/run_local.sh
```

`run_windows.ps1` performs the corresponding same-host certification with
Microsoft Client for NFS. It starts the standalone TCP+UDP portmapper on port
111 and deliberately gives the Windows mount command no NFS or MOUNT port, so
the native discovery path is part of the test. Run it from an elevated
PowerShell session after installing Client for NFS:

```powershell
Install-WindowsFeature -Name NFS-Client
Set-Service -Name NfsClnt -StartupType Automatic
Start-Service -Name NfsClnt
.\tests\native\run_windows.ps1
```

The runner verifies that Client for NFS is configured for TCP (and attempts to
select it when necessary), because the crate intentionally does not implement
NFS-over-UDP.

The Windows profile covers discovery, 32 KiB transfer negotiation, a 2 MiB
read, multi-request writes, create/mkdir/rename/remove, 512-entry enumeration,
reconnect, restart, lost reply, read-only, and case-sensitive/case-insensitive
lookups. The direct wire probe supplements operations not exposed naturally by
the Windows shell.

An additional profile runs the mirror backend against a temporary NTFS
directory. It verifies preserved name spelling with case-folded lookup,
timestamps, the read-only attribute mapping, reserved-name rejection,
non-empty-directory errors, pagination, and reconnect persistence.

From macOS, the Linux-host/Linux-client cell can be exercised in the local
Docker VM with:

```sh
./tests/native/run_linux_container.sh
```

The macOS-server/Linux-client cross-host cell uses the Lima VM as the Linux
client host:

```sh
./tests/native/run_macos_server_linux_client_lima.sh
```

For cross-host runs, start `certification_server` on the server host and invoke
the client runner on the other operating system:

```sh
./tests/native/client.sh SERVER_ADDRESS SERVER_PORT
```

The `native-client.yml` workflow runs Linux, macOS, and Windows same-host cells
on every pull request and push. Local cross-host helpers remain available for
macOS-server/Linux-client and Linux-server/macOS-client coverage. Every native
cell runs read-write, restart, lost-reply, read-only, and case-policy profiles.
Exact replay assertions remain in `e2e_runtime.rs`, where the harness can close
a TCP connection at the precise RPC boundary.
