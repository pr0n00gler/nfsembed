# Native NFSv3 certification

`run_local.sh` launches the crate's persistent embedded certification
filesystem and mounts it with the host kernel's native NFSv3 client. The suite
verifies large reads, stable write data, post-create/rename/link namespace
state, a 512-entry multi-page directory, concurrent creates, reconnects, an in-process
server restart with rotated handles, graceful shutdown, a read-only profile,
case-sensitive and case-insensitive profiles, and an explicit wire probe of all
22 NFSv3 and all six MOUNTv3 procedure numbers. It requires passwordless privilege escalation
for mount operations.

```sh
./tests/native/run_local.sh
```

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

The `native-client.yml` workflow runs all four required cells on every pull
request and push. Same-host cells run directly on Linux and macOS runners. The
two cross-host cells use a Lima Linux VM on a `macos-15-intel` runner with static
port forwarding, so no manually coordinated external endpoint is required.
Every cell runs read-write, restart, lost-reply, read-only, and case-policy
profiles. Normal interoperability uses hard mounts; bounded `soft` retry options
are isolated to the lost-reply fault profile. Exact replay assertions remain in
`e2e_runtime.rs`, where the harness can close a TCP connection at the precise
RPC boundary.
