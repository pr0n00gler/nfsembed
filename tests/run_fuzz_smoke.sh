#!/bin/sh
set -eu

command -v cargo-fuzz >/dev/null 2>&1 || {
  echo "cargo-fuzz is required for the certification gate" >&2
  exit 1
}

nightly_toolchain=${NIGHTLY_TOOLCHAIN:-nightly}

cargo +"$nightly_toolchain" fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo +"$nightly_toolchain" fuzz build

for target in rpc_codec rpc_auth rpc_record file_handle nfs_write nfs_readdir replay \
  nfs4_compound nfs4_callback rpc_gss
do
  cargo +"$nightly_toolchain" fuzz run "$target" -- -runs=1000
done
