#!/bin/sh
set -eu

command -v cargo-fuzz >/dev/null 2>&1 || {
  echo "cargo-fuzz is required for the certification gate" >&2
  exit 1
}

cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo +nightly fuzz build

for target in rpc_codec rpc_auth rpc_record file_handle nfs_write nfs_readdir replay; do
  cargo +nightly fuzz run "$target" -- -runs=1000
done
