#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-targets
cargo test --all-features --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo package --allow-dirty --offline
./tests/run_fuzz_smoke.sh
