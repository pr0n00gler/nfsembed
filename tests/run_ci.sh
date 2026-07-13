#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-targets
cargo test --all-features --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
# Keep the documented Criterion suite runnable from the published crate.
if ! cargo package --allow-dirty --offline --list | grep -Fqx 'benches/performance.rs'; then
    echo "packaged crate is missing benches/performance.rs" >&2
    exit 1
fi
cargo package --allow-dirty --offline
./tests/run_fuzz_smoke.sh
