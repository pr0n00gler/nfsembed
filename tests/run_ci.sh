#!/bin/sh
set -eu

./tests/check_local_tooling.sh
./tools/regenerate-xdr.sh --check
cargo +"${NIGHTLY_TOOLCHAIN:-nightly-2026-07-01}" fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --all-features --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
# Keep the documented benchmark, generator, and Docker-first maintenance
# entrypoints available from the published source crate.
package_list=$(mktemp)
trap 'rm -f "$package_list"' EXIT HUP INT TERM
cargo package --locked --allow-dirty --offline --list >"$package_list"
for required in \
    benches/performance.rs \
    compose.yaml \
    Makefile \
    tools/regenerate-xdr.sh \
    vendor/xdr/nfs4_prot.x \
    vendor/xdr/rpcsec_gss_v2.x
do
    if ! grep -Fqx "$required" "$package_list"; then
        echo "packaged crate is missing $required" >&2
        exit 1
    fi
done
cargo package --locked --allow-dirty --offline
./tests/run_fuzz_smoke.sh
