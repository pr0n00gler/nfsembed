#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
docker build -t nfsserve-native-linux -f "$root/tests/native/Dockerfile" "$root"
docker run --rm --privileged \
  -v "$root:/work" \
  -v "${HOME}/.cargo/registry:/usr/local/cargo/registry:ro" \
  -e CARGO_TARGET_DIR=/tmp/target \
  nfsserve-native-linux \
  ./tests/native/run_local.sh
