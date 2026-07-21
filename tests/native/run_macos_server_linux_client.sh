#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
state_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfsserve-cross-state.XXXXXX")
ready_file=$state_dir/ready
shutdown_file=$state_dir/shutdown
server_log=$state_dir/server.log
server_pid=

cleanup() {
  : >"$shutdown_file"
  if [ -n "$server_pid" ]; then
    wait "$server_pid" || true
  fi
}
trap cleanup EXIT INT TERM

cd "$root"
cargo run --quiet --example certification_server -- "0.0.0.0:0" "$ready_file" "$shutdown_file" \
  >"$server_log" 2>&1 &
server_pid=$!

attempt=0
while [ ! -s "$ready_file" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -gt 300 ]; then
    cat "$server_log" >&2
    exit 1
  fi
  sleep 0.1
done

docker build -t nfsserve-native-linux -f "$root/tests/native/Dockerfile" "$root"
if ! docker run --rm --privileged \
  -v "$root:/work" \
  nfsserve-native-linux \
  ./tests/native/client.sh host.docker.internal "$(cat "$ready_file")"; then
  cat "$server_log" >&2
  exit 1
fi

: >"$shutdown_file"
wait "$server_pid"
server_pid=
