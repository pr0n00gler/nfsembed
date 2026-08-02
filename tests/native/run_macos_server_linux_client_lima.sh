#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
instance=${LIMA_INSTANCE:-linux}
guest_root=${LIMA_REPOSITORY:-/tmp/nfsembed}
port=${NFS_PORT:-20491}
state_dir=
ready_file=
shutdown_file=
server_log=
server_pid=

cleanup() {
  if [ -n "$shutdown_file" ]; then
    : >"$shutdown_file"
  fi
  if [ -n "$server_pid" ]; then
    wait "$server_pid" || true
  fi
  if [ -n "$state_dir" ]; then
    rm -rf "$state_dir"
  fi
}
trap cleanup EXIT INT TERM

wait_ready() {
  attempt=0
  while [ ! -s "$ready_file" ]; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 300 ]; then
      cat "$server_log" >&2
      exit 1
    fi
    sleep 0.1
  done
}

run_profile() {
  profile=$1
  client_mode=$2
  state_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfsembed-lima-cross.XXXXXX")
  ready_file=$state_dir/ready
  shutdown_file=$state_dir/shutdown
  restart_file=$state_dir/restart
  server_log=$state_dir/server.log

  cargo run --locked --quiet --example certification_server -- \
    "0.0.0.0:$port" "$ready_file" "$shutdown_file" "$profile" "$restart_file" \
    >"$server_log" 2>&1 &
  server_pid=$!
  wait_ready
  read -r server_port mount_port <"$ready_file"

  limactl shell "$instance" -- \
    "$guest_root/tests/native/client.sh" host.lima.internal "$server_port" "$client_mode" "$mount_port"
  if [ "$profile" = "read-write" ]; then
    limactl shell "$instance" -- \
      "$guest_root/tests/native/client.sh" host.lima.internal "$server_port" restart-prepare "$mount_port"
    rm -f "$ready_file"
    : >"$restart_file"
    wait_ready
    read -r server_port mount_port <"$ready_file"
    limactl shell "$instance" -- \
      "$guest_root/tests/native/client.sh" host.lima.internal "$server_port" restart-verify "$mount_port"
  fi

  : >"$shutdown_file"
  wait "$server_pid" || {
    cat "$server_log" >&2
    exit 1
  }
  server_pid=
  shutdown_file=
  rm -rf "$state_dir"
  state_dir=
}

cd "$root"
run_profile read-write read-write
run_profile lost-reply lost-reply
run_profile read-only read-only
run_profile case-insensitive case-insensitive
