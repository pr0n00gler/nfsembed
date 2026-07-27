#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
server_pid=
shutdown_file=
server_log=
state_dir=
current_profile=

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [ -n "$shutdown_file" ]; then
    : >"$shutdown_file"
  fi
  if [ -n "$server_pid" ]; then
    wait "$server_pid"
    server_status=$?
    if [ "$status" -eq 0 ] && [ "$server_status" -ne 0 ]; then
      status=$server_status
    fi
  fi
  if [ "$status" -ne 0 ]; then
    echo "native certification failed in profile: ${current_profile:-unknown}" >&2
    if [ -n "$state_dir" ]; then
      echo "diagnostic artifacts preserved at: $state_dir" >&2
    fi
    if [ -n "$server_log" ] && [ -s "$server_log" ]; then
      echo "server log:" >&2
      cat "$server_log" >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_ready() {
  ready_file=$1
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
  protocol=${3:-v3}
  current_profile="$protocol/$profile"
  state_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfsembed-native-state.XXXXXX")
  ready_file=$state_dir/ready
  shutdown_file=$state_dir/shutdown
  restart_file=$state_dir/restart
  server_log=$state_dir/server.log

  NFSEMBED_PROTOCOL=$protocol cargo run --locked --quiet --example certification_server -- \
    "127.0.0.1:0" "$ready_file" "$shutdown_file" "$profile" "$restart_file" \
    >"$server_log" 2>&1 &
  server_pid=$!
  wait_ready "$ready_file"
  read -r server_port mount_port <"$ready_file"

  if [ "$protocol" = "v4" ]; then
    "$root/tests/native/client_nfs4.sh" 127.0.0.1 "$server_port"
  else
    "$root/tests/native/client.sh" 127.0.0.1 "$server_port" "$client_mode" "$mount_port"
  fi

  if [ "$profile" = "read-write" ] && [ "$protocol" = "v3" ]; then
    "$root/tests/native/client.sh" 127.0.0.1 "$server_port" restart-prepare "$mount_port"
    rm -f "$ready_file"
    : >"$restart_file"
    wait_ready "$ready_file"
    read -r server_port mount_port <"$ready_file"
    "$root/tests/native/client.sh" 127.0.0.1 "$server_port" restart-verify "$mount_port"
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
  server_log=
  current_profile=
}

cd "$root"
run_profile read-write read-write
run_profile lost-reply lost-reply
run_profile read-only read-only
run_profile case-insensitive case-insensitive
run_profile read-write read-write v4
