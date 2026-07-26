#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
instance=${LIMA_INSTANCE:-linux}
guest_root=${LIMA_REPOSITORY:-/tmp/nfsembed}
port=${NFS_PORT:-20490}
state=

cleanup() {
  if [ -n "$state" ]; then
    limactl shell "$instance" -- sh -lc "touch '$state/shutdown'; test ! -f '$state/pid' || ! kill -0 \$(cat '$state/pid') 2>/dev/null || kill \$(cat '$state/pid') 2>/dev/null || true" || true
  fi
}
trap cleanup EXIT INT TERM

wait_ready() {
  attempt=0
  while ! limactl shell "$instance" -- test -s "$state/ready"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 600 ]; then
      limactl shell "$instance" -- cat "$state/server.log" >&2
      exit 1
    fi
    sleep 0.1
  done
}

stop_server() {
  limactl shell "$instance" -- touch "$state/shutdown"
  attempt=0
  while ! limactl shell "$instance" -- test -f "$state/exit"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 300 ]; then
      limactl shell "$instance" -- cat "$state/server.log" >&2
      echo "Linux certification server did not shut down gracefully" >&2
      exit 1
    fi
    sleep 0.1
  done
  attempt=0
  while limactl shell "$instance" -- sh -lc "kill -0 \$(cat '$state/pid') 2>/dev/null"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 100 ]; then
      limactl shell "$instance" -- cat "$state/server.log" >&2
      echo "Linux certification server reported completion but its process did not exit" >&2
      exit 1
    fi
    sleep 0.1
  done
  status=$(limactl shell "$instance" -- cat "$state/exit")
  if [ "$status" -ne 0 ]; then
    limactl shell "$instance" -- cat "$state/server.log" >&2
    exit "$status"
  fi
}

run_profile() {
  profile=$1
  client_mode=$2
  state="/tmp/nfsembed-linux-server-$profile"
  limactl shell "$instance" -- sh -lc "rm -rf '$state'; mkdir -p '$state'; nohup sh '$guest_root/tests/native/certification_server_process.sh' '$guest_root' '0.0.0.0:$port' '$state' '$profile' '$state/restart' >'$state/server.log' 2>&1 </dev/null & echo \$! >'$state/pid'"
  wait_ready

  "$root/tests/native/client.sh" 127.0.0.1 "$port" "$client_mode"
  if [ "$profile" = "read-write" ]; then
    "$root/tests/native/client.sh" 127.0.0.1 "$port" restart-prepare
    limactl shell "$instance" -- sh -lc "rm -f '$state/ready'; touch '$state/restart'"
    wait_ready
    "$root/tests/native/client.sh" 127.0.0.1 "$port" restart-verify
  fi
  stop_server
  state=
}

run_profile read-write read-write
run_profile lost-reply lost-reply
run_profile read-only read-only
run_profile case-insensitive case-insensitive
