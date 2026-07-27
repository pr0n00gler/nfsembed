#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
server_host=${1:?usage: client.sh SERVER_HOST SERVER_PORT}
server_port=${2:?usage: client.sh SERVER_HOST SERVER_PORT}
profile=${3:-read-write}
mount_port=${4:-$server_port}
mount_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfsembed-native-mount.XXXXXX")
expected_file=$(mktemp "${TMPDIR:-/tmp}/nfsembed-native-expected.XXXXXX")
mounted=0

privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

cleanup() {
  if [ "$mounted" -eq 1 ]; then
    privileged umount "$mount_dir" || true
  fi
  rm -f "$expected_file"
  rmdir "$mount_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mount_server() {
  case "$(uname -s)" in
    Darwin)
      mount_options="vers=3,tcp,port=$server_port,mountport=$mount_port,nolocks"
      if [ "$profile" = "lost-reply" ]; then
        mount_options="$mount_options,soft"
      fi
      privileged mount_nfs -o "$mount_options" \
        "$server_host:/" "$mount_dir"
      ;;
    Linux)
      mount_options="vers=3,mountvers=3,tcp,port=$server_port,mountport=$mount_port,nolock"
      if [ "$profile" = "lost-reply" ]; then
        mount_options="$mount_options,soft,timeo=20,retrans=3"
      fi
      privileged mount -t nfs -o "$mount_options" \
        "$server_host:/" "$mount_dir"
      ;;
    *)
      echo "unsupported native client: $(uname -s)" >&2
      exit 1
      ;;
  esac
  mounted=1
}

unmount_server() {
  privileged umount "$mount_dir"
  mounted=0
}

mount_server

case "$profile" in
  read-only)
    "$root/tests/run_python_entrypoint.sh" \
      tests/native/procedure_probe.py "$server_host" "$server_port" read-only
    test -f "$mount_dir/file"
    dd if="$mount_dir/file" of=/dev/null bs=131072 >/dev/null 2>&1
    original_checksum=$(cksum <"$mount_dir/file")

    # Darwin's NFS client can report success for a cached namespace operation
    # even though the server returned NFS3ERR_ROFS. The wire probe above checks
    # the exact status; remounting below verifies that no mutation persisted.
    (printf 'must-fail' >"$mount_dir/file") 2>/dev/null || true
    (printf 'must-fail' >"$mount_dir/read-only-attempt") 2>/dev/null || true
    mkdir "$mount_dir/read-only-directory" 2>/dev/null || true
    ln -s file "$mount_dir/read-only-symlink" 2>/dev/null || true
    ln "$mount_dir/file" "$mount_dir/read-only-hardlink" 2>/dev/null || true
    mv "$mount_dir/file" "$mount_dir/read-only-rename" 2>/dev/null || true
    rm "$mount_dir/file" 2>/dev/null || true
    rmdir "$mount_dir/dir" 2>/dev/null || true

    unmount_server
    mount_server
    test -f "$mount_dir/file"
    test "$(cksum <"$mount_dir/file")" = "$original_checksum"
    test -d "$mount_dir/dir"
    test ! -e "$mount_dir/read-only-attempt"
    test ! -e "$mount_dir/read-only-directory"
    test ! -L "$mount_dir/read-only-symlink"
    test ! -e "$mount_dir/read-only-hardlink"
    test ! -e "$mount_dir/read-only-rename"
    ;;
  case-insensitive)
    test -f "$mount_dir/FiLe"
    printf 'case-policy\n' >"$mount_dir/MixedCase"
    test "$(cat "$mount_dir/mixedcase")" = "case-policy"
    rm "$mount_dir/MIXEDCASE"
    ;;
  restart-prepare)
    printf 'survives-server-restart\n' >"$mount_dir/restart-persist"
    sync
    ;;
  restart-verify)
    test "$(cat "$mount_dir/restart-persist")" = "survives-server-restart"
    rm "$mount_dir/restart-persist"
    ;;
  lost-reply)
    printf 'kernel-retransmission-survived\n' >"$mount_dir/lost-reply-write"
    sync
    test "$(cat "$mount_dir/lost-reply-write")" = "kernel-retransmission-survived"
    rm "$mount_dir/lost-reply-write"
    ;;
  read-write)
    "$root/tests/run_python_entrypoint.sh" \
      tests/native/procedure_probe.py "$server_host" "$server_port"
    ls -la "$mount_dir" >/dev/null
    test -f "$mount_dir/file"
    if test -e "$mount_dir/FiLe"; then
      echo "case-sensitive export accepted a differently cased lookup" >&2
      exit 1
    fi
    test -d "$mount_dir/dir"
    test -L "$mount_dir/link"
    test "$(readlink "$mount_dir/link")" = "file"
    test "$(wc -c <"$mount_dir/file" | tr -d ' ')" = "2097152"
    dd if="$mount_dir/file" of=/dev/null bs=131072 >/dev/null 2>&1
    stat "$mount_dir/file" >/dev/null
    getconf NAME_MAX "$mount_dir" >/dev/null 2>&1 || true

    dd if=/dev/zero of="$expected_file" bs=131072 count=16 >/dev/null 2>&1
    printf 'native-write-persisted\n' | dd of="$expected_file" bs=1 conv=notrunc >/dev/null 2>&1
    cp "$expected_file" "$mount_dir/file"
    sync
    test "$(wc -c <"$mount_dir/file" | tr -d ' ')" = "2097152"
    cmp "$expected_file" "$mount_dir/file"

    printf 'created-content\n' >"$mount_dir/new-native"
    mkdir "$mount_dir/native-dir"
    printf 'nested-content\n' >"$mount_dir/native-dir/child"
    test "$(cat "$mount_dir/native-dir/child")" = "nested-content"
    ln "$mount_dir/file" "$mount_dir/native-hardlink"
    cmp "$mount_dir/file" "$mount_dir/native-hardlink"
    mv "$mount_dir/new-native" "$mount_dir/renamed-native"
    test ! -e "$mount_dir/new-native"
    test "$(cat "$mount_dir/renamed-native")" = "created-content"
    ln -s renamed-native "$mount_dir/native-symlink"
    test "$(cat "$mount_dir/native-symlink")" = "created-content"
    mkfifo "$mount_dir/native-fifo"
    test -p "$mount_dir/native-fifo"

    page=0
    while [ "$page" -lt 512 ]; do
      printf '%s\n' "$page" >"$mount_dir/page-$page"
      page=$((page + 1))
    done
    page_count=$(find "$mount_dir" -maxdepth 1 -name 'page-*' | wc -l | tr -d ' ')
    test "$page_count" = "512"

    concurrent=0
    pids=
    while [ "$concurrent" -lt 12 ]; do
      (printf 'concurrent-%s\n' "$concurrent" >"$mount_dir/concurrent-$concurrent") &
      pids="$pids $!"
      concurrent=$((concurrent + 1))
    done
    for pid in $pids; do
      wait "$pid"
    done

    # Force a fresh TCP session and mount negotiation, then verify all state
    # observed after reconnect is the state produced before it.
    unmount_server
    mount_server
    cmp "$expected_file" "$mount_dir/file"
    test "$(cat "$mount_dir/renamed-native")" = "created-content"
    test "$(cat "$mount_dir/concurrent-7")" = "concurrent-7"

    rm -f "$mount_dir"/page-* "$mount_dir"/concurrent-*
    rm -f "$mount_dir/native-symlink" "$mount_dir/native-fifo"
    rm -f "$mount_dir/renamed-native" "$mount_dir/native-hardlink"
    rm -f "$mount_dir/native-dir/child"
    rmdir "$mount_dir/native-dir" "$mount_dir/dir"
    sync
    ;;
  *)
    echo "unknown native certification profile: $profile" >&2
    exit 1
    ;;
esac

unmount_server
