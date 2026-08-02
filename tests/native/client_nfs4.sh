#!/bin/sh
set -eu

server_host=${1:?usage: client_nfs4.sh SERVER_HOST SERVER_PORT [EXPORT_PATH]}
server_port=${2:?usage: client_nfs4.sh SERVER_HOST SERVER_PORT [EXPORT_PATH]}
export_path=${3:-/}
mount_dir=$(mktemp -d "${TMPDIR:-/tmp}/nfsembed-native-v4-mount.XXXXXX")
work_name="nfsembed-v4-cert-$$"
mounted=0

privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$mounted" -eq 1 ]; then
    rm -rf "$mount_dir/$work_name"
    privileged umount "$mount_dir"
  fi
  rmdir "$mount_dir" 2>/dev/null
  exit "$status"
}
trap cleanup EXIT INT TERM

mount_server() {
  case "$(uname -s)" in
    Darwin)
      privileged mount_nfs -o "vers=4.0,tcp,port=$server_port,sec=sys" \
        "$server_host:$export_path" "$mount_dir"
      ;;
    Linux)
      privileged mount -t nfs4 -o "vers=4.0,proto=tcp,port=$server_port,sec=sys" \
        "$server_host:$export_path" "$mount_dir"
      ;;
    *)
      echo "unsupported native NFSv4 client: $(uname -s)" >&2
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
ls -la "$mount_dir" >/dev/null
test -f "$mount_dir/file"
test -d "$mount_dir/dir"
test -L "$mount_dir/link"
test "$(readlink "$mount_dir/link")" = "file"
test "$(wc -c <"$mount_dir/file" | tr -d ' ')" = "2097152"
dd if="$mount_dir/file" of=/dev/null bs=131072 >/dev/null 2>&1

mkdir "$mount_dir/$work_name"
printf 'created-through-open\n' >"$mount_dir/$work_name/created"
test "$(cat "$mount_dir/$work_name/created")" = "created-through-open"
mv "$mount_dir/$work_name/created" "$mount_dir/$work_name/renamed"
ln "$mount_dir/$work_name/renamed" "$mount_dir/$work_name/hardlink"
ln -s renamed "$mount_dir/$work_name/symlink"
test "$(cat "$mount_dir/$work_name/symlink")" = "created-through-open"

# Keep a native OPEN state alive while the last directory entry is removed.
# The write must continue through the retained backend object until CLOSE.
printf 'before-unlink\n' >"$mount_dir/$work_name/unlinked-open"
exec 3<>"$mount_dir/$work_name/unlinked-open"
rm "$mount_dir/$work_name/unlinked-open"
printf 'after-unlink\n' >&3
exec 3>&-

# Keep another OPEN alive across a namespace rename and verify the renamed
# entry reflects I/O performed through the original open description.
printf 'before-rename\n' >"$mount_dir/$work_name/rename-open"
exec 4<>"$mount_dir/$work_name/rename-open"
mv "$mount_dir/$work_name/rename-open" "$mount_dir/$work_name/rename-opened"
printf 'after-rename\n' >&4
exec 4>&-
test "$(cat "$mount_dir/$work_name/rename-opened")" = "after-rename"

# Exercise the native client's NFSv4 LOCK/LOCKU path when the platform ships
# its standard advisory-lock utility.
printf 'lock-target\n' >"$mount_dir/$work_name/locked"
if command -v flock >/dev/null 2>&1; then
  flock -x -w 5 "$mount_dir/$work_name/locked" true
elif command -v lockf >/dev/null 2>&1; then
  lockf -kw -t 5 "$mount_dir/$work_name/locked" true
else
  echo "no native advisory-lock utility found; OPEN/CLOSE coverage continues" >&2
fi

entry=0
while [ "$entry" -lt 128 ]; do
  printf '%s\n' "$entry" >"$mount_dir/$work_name/entry-$entry"
  entry=$((entry + 1))
done
entry_count=$(find "$mount_dir/$work_name" -maxdepth 1 -name 'entry-*' | wc -l | tr -d ' ')
test "$entry_count" = "128"
sync

# Force a new TCP connection and stateful mount negotiation.
unmount_server
mount_server
test "$(cat "$mount_dir/$work_name/renamed")" = "created-through-open"
test "$(cat "$mount_dir/$work_name/rename-opened")" = "after-rename"
test "$(cat "$mount_dir/$work_name/entry-127")" = "127"

rm -rf "$mount_dir/$work_name"
unmount_server
