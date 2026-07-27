#!/bin/sh
set -eu

pynfs_root=/opt/pynfs
pynfs_ref=cd4701827a8261fedbfb4c6e39029fb9671321a6

if [ "${1:-}" = "--self-test" ]; then
  test "$(cat "$pynfs_root/PINNED_COMMIT")" = "$pynfs_ref"
  test -f "$pynfs_root/nfs4.0/testserver.py"
  test -f "$pynfs_root/nfs4.1/testmod.py"
  check-pynfs-client "$pynfs_root"
  echo "pynfs $pynfs_ref is ready"
  exit 0
fi

if [ "${PYNFS_KINIT:-0}" = "1" ]; then
  : "${KRB5_CLIENT_KTNAME:?set KRB5_CLIENT_KTNAME for PYNFS_KINIT}"
  : "${KRB5_CLIENT_PRINCIPAL:?set KRB5_CLIENT_PRINCIPAL for PYNFS_KINIT}"
  test -s "$KRB5_CLIENT_KTNAME"
  kinit -kt "$KRB5_CLIENT_KTNAME" "$KRB5_CLIENT_PRINCIPAL"
fi

if [ "$#" -eq 0 ]; then
  : "${PYNFS_SERVER:?set PYNFS_SERVER or pass testserver.py arguments}"

  export_path=${PYNFS_EXPORT:-/}
  # PYNFS_TESTS is intentionally word-split so multiple pynfs flags/codes can
  # be supplied without invoking a command shell or eval.
  # shellcheck disable=SC2086
  set -- "${PYNFS_SERVER}:${export_path}" --maketree ${PYNFS_TESTS:-all}
fi

# The pinned pynfs runner prints its failure count but exits successfully even
# when tests fail. Always request its machine-readable report and turn reported
# failures into a failing container/Make target.
result_file=$(mktemp)
trap 'rm -f "$result_file"' EXIT HUP INT TERM
python3 "$pynfs_root/nfs4.0/testserver.py" "$@" --jsonout "$result_file"
if [ ! -s "$result_file" ]; then
  # Informational commands such as --showflags exit before the runner writes
  # a test report.
  exit 0
fi
python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report:
    result = json.load(report)
failures = int(result.get("failures", 0))
errors = int(result.get("errors", 0))
if failures or errors:
    print(f"pynfs reported {failures} failure(s) and {errors} error(s)", file=sys.stderr)
    raise SystemExit(1)
' "$result_file"
