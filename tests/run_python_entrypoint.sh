#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
script=${1:?usage: run_python_entrypoint.sh SCRIPT.py [ARGUMENT ...]}
shift

case "$script" in
  /*|*".."*)
    echo "Python entrypoint must be a repository-relative path" >&2
    exit 2
    ;;
  *.py)
    ;;
  *)
    echo "Python entrypoint must end in .py: $script" >&2
    exit 2
    ;;
esac

if [ ! -f "$repository/$script" ]; then
  echo "Python entrypoint does not exist: $script" >&2
  exit 2
fi

case "${CI:-}" in
  1|true)
    cd "$repository"
    exec python3 "$script" "$@"
    ;;
esac

if [ "${NFSEMBED_CONTAINERIZED:-0}" = "1" ]; then
  cd "$repository"
  exec python3 "$script" "$@"
fi

# A container reaches a server bound to the local workstation through Docker's
# stable host alias rather than the container's own loopback interface.
if [ "$#" -gt 0 ]; then
  first_argument=$1
  shift
  case "$first_argument" in
    127.0.0.1|localhost)
      first_argument=host.docker.internal
      ;;
  esac
  set -- "$first_argument" "$@"
fi

exec docker compose \
  --project-directory "$repository" \
  -f "$repository/compose.yaml" \
  --profile scripts \
  run --rm --no-deps script-runner "$script" "$@"
