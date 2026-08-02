#!/bin/sh
set -eu

pynfs_root=${1:-/opt/pynfs}

# This pinned pynfs revision contains two unfinished NFSv4.0 server
# implementation modules. They are not part of the testserver.py client and
# conformance runner, and both contain upstream syntax errors. Compile every
# other Python module so a new syntax failure cannot be hidden by a broad
# directory exclusion.
server_only_modules='/nfs4[.]0/(nfs4server|nfs4state)[.]py$'

test -f "$pynfs_root/nfs4.0/testserver.py"
test -f "$pynfs_root/nfs4.0/nfs4server.py"
test -f "$pynfs_root/nfs4.0/nfs4state.py"
test -f "$pynfs_root/nfs4.1/testmod.py"

python3 -m compileall -q -x "$server_only_modules" "$pynfs_root"

# Loading the CLI exercises the actual NFSv4.0 conformance runner's import
# graph without contacting a server.
(
  cd "$pynfs_root/nfs4.0"
  python3 ./testserver.py --help >/dev/null
)
