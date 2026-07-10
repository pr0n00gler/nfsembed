#!/bin/sh
set +e

repository=${1:?missing repository path}
address=${2:?missing listen address}
state=${3:?missing state directory}
profile=${4:-read-write}
restart=${5:-}

cd "$repository" || exit 125
if [ -n "$restart" ]; then
  "$HOME/.cargo/bin/cargo" run --quiet --example certification_server -- \
    "$address" "$state/ready" "$state/shutdown" "$profile" "$restart"
else
  "$HOME/.cargo/bin/cargo" run --quiet --example certification_server -- \
    "$address" "$state/ready" "$state/shutdown" "$profile"
fi
status=$?
printf '%s\n' "$status" >"$state/exit"
exit "$status"
