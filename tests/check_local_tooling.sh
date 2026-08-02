#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repository"

failure=0

fail() {
  echo "tooling policy: $*" >&2
  failure=1
}

for required in Makefile compose.yaml \
  tests/docker/tools.Dockerfile \
  tests/docker/pynfs.Dockerfile \
  tests/docker/kdc.Dockerfile \
  tests/run_python_entrypoint.sh
do
  if [ ! -f "$required" ]; then
    fail "missing $required"
  fi
done

for service in tools script-runner pynfs kdc
do
  if ! grep -Eq "^  $service:" compose.yaml; then
    fail "compose.yaml is missing the $service service"
  fi
done

recipe_runtimes='(^|[[:space:];&|])(python|python3|node|npm|npx|bun|deno|ts-node)([[:space:];&|]|$)'
for makefile in $(find . \
  -path './.git' -prune -o \
  -path './target' -prune -o \
  -path './fuzz/target' -prune -o \
  -type f \( -name Makefile -o -name '*.mk' \) -print)
do
  if sed -n '/^	/p' "$makefile" | grep -En "$recipe_runtimes" >&2; then
    fail "$makefile recipes must route Python/JavaScript/TypeScript through Compose"
  fi
done

documented_host_runtime='^[[:space:]]*(\$[[:space:]]*)?(python|python3|pip|pip3|node|npm|npx|bun|deno|ts-node)([[:space:]]|$)'
for document in README.md CONTRIBUTING.md fuzz/README.md tests/README.md tests/native/README.md
do
  if [ -f "$document" ] && grep -En "$documented_host_runtime" "$document" >&2; then
    fail "$document instructs contributors to invoke a host scripting runtime"
  fi
done

for script in tests/*.sh tests/native/*.sh
do
  if [ "$script" = "tests/run_python_entrypoint.sh" ] \
    || [ "$script" = "tests/check_local_tooling.sh" ]
  then
    continue
  fi
  if grep -En "$recipe_runtimes" "$script" >&2; then
    fail "$script directly invokes a host scripting runtime"
  fi
done

executable_script_sources=$(
  find . \
    -path './.git' -prune -o \
    -path './target' -prune -o \
    -path './fuzz/target' -prune -o \
    -type f \( \
      -name '*.py' -o \
      -name '*.js' -o \
      -name '*.jsx' -o \
      -name '*.ts' -o \
      -name '*.tsx' -o \
      -name '*.mjs' -o \
      -name '*.cjs' \
    \) \
    -perm -111 \
    -print
)
if [ -n "$executable_script_sources" ]; then
  printf '%s\n' "$executable_script_sources" >&2
  fail "scripting-language sources must be non-executable and launched through a container wrapper"
fi

if ! grep -Fq 'docker compose' tests/run_python_entrypoint.sh; then
  fail "the local Python entrypoint wrapper is not container-routed"
fi
if ! grep -Fq 'NFSEMBED_CONTAINERIZED=1' tests/native/Dockerfile; then
  fail "the native Docker image is not marked as containerized"
fi
if ! grep -Fq '$env:CI' tests/native/run_windows.ps1 \
  || ! grep -Fq 'script-runner' tests/native/run_windows.ps1
then
  fail "the Windows probe must be direct only in CI and containerized locally"
fi

if grep -R -nE '^FROM [^ ]+:latest($|[[:space:]])' tests/docker >&2; then
  fail "Docker tooling must not use latest image tags"
fi
if ! grep -Fq '@sha256:' tests/docker/tools.Dockerfile \
  || ! grep -Fq '@sha256:' tests/docker/pynfs.Dockerfile \
  || ! grep -Fq '@sha256:' tests/docker/kdc.Dockerfile \
  || ! grep -Fq '@sha256:' compose.yaml
then
  fail "Docker base images and script-runner must be digest-pinned"
fi
if ! grep -Fq 'cd4701827a8261fedbfb4c6e39029fb9671321a6' \
  tests/docker/pynfs.Dockerfile
then
  fail "pynfs must be pinned to an immutable upstream commit"
fi

if [ "$failure" -ne 0 ]; then
  exit 1
fi

echo "local tooling policy passed"
