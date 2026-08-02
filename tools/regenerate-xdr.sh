#!/bin/sh
set -eu

mode=${1:---check}
case "$mode" in
  --check|--write) ;;
  *)
    echo "usage: $0 [--check|--write]" >&2
    exit 2
    ;;
esac

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
canonical="$repository/vendor/xdr/nfs4_prot.x"
gss_canonical="$repository/vendor/xdr/rpcsec_gss_v2.x"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

curl -fsS https://www.rfc-editor.org/rfc/rfc7531.txt -o "$temporary/rfc7531.txt"
curl -fsS https://www.rfc-editor.org/rfc/rfc5403.txt -o "$temporary/rfc5403.txt"
grep '^  *///' "$temporary/rfc7531.txt" \
  | sed 's?^  */// ??' \
  | sed 's?^  *///$??' \
  > "$temporary/nfs4_prot.x"
grep '^  *///' "$temporary/rfc5403.txt" \
  | sed 's?^  */// ??' \
  | sed 's?^  *///$??' \
  > "$temporary/rpcsec_gss_v2.x"

if [ "$mode" = "--write" ]; then
  cp "$temporary/nfs4_prot.x" "$canonical"
  cp "$temporary/rpcsec_gss_v2.x" "$gss_canonical"
else
  diff -u "$canonical" "$temporary/nfs4_prot.x"
  diff -u "$gss_canonical" "$temporary/rpcsec_gss_v2.x"
fi

# The checked-in Rust codecs are the generated deliverable. Their exhaustive
# discriminant and round-trip suite is the conformance diff until the source
# changes and a reviewed codec update is checked in.
cargo test --locked --lib nfs4::codec::
cargo test --locked --lib rpc::gss::xdr::
