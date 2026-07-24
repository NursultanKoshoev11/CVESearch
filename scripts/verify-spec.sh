#!/usr/bin/env sh
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MATERIALIZED=$($ROOT_DIR/scripts/materialize-spec.sh)
EXPECTED=$(awk '{print $1}' "$ROOT_DIR/docs/specification/SHA256SUMS")
ACTUAL=$(sha256sum "$MATERIALIZED" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || {
  echo "Specification checksum mismatch: expected $EXPECTED, got $ACTUAL" >&2
  exit 1
}
echo "CVE Atlas.docx: OK"
