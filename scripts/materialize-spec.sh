#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_DIR="$ROOT_DIR/docs/specification/source-archive"
RUNTIME_DIR="$ROOT_DIR/.runtime/specification"
ARCHIVE="$RUNTIME_DIR/cve-atlas-source.tar.gz"
TARGET="$RUNTIME_DIR/CVE Atlas.docx"

mkdir -p "$RUNTIME_DIR"
cat "$SOURCE_DIR"/part-* | base64 --decode > "$ARCHIVE"
(
  cd "$RUNTIME_DIR"
  sha256sum --check "$SOURCE_DIR/SHA256SUMS"
)

tar -xOf "$ARCHIVE" 'docs/specification/CVE Atlas.docx' > "$TARGET"
echo 'd2c81279d40c22961438fbc804311c444ae01574ad61766617f32210c180329e  CVE Atlas.docx' | (
  cd "$RUNTIME_DIR"
  sha256sum --check --strict
)
printf '%s\n' "$TARGET"
