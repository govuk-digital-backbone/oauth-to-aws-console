#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PACKAGE_DIR="$DIST_DIR/package"
ZIP_PATH="$DIST_DIR/lambda.zip"
BUILD_VENV="$DIST_DIR/.build-venv"

rm -rf "$PACKAGE_DIR" "$BUILD_VENV"
mkdir -p "$PACKAGE_DIR"
python3 -m venv "$BUILD_VENV"

"$BUILD_VENV/bin/pip" install \
  --upgrade \
  --disable-pip-version-check \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --abi cp312 \
  --only-binary=:all: \
  --target "$PACKAGE_DIR" \
  "$ROOT_DIR"

(
  cd "$PACKAGE_DIR"
  zip -qr "$ZIP_PATH" .
)

rm -rf "$BUILD_VENV"

printf 'Created %s\n' "$ZIP_PATH"
