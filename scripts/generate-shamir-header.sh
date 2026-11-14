#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Renders src/crypto/sharing_ffi.h from the Rust declarations in
# src/rust/src/shamir.rs with a pinned cbindgen, formatted with the
# clang-format release pinned by scripts/check-format.sh.
# Pass --check to verify that the committed header is up to date instead.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEADER=src/crypto/sharing_ffi.h
CBINDGEN_VERSION=0.29.4
CBINDGEN_BIN="${CBINDGEN_BIN:-cbindgen}"

if [ "$("$CBINDGEN_BIN" --version 2>/dev/null)" != "cbindgen $CBINDGEN_VERSION" ]; then
  echo "Expected cbindgen $CBINDGEN_VERSION. Install it with:" >&2
  echo "  cargo install cbindgen --version $CBINDGEN_VERSION --locked" >&2
  exit 1
fi

if [ -x "$(command -v clang-format-18)" ]; then
  CLANG_FORMAT=(clang-format-18)
else
  CLANG_FORMAT=(uvx --from clang-format==18.1.8 clang-format)
fi

GENERATED="$(mktemp)"
trap 'rm -f "$GENERATED"' EXIT

cd "$ROOT_DIR"
"$CBINDGEN_BIN" --quiet --config src/rust/cbindgen.toml --crate ccf-rs \
  --lockfile src/rust/Cargo.lock --output "$GENERATED" src/rust
"${CLANG_FORMAT[@]}" -i -style="file:$ROOT_DIR/.clang-format" "$GENERATED"

if [ "${1:-}" == "--check" ]; then
  if ! diff -u "$HEADER" "$GENERATED"; then
    echo "$HEADER is out of date; run scripts/generate-shamir-header.sh" >&2
    exit 1
  fi
  echo "$HEADER is up to date"
else
  cp "$GENERATED" "$HEADER"
  echo "Wrote $HEADER"
fi
