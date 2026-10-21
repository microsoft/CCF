#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${AENEAS_BIN:?Set AENEAS_BIN to the pinned Aeneas executable}"
: "${CHARON_BIN:?Set CHARON_BIN to the Charon executable from the same bundle}"

if [ "$("$AENEAS_BIN" -version)" != "aeneas nightly-2026.10.20-fc321a2" ]; then
  echo "Expected Aeneas nightly-2026.10.20-fc321a2" >&2
  exit 1
fi

export RUSTUP_TOOLCHAIN=nightly-2026-09-17
export CARGO_BUILD_JOBS=1
export LEAN_NUM_THREADS=1
unset CARGO_BUILD_TARGET

cd "$ROOT_DIR/src/rust/shamir"
"$CHARON_BIN" cargo --preset=aeneas --sysroot default \
  --start-from ccf_shamir::reduce \
  --start-from ccf_shamir::evaluate \
  --start-from ccf_shamir::share_limb \
  --start-from ccf_shamir::recover -- --lib --locked

cd "$ROOT_DIR"
"$AENEAS_BIN" -backend lean -dest lean/shamir/Generated \
  -namespace ccf_shamir -loops-to-rec -sequential -no-progress-bar \
  src/rust/shamir/ccf_shamir.llbc
