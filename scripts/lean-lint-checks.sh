#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR/lean"

if ! command -v lake >/dev/null 2>&1; then
  echo "lake is required. Install Lean via elan: https://lean-lang.org/install/" >&2
  exit 1
fi

lake exe cache get Mathlib.Init Mathlib.Tactic.Linter.TextBased
lake build --wfail SourceLint
lake env python3 "$SCRIPT_DIR/test_lean_lint.py"
lake env python3 "$SCRIPT_DIR/lean_lint.py"
