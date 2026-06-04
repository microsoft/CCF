#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks that C/C++ and Python source files contain only ASCII characters.
# Non-ASCII punctuation/ligatures (em/en dashes, smart quotes, arrows, the fi
# ligature, ...) frequently slip into comments, docstrings and string literals
# via copy-paste or AI-generated text. This is a deterministic counterpart to
# the Copilot review rule in .github/copilot-instructions.md.
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

# Files that intentionally contain non-ASCII characters (for example box-drawing
# or block glyphs used to render terminal charts/visualisations). These are
# excluded from the check.
ALLOWLIST=(
  "python/src/ccf/ledger_viz.py"
  "scripts/compare_bencher_ab.py"
  "tests/infra/basicperf.py"
)

is_allowlisted() {
  local file="$1"
  for allowed in "${ALLOWLIST[@]}"; do
    if [ "$file" == "$allowed" ]; then
      return 0
    fi
  done
  return 1
}

failed=0
while IFS= read -r file; do
  if is_allowlisted "$file"; then
    continue
  fi
  # Report each offending line with its line number.
  matches=$(LC_ALL=C grep -nP '[^\x00-\x7F]' "$file" 2>/dev/null) || continue
  if [ -n "$matches" ]; then
    failed=1
    echo "Non-ASCII characters found in $file:"
    echo "$matches"
  fi
done < <(git ls-files '*.h' '*.hpp' '*.cpp' '*.c' '*.py' | grep -v -e '^3rdparty/')

if [ "$failed" -ne 0 ]; then
  echo "Replace non-ASCII characters with their plain ASCII equivalents."
  echo "If the non-ASCII content is intentional, add the file to ALLOWLIST in scripts/ascii-checks.sh."
  exit 1
fi

echo "All checked files contain only ASCII characters!"
