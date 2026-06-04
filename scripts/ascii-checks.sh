#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks that source files contain only ASCII characters.
# Non-ASCII punctuation/ligatures (em/en dashes, smart quotes, arrows, the fi
# ligature, ...) frequently slip into comments, docstrings and string literals
# via copy-paste or AI-generated text. This is a deterministic counterpart to
# the Copilot review rule in .github/copilot-instructions.md.
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

# Source file extensions to enforce. Keep this list as the single source of
# truth for which files are checked.
EXTENSIONS=(
  # C/C++
  c cc cpp h hpp
  # Templated source (e.g. version.h.in, ccf-config.cmake.in)
  in
  # Python
  py
  # JavaScript / TypeScript
  js cjs mjs ts
  # Rust
  rs
  # TLA+ specs and their model configs. TLA+ permits Unicode, but we enforce
  # ASCII in lieu of an official formatter.
  tla cfg
  # Build / config
  cmake toml ini
  # Data interchange / schemas
  json yml yaml cddl
  # Templates
  jinja hbs
  # Web
  css html svg
  # Shell
  sh
)
#
# Deliberately excluded suffixes (and why):
# - Prose documentation (md, rst, txt): human-authored prose where non-ASCII
#   (em dashes, accented author names, mathematical symbols) is legitimate.
# - Binary / generated / vendored data (committed, cose, pem, png, pdf, ico,
#   lock, csv, numbered raft scenario fixtures, everything under 3rdparty/):
#   not human-edited source, so an ASCII check is meaningless or harmful.

# Files that intentionally contain non-ASCII characters (for example box-drawing
# or block glyphs used to render terminal charts/visualisations, or symbolic
# state labels). These are excluded from the check.
ALLOWLIST=(
  "python/src/ccf/ledger_viz.py"
  "scripts/compare_bencher_ab.py"
  "tests/infra/basicperf.py"
  "js/ccf-app/doc/theme/partials/analytics.hbs"
  "tla/consensus/MCAliases.tla"
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

# Build the git ls-files glob arguments from the extension list.
globs=()
for ext in "${EXTENSIONS[@]}"; do
  globs+=("*.$ext")
done

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
done < <(git ls-files "${globs[@]}" | grep -v -e '^3rdparty/')

if [ "$failed" -ne 0 ]; then
  echo "Replace non-ASCII characters with their plain ASCII equivalents."
  echo "If the non-ASCII content is intentional, add the file to ALLOWLIST in scripts/ascii-checks.sh."
  exit 1
fi

echo "All checked files contain only ASCII characters!"
