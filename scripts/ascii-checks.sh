#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks that source and agent instruction files contain only ASCII characters,
# except for Lean source and grandfathered Unicode lines.
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
# - Lean source (lean): Unicode syntax and identifiers are idiomatic.
# - Prose documentation (md, rst, txt): human-authored prose where non-ASCII
#   is legitimate. Agent instruction Markdown is included explicitly below.
# - Binary / generated / vendored data (committed, cose, pem, png, pdf, ico,
#   lock, csv, numbered raft scenario fixtures, everything under 3rdparty/):
#   not human-edited source, so an ASCII check is meaningless or harmful.

# SHA-256 hashes of existing Unicode lines, excluding their line endings.
# Consume each hash once so neither edited lines nor extra copies are exempt.
# Do not expand this baseline to allow new Unicode outside Lean.
declare -A LEGACY_NON_ASCII_LINES=(
  ["python/src/ccf/ledger_viz.py"]="da452fa6d2ee3717bf92ca53b9225a3aa53ba66e838e39decba2d50edc539855"
  ["js/ccf-app/doc/theme/partials/analytics.hbs"]="d22a72116e0f20860074017113d763917f4516d95a566d9ab90464f60ec7f144"
  ["tla/consensus/MCAliases.tla"]=$'b9acbf868d048a06807d3d7bd7d321610a271281285476e24d6c646fe88ce637\n57f4a8bc014081bb7465cb339edf54e506ced1cfabf26e468dc96b1dedab87af'
)

globs=(
  "CMakeLists.txt" "*/CMakeLists.txt"
  ".github/copilot-instructions.md"
  ".github/instructions/*.md"
  ".github/skills/*.md"
  ".github/agents/*.md"
  "AGENTS.md" "*/AGENTS.md"
  "CLAUDE.md" "*/CLAUDE.md"
  "GEMINI.md" "*/GEMINI.md"
)
for ext in "${EXTENSIONS[@]}"; do
  globs+=("*.$ext")
done

if git ls-files -z "${globs[@]}" | {
  failed=0
  while IFS= read -r -d '' file; do
    # Missing tracked files may have been deleted in the working tree.
    if [[ "$file" == 3rdparty/* || ! -e "$file" ]]; then
      continue
    fi

    if matches=$(LC_ALL=C grep -nP '[^\x00-\x7F]' "$file"); then
      remaining_legacy=$'\n'"${LEGACY_NON_ASCII_LINES[$file]:-}"$'\n'
      reported=0
      while IFS= read -r match; do
        if [[ -n "${LEGACY_NON_ASCII_LINES[$file]:-}" ]]; then
          line=${match#*:}
          if ! digest=$(printf '%s' "${line%$'\r'}" | sha256sum); then
            echo "Could not check grandfathered Unicode in $file" >&2
            failed=1
            continue
          fi
          legacy_hash=$'\n'"${digest%% *}"$'\n'
          if [[ "$remaining_legacy" == *"$legacy_hash"* ]]; then
            remaining_legacy=${remaining_legacy/"$legacy_hash"/$'\n'}
            continue
          fi
        fi
        if [ "$reported" -eq 0 ]; then
          echo "Non-ASCII characters found in $file:"
          reported=1
        fi
        echo "$match"
        failed=1
      done <<< "$matches"
    elif [ "$?" -ne 1 ]; then
      failed=1
    fi
  done
  exit "$failed"
}; then
  echo "All checked files satisfy the ASCII policy."
else
  echo "Outside Lean source (*.lean), use plain ASCII or language-appropriate ASCII escapes for required Unicode data."
  echo "Do not add file-wide exemptions or expand the grandfathered Unicode baseline."
  exit 1
fi
