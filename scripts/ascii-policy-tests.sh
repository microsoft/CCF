#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_CONFIG_COUNT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git -c init.defaultBranch=ascii-policy-tests init -q "$TEST_ROOT"
mkdir -p "$TEST_ROOT/scripts"
cp "$SCRIPT_DIR/ascii-checks.sh" "$TEST_ROOT/scripts/ascii-checks.sh"

legacy_files=(
  "python/src/ccf/ledger_viz.py"
  "js/ccf-app/doc/theme/partials/analytics.hbs"
  "tla/consensus/MCAliases.tla"
)
for file in "${legacy_files[@]}"; do
  mkdir -p "$TEST_ROOT/$(dirname "$file")"
  cp "$ROOT_DIR/$file" "$TEST_ROOT/$file"
done
git -C "$TEST_ROOT" add .

check() {
  local expected=$1
  local description=$2
  local actual=0
  local output
  output=$(cd "$TEST_ROOT" && bash scripts/ascii-checks.sh 2>&1) || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    printf '%s: expected exit %s, got %s\n%s\n' "$description" "$expected" "$actual" "$output" >&2
    exit 1
  fi
}

check 0 "Existing Unicode remains accepted"

ascii_files=(
  "src/example.py"
  "src/example.rs"
  "CMakeLists.txt"
  "src/CMakeLists.txt"
  ".github/copilot-instructions.md"
  ".github/instructions/nested/example.instructions.md"
  ".github/skills/example/SKILL.md"
  ".github/skills/example/references/guide.md"
  ".github/agents/reviewer.md"
  "AGENTS.md"
  "src/AGENTS.md"
  "CLAUDE.md"
  "GEMINI.md"
)
for file in "${ascii_files[@]}"; do
  mkdir -p "$TEST_ROOT/$(dirname "$file")"
  printf '\342\206\222\n' > "$TEST_ROOT/$file"
  git -C "$TEST_ROOT" add -- "$file"
  check 1 "Reject Unicode in $file"
  printf '%s\n' 'ASCII text with an escape: "\u2192"' > "$TEST_ROOT/$file"
  check 0 "Accept ASCII escapes in $file"
done

for file in proof.lean nested/proof.lean doc/guide.md 3rdparty/example.py; do
  mkdir -p "$TEST_ROOT/$(dirname "$file")"
  printf '\342\210\200 n : Nat, n = n\n' > "$TEST_ROOT/$file"
  git -C "$TEST_ROOT" add -- "$file"
done
check 0 "Lean, prose and vendored files remain exempt"

for file in "${legacy_files[@]}"; do
  printf '\342\206\222\n' >> "$TEST_ROOT/$file"
  check 1 "Reject additional Unicode in $file"
  cp "$ROOT_DIR/$file" "$TEST_ROOT/$file"

  match=$(LC_ALL=C grep -nPm1 '[^\x00-\x7F]' "$ROOT_DIR/$file")
  printf '%s\n' "${match#*:}" >> "$TEST_ROOT/$file"
  check 1 "Reject duplicate grandfathered lines in $file"

  awk -v target="${match%%:*}" 'NR == target { $0 = $0 " changed" } { print }' \
    "$ROOT_DIR/$file" > "$TEST_ROOT/$file"
  check 1 "Reject edits to grandfathered lines in $file"
  cp "$ROOT_DIR/$file" "$TEST_ROOT/$file"

  printf '\n# ASCII addition\n' >> "$TEST_ROOT/$file"
  check 0 "Accept ASCII-only additions in $file"
  cp "$ROOT_DIR/$file" "$TEST_ROOT/$file"
done

rm "$TEST_ROOT/src/example.py"
check 0 "Deleted tracked files do not fail"
mkdir "$TEST_ROOT/src/example.py"
check 1 "Read errors must fail the check"
rmdir "$TEST_ROOT/src/example.py"
GIT_DIR="$TEST_ROOT/missing.git" check 1 "Git errors must fail the check"

echo "ASCII policy regression tests passed"
