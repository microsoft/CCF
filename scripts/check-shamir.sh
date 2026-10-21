#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LEAN_NUM_THREADS=1
cd "$ROOT_DIR/lean/shamir"
lake build --wfail
lake exe mk_all --check --module

CHECK_DIR="$(mktemp -d "$PWD/.lake/check.XXXXXX")"
DECLARATIONS="$CHECK_DIR/declarations"
EXPORT="$CHECK_DIR/project.ndjson"
trap 'rm -f "$DECLARATIONS" "$EXPORT"; rmdir "$CHECK_DIR"' EXIT

# Check every project declaration and its dependency closure, not unused
# upstream test declarations imported by Aeneas's umbrella module.
if ! lake env lean -M 4500 ListDeclarations.lean > "$DECLARATIONS"; then
  cat "$DECLARATIONS" >&2
  exit 1
fi
mapfile -t names < "$DECLARATIONS"
if [ "${#names[@]}" -eq 0 ]; then
  echo "No Shamir declarations were found" >&2
  exit 1
fi
printf 'Exporting all %s project declarations and their dependencies\n' "${#names[@]}"
lake env leanexport Generated Shamir -- "${names[@]}" > "$EXPORT"
lake check --from-export="$EXPORT" "$@"
