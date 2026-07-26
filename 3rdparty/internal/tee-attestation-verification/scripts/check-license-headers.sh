#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Checks that every source file of a known type carries the standard two-line
# license/copyright header:
#
#   <comment> Copyright (c) Microsoft Corporation.
#   <comment> Licensed under the MIT License.
#
# The comment marker is `#` for .py/.sh and `//` for .rs/.c/.h/.cpp/.hpp/.js.
# A leading shebang (`#!...`) line is allowed before the header.
#
# Usage: scripts/check-license-headers.sh [root]
#   root defaults to the repository root (the script's parent directory).
#
# Exits 0 when every checked file is compliant, or 1 while listing offenders.

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

COPYRIGHT="Copyright (c) Microsoft Corporation."
LICENSE="Licensed under the MIT License."

missing=()
checked=0

while IFS= read -r -d '' file; do
  case "$file" in
    *.py | *.sh) prefix='#' ;;
    *) prefix='//' ;;
  esac

  # Read the first three lines so the header can be found after an optional
  # shebang line.
  mapfile -t lines < <(head -n 3 "$file")
  if [[ "${lines[0]:-}" == '#!'* ]]; then
    line1="${lines[1]:-}"
    line2="${lines[2]:-}"
  else
    line1="${lines[0]:-}"
    line2="${lines[1]:-}"
  fi

  # Tolerate CRLF line endings.
  line1="${line1%$'\r'}"
  line2="${line2%$'\r'}"

  if [[ "$line1" != "$prefix $COPYRIGHT" || "$line2" != "$prefix $LICENSE" ]]; then
    missing+=("${file#"$ROOT"/}")
  fi
  checked=$((checked + 1))
done < <(
  find "$ROOT" \
    \( -path '*/.git' \
    -o -path '*/target' \
    -o -path '*/node_modules' \
    -o -path '*/dist' \
    -o -path '*/pkg' \
    -o -path '*/caci_pkg' \
    -o -path '*/vendor' \) -prune -o \
    -type f \( \
    -name '*.py' \
    -o -name '*.rs' \
    -o -name '*.c' \
    -o -name '*.h' \
    -o -name '*.cpp' \
    -o -name '*.hpp' \
    -o -name '*.js' \
    -o -name '*.sh' \) -print0
)

if ((${#missing[@]} > 0)); then
  echo "Missing or malformed license header in ${#missing[@]} of ${checked} file(s):" >&2
  for f in "${missing[@]}"; do
    echo "  ${f}" >&2
  done
  exit 1
fi

echo "All ${checked} checked file(s) have the expected license header."
