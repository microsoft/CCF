#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Validates public C++ headers:
#   1. No private headers included from public headers
#   2. All public headers declare a ccf namespace
#   3. All exported headers are actually included somewhere
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

STATUS=0

# 1. Public includes: no private headers included from public header files
echo "Checking public includes..."
violations=$(find "$ROOT_DIR/include/ccf" -type f -print0 | xargs --null grep -e "#include \"" | grep -v "#include \"ccf" | sort)
if [[ -n "$violations" ]]; then
  echo "Public headers include private implementation files:"
  echo "$violations"
  STATUS=1
else
  echo "No public-private include violations"
fi

# 2. Public header namespaces: all public headers namespace their exports
echo "Checking public header namespaces..."
violations=$(find "$ROOT_DIR/include/ccf" -type f -name "*.h" -print0 | xargs --null grep -L "namespace ccf" | sort || true)
if [[ -n "$violations" ]]; then
  echo "Public headers missing ccf namespace:"
  echo "$violations"
  STATUS=1
else
  echo "No public header namespace violations"
fi

# 3. Headers are included: all exported headers are actually included somewhere
echo "Checking headers are included..."
"$SCRIPT_DIR"/headers-are-included.sh || STATUS=1

# 4. src/ds isolation: production files under src/ds must not include other
# CCF source components, to keep ds a dependency-free leaf and avoid source
# cycles such as crypto -> ds -> pal -> crypto.
echo "Checking src/ds does not depend on other CCF source components..."
# Every top-level directory name under src/ and include/ccf/, other than ds
# itself, is treated as a distinct CCF source component.
components=$(
  {
    find "$ROOT_DIR/src" -mindepth 1 -maxdepth 1 -type d -printf "%f\n"
    find "$ROOT_DIR/include/ccf" -mindepth 1 -maxdepth 1 -type d -printf "%f\n"
  } | sort -u | grep -v -x "ds"
)
component_pattern=$(echo "$components" | paste -sd'|' -)
violations=""
while IFS= read -r -d '' file; do
  matches=$(grep -nE "#include \"(ccf/)?(${component_pattern})/" "$file" || true)
  if [[ -n "$matches" ]]; then
    violations+=$'\n'"$file:"$'\n'"$matches"
  fi
done < <(find "$ROOT_DIR/src/ds" -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.cpp" -o -name "*.cc" \) -not -path "*/test/*" -not -path "*/benchmark/*" -not -path "*/fuzz/*" -print0)
if [[ -n "$violations" ]]; then
  echo "src/ds production files include other CCF components:"
  echo "$violations"
  STATUS=1
else
  echo "No src/ds dependency violations"
fi

exit $STATUS
