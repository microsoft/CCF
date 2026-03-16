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

exit $STATUS
