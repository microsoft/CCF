#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Validates OpenAPI schema files via swagger-cli.
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

if [ ! -x "$(command -v uv)" ]; then
  echo "uv is required but not installed. See https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

VALIDATOR="uvx --from openapi-spec-validator openapi-spec-validator"

$VALIDATOR doc/schemas/*.json || exit 1
$VALIDATOR doc/schemas/gov/*/*.json
