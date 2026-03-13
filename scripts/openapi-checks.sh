#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Validates OpenAPI schema files via swagger-cli.
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

npm install --loglevel=error --no-save @apidevtools/swagger-cli 1>/dev/null || exit 1

find doc/schemas/*.json -exec npx swagger-cli validate {} \; || exit 1
find doc/schemas/gov/*/*.json -exec npx swagger-cli validate {} \;
