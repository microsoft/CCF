#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) formatting for TypeScript, JavaScript,
# Markdown, TypeSpec, YAML, and JSON files via prettier.
# Pass -f to auto-fix formatting issues.

set -uo pipefail

if [ "${1:-}" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

NPM_DIR=$(mktemp -d)
trap 'rm -rf "$NPM_DIR"' EXIT
npm install --loglevel=error --no-save --prefix "$NPM_DIR" prettier @typespec/prettier-plugin-typespec 1>/dev/null || exit 1

if [ $FIX -ne 0 ]; then
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | grep -v -e 'tests/sandbox/' | xargs npx --prefix "$NPM_DIR" prettier --write
else
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | grep -v -e 'tests/sandbox/' | xargs npx --prefix "$NPM_DIR" prettier --check
fi
