#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks Markdown and RST prose for arbitrary mid-sentence newlines.
# Pass -f to rewrite affected paragraphs with one sentence per line.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

if [ "${1:-}" == "-f" ]; then
  FIX_ARGS=(--fix)
  shift
else
  FIX_ARGS=()
fi

"$SCRIPT_DIR"/doc-newline-check.py "${FIX_ARGS[@]}" "$@"
