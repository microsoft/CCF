#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
umask 077

# postStartCommand backgrounds this script and redirects its output to the log.
: "${CODESPACE_NAME:?This startup script requires a Codespace}"

export PATH="$HOME/.local/bin:$PATH"
# Refresh on every Codespace start, not on daemon restarts within this loop.
curl -fsSL --retry 3 https://gh.io/copilotd-install \
  | COPILOTD_VERSION=latest bash
if ! command -v copilotd >/dev/null; then
  printf 'copilotd is not on PATH after installation\n' >&2
  exit 1
fi

while true; do
  # A daemon failure must not stop the restart loop.
  status=0
  copilotd --relay \
    --environment-name "$CODESPACE_NAME" \
    --workspace "$PWD" \
    --project "$PWD" || status=$?
  printf 'copilotd exited with status %s; restarting in 10 seconds\n' "$status" >&2
  sleep 10
done
