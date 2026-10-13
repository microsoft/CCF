#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
umask 077

# postStartCommand backgrounds this script and redirects its output to the log.
: "${CODESPACE_NAME:?This startup script requires a Codespace}"
if [ -z "${COPILOTD_MISSION_CONTROL_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
  printf 'copilotd relay requires GITHUB_TOKEN or COPILOTD_MISSION_CONTROL_TOKEN\n' >&2
  exit 1
fi

export PATH="$HOME/.local/bin:$PATH"
# Reuse the installed binary across Codespace starts and daemon restarts.
if [ ! -x "$HOME/.local/bin/copilotd" ]; then
  curl -fsSL --retry 3 https://gh.io/copilotd-install \
    | COPILOTD_INSTALL_DIR="$HOME/.local/bin" bash
fi
if [ ! -x "$HOME/.local/bin/copilotd" ]; then
  printf 'copilotd installer did not create %s/.local/bin/copilotd\n' "$HOME" >&2
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
