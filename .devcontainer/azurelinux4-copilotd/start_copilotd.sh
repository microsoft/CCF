#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
umask 077

supervise() {
  local workspace=$1
  local child=""
  local status

  cleanup() {
    if [ -n "$child" ]; then
      kill "$child" 2>/dev/null || true
      wait "$child" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT
  trap 'exit 0' TERM INT

  while true; do
    "$HOME/.local/bin/copilotd" --relay \
      --environment-name "$CODESPACE_NAME" \
      --workspace "$workspace" \
      --project "$workspace" &
    child=$!
    status=0
    wait "$child" || status=$?
    child=""
    printf 'copilotd exited with status %s; restarting in 10 seconds\n' "$status" >&2
    sleep 10 &
    child=$!
    wait "$child"
    child=""
  done
}

if [ "${1:-}" = "--supervise" ]; then
  # The launcher passes its locked descriptor through nohup and bash.
  flock -n 9
  supervise "${2:?Missing workspace}"
  exit 0
fi

: "${CODESPACE_NAME:?This startup script requires a Codespace}"
if [ -z "${COPILOTD_MISSION_CONTROL_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
  printf 'copilotd relay requires GITHUB_TOKEN or COPILOTD_MISSION_CONTROL_TOKEN\n' >&2
  exit 1
fi

workspace=$(pwd -P)
script=$(realpath "${BASH_SOURCE[0]}")
state_dir="$HOME/.local/state/ccf-copilotd"
mkdir -p "$state_dir"
exec 9>"$state_dir/lock"
if ! flock -n 9; then
  printf 'copilotd supervisor is already running; log: %s/copilotd.log\n' "$state_dir"
  exit 0
fi

export PATH="$HOME/.local/bin:$PATH"
if [ ! -x "$HOME/.local/bin/copilotd" ]; then
  curl -fsSL --retry 3 https://gh.io/copilotd-install \
    | COPILOTD_INSTALL_DIR="$HOME/.local/bin" bash
fi
if [ ! -x "$HOME/.local/bin/copilotd" ]; then
  printf 'copilotd installer did not create %s/.local/bin/copilotd\n' "$HOME" >&2
  exit 1
fi

nohup bash "$script" --supervise "$workspace" \
  </dev/null >>"$state_dir/copilotd.log" 2>&1 &
supervisor=$!
sleep 1
if ! kill -0 "$supervisor" 2>/dev/null; then
  printf 'copilotd supervisor failed to start; see %s/copilotd.log\n' "$state_dir" >&2
  exit 1
fi
printf 'copilotd supervisor started (PID %s); log: %s/copilotd.log\n' "$supervisor" "$state_dir"
