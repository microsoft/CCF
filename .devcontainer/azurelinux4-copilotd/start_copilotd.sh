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
  version=1.0.1
  arch=$(uname -m)
  case "$arch" in
    x86_64) sha256=a1f351545590304ddfe663fea96495ad57e7c8b5301ef528ee9868f52ebf4038 ;;
    aarch64) sha256=339e0d2ac03e4aacf164c7d848a274592c5b5f04df6960e91974d5f8965b3ec2 ;;
    *) printf 'Unsupported copilotd architecture: %s\n' "$arch" >&2; exit 1 ;;
  esac
  archive="copilotd-$version-$arch-unknown-linux-gnu.tar.gz"
  temp_dir=$(mktemp -d)
  trap 'rm -rf "$temp_dir"' EXIT

  # Resolve only the mirror's signed access URL; never execute its installer.
  mirror=https://copilotd.blob.core.windows.net/release
  redirect=$(curl -fsSLI --retry 3 --output /dev/null \
    --write-out '%{url_effective}' https://gh.io/copilotd-install)
  if [[ "$redirect" != "$mirror/install.sh?"* ]]; then
    printf 'Unexpected copilotd mirror URL\n' >&2
    exit 1
  fi
  sas=${redirect#*\?}
  if [[ ! "$sas" =~ ^[a-zA-Z0-9%._~=:\&+/-]+$ ]]; then
    printf 'Invalid copilotd mirror access query\n' >&2
    exit 1
  fi

  # Pass the signed URL through stdin so its credential is not exposed in argv.
  printf 'url = "%s/v%s/%s?%s"\n' "$mirror" "$version" "$archive" "$sas" \
    | curl --config - -fsSL --retry 3 --output "$temp_dir/$archive"
  printf '%s  %s\n' "$sha256" "$temp_dir/$archive" | sha256sum --check
  tar -xzf "$temp_dir/$archive" -C "$temp_dir" "${archive%.tar.gz}/copilotd"
  mkdir -p "$HOME/.local/bin"
  install -m 0755 "$temp_dir/${archive%.tar.gz}/copilotd" "$HOME/.local/bin/copilotd"
  rm -rf "$temp_dir"
  trap - EXIT
fi
if [ ! -x "$HOME/.local/bin/copilotd" ]; then
  printf 'copilotd installation did not create %s/.local/bin/copilotd\n' "$HOME" >&2
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
