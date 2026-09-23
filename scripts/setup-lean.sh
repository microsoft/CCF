#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
export PATH="${ELAN_HOME:-$HOME/.elan}/bin:$PATH"

if ! command -v elan >/dev/null 2>&1; then
  ELAN_VERSION=4.2.4
  case "$(uname -m)" in
    x86_64|aarch64) target="$(uname -m)-unknown-linux-gnu" ;;
    *) echo "Unsupported architecture for elan: $(uname -m)" >&2; exit 1 ;;
  esac
  INSTALL_DIR=$(mktemp -d)
  trap 'rm -rf "$INSTALL_DIR"' EXIT
  curl --proto "=https" --tlsv1.2 -LsSf \
    "https://github.com/leanprover/elan/releases/download/v${ELAN_VERSION}/elan-${target}.tar.gz" |
    tar -xz -C "$INSTALL_DIR"
  "$INSTALL_DIR/elan-init" -y --no-modify-path --default-toolchain none
fi

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${ELAN_HOME:-$HOME/.elan}/bin" >> "$GITHUB_PATH"
fi

cd "$ROOT_DIR/lean/disaster-recovery"
lake --version
lake exe cache get
