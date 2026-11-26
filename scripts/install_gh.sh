#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Installs a pinned GitHub CLI release, for distributions such as Azure Linux 4
# whose package repositories do not provide it.

set -euo pipefail

GH_VERSION=2.105.0
install_dir=${1:-/usr/local/bin}

if [[ -x "$install_dir/gh" ]] &&
    [[ "$("$install_dir/gh" --version)" == "gh version ${GH_VERSION} "* ]]; then
    exit 0
fi

case "$(uname -m)" in
    x86_64)
        arch=amd64
        sha256=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f
        ;;
    aarch64)
        arch=arm64
        sha256=b1278c75107423d818f1937fd92cafc9e5e9b606631568f68d7fb816f5885a02
        ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

archive="gh_${GH_VERSION}_linux_${arch}"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

curl --proto "=https" --tlsv1.2 -LsSf --retry 5 --retry-delay 5 \
    -o "$tmp_dir/gh.tar.gz" \
    "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${archive}.tar.gz"
echo "${sha256}  $tmp_dir/gh.tar.gz" | sha256sum --check --quiet

tar -xzf "$tmp_dir/gh.tar.gz" -C "$tmp_dir" "${archive}/bin/gh"
mkdir -p "$install_dir"
install -m 0755 "$tmp_dir/${archive}/bin/gh" "$install_dir/gh"

"$install_dir/gh" --version
