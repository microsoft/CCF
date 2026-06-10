#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Installs the dependencies required to run scripts/ci-checks.sh, limited to the
# formatting and linting checks. Works on both Azure Linux 3.0 (tdnf) and
# Ubuntu 24.04 (apt).
#
# Note: this deliberately does NOT install a C/C++ compiler, cmake or ninja, so
# the test-buckets check (which configures a build tree) is out of scope. All
# other checks - clang-format, prettier, black, ruff, mypy, gersemi,
# openapi-spec-validator, shellcheck, copyright and release-notes - are covered.

set -euo pipefail

log() {
  echo "-=[ $* ]=-"
}

# Detect the platform via /etc/os-release.
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  PLATFORM_ID="${ID:-unknown}"
else
  echo "Cannot read /etc/os-release; unsupported platform" >&2
  exit 1
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "This script needs root privileges (or sudo) to install packages" >&2
    exit 1
  fi
fi

install_packages_azurelinux() {
  log "Installing packages with tdnf (Azure Linux)"
  $SUDO tdnf -y install \
    ca-certificates \
    git \
    tar \
    curl \
    which \
    grep \
    gawk \
    sed \
    diffutils \
    coreutils \
    findutils \
    python3 \
    python3-pip \
    npm \
    jq \
    clang-tools-extra
}

install_packages_ubuntu() {
  log "Installing packages with apt (Ubuntu)"
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update
  # clang-format-18 matches the version pinned by scripts/check-format.sh.
  $SUDO apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    tar \
    curl \
    grep \
    gawk \
    findutils \
    python3 \
    python3-pip \
    npm \
    jq \
    clang-format-18
  # check-format.sh prefers clang-format-18, but fall back to a generic
  # clang-format symlink if one is not already present.
  if ! command -v clang-format >/dev/null 2>&1; then
    $SUDO ln -sf "$(command -v clang-format-18)" /usr/local/bin/clang-format
  fi
}

# uv provides the isolated Python tool runtime (uvx) used by black, ruff, mypy,
# gersemi and openapi-spec-validator.
install_uv() {
  if command -v uv >/dev/null 2>&1; then
    log "uv already installed ($(uv --version))"
    return
  fi
  log "Installing uv"
  curl -fsSL https://astral.sh/uv/install.sh | $SUDO env UV_INSTALL_DIR=/usr/local/bin sh
}

case "$PLATFORM_ID" in
  azurelinux | mariner)
    install_packages_azurelinux
    ;;
  ubuntu | debian)
    install_packages_ubuntu
    ;;
  *)
    echo "Unsupported platform: $PLATFORM_ID (expected azurelinux or ubuntu)" >&2
    exit 1
    ;;
esac

install_uv

log "All ci-checks formatting/lint dependencies installed"
log "Versions:"
echo "  git:          $(git --version)"
echo "  python3:      $(python3 --version 2>&1)"
echo "  npm:          $(npm --version 2>&1)"
echo "  clang-format: $( { command -v clang-format-18 >/dev/null 2>&1 && clang-format-18 --version; } || clang-format --version)"
echo "  shellcheck:   $(uvx --from shellcheck-py shellcheck --version | awk '/version:/ {print $2}')"
echo "  uv:           $(uv --version)"
