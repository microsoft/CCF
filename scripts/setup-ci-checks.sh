#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Installs the dependencies required to run scripts/ci-checks.sh, limited to the
# formatting and linting checks on Azure Linux 3 hosts.
#
# Note: this deliberately does NOT install a C/C++ compiler, cmake or ninja, so
# the test-buckets check (which configures a build tree) is out of scope. All
# other checks - clang-format, prettier, black, ruff, mypy, gersemi,
# openapi-spec-validator, shellcheck, copyright and release-notes - are covered.

set -euo pipefail

log() {
  echo "-=[ $* ]=-"
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "This script needs root privileges (or sudo) to install packages" >&2
    exit 1
  fi
fi

install_packages() {
  log "Installing packages with tdnf"
  $SUDO tdnf -y install \
    ca-certificates \
    git \
    tar \
    curl \
    grep \
    gawk \
    findutils \
    python3 \
    python3-pip \
    nodejs-npm \
    jq \
    clang-tools-extra
}

# uv provides the isolated Python tool runtime (uvx) used by black, ruff, mypy,
# gersemi and openapi-spec-validator.
install_uv() {
  if command -v uv >/dev/null 2>&1; then
    log "uv already installed ($(uv --version))"
    return
  fi
  log "Installing uv from PyPI"
  $SUDO python3 -m pip install --upgrade uv
}

install_packages
install_uv

log "All ci-checks formatting/lint dependencies installed"
log "Versions:"
echo "  git:          $(git --version)"
echo "  python3:      $(python3 --version 2>&1)"
echo "  npm:          $(npm --version 2>&1)"
echo "  clang-format: $( { command -v clang-format-18 >/dev/null 2>&1 && clang-format-18 --version; } || clang-format --version)"
echo "  shellcheck:   $(uvx --from shellcheck-py shellcheck --version | awk '/version:/ {print $2}')"
echo "  uv:           $(uv --version)"
