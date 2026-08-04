#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Prints build-tool versions for the requested toolchains in argument order.
#
# Usage: scripts/capture-build-info.sh <toolchain>...
#   toolchain: rust, wasm, or dotnet

set -euo pipefail

usage() {
  echo "Usage: $0 <toolchain>... (valid toolchains: rust, wasm, dotnet)" >&2
}

if [[ "$#" -eq 0 ]]; then
  usage
  exit 1
fi

required_tools=()
for toolchain in "$@"; do
  case "${toolchain}" in
    rust)
      required_tools+=(rustc cargo)
      ;;
    wasm)
      required_tools+=(wasm-pack)
      ;;
    dotnet)
      # OpenSSL is part of the native .NET package build environment.
      required_tools+=(dotnet openssl)
      ;;
    *)
      echo "Unknown toolchain '${toolchain}' (valid toolchains: rust, wasm, dotnet)" >&2
      exit 1
      ;;
  esac
done

for tool in "${required_tools[@]}"; do
  if ! command -v "${tool}" > /dev/null; then
    echo "Required tool '${tool}' was not found on PATH" >&2
    exit 1
  fi
done

emitted=false
emit_section() {
  local heading="$1"
  shift

  if [[ "${emitted}" == true ]]; then
    echo
  fi
  echo "## ${heading}"
  "$@"
  emitted=true
}

for toolchain in "$@"; do
  case "${toolchain}" in
    rust)
      emit_section rustc rustc --version --verbose
      emit_section cargo cargo --version --verbose
      ;;
    wasm)
      emit_section wasm-pack wasm-pack --version
      ;;
    dotnet)
      emit_section dotnet dotnet --info
      emit_section openssl openssl version -a
      ;;
  esac
done
