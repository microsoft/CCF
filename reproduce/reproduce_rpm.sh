#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# This script is intended to be called from start_container_and_reproduce_rpm.sh script.
# builds the RPM using timestamps from the JSON and outputs the package.

set -exu

usage() {
  echo "Usage: $0 <reproduce_platform.json>"
  exit 1
}

setup_env() {
  PLATFORM=$(jq -r '.platform_name' "$REPRO_JSON")
  SOURCE_DATE_EPOCH=$(jq -r '.tdnf_snapshottime' "$REPRO_JSON")
  export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
  echo "Reproducing using SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

install_deps() {
  ./scripts/setup-ci.sh
}

build_pkg() {
  mkdir -p build && cd build
  echo "Reproducing devel package..."
  cmake -G Ninja -DCOMPILE_TARGET="$PLATFORM" -DCLIENT_PROTOCOLS_TEST=ON -DCMAKE_BUILD_TYPE=Release ..
  ninja -v
  cmake -L .. 2>/dev/null | grep CMAKE_INSTALL_PREFIX: | cut -d = -f 2 > /tmp/install_prefix
  cpack -V -G RPM
  for f in *.rpm; do
    if [[ "$f" == *devel* ]]; then
      D_INITIAL_PKG="$f"
      break
    fi
  done
  D_FINAL_PKG=${D_INITIAL_PKG//\~/_}
  if [ "$D_INITIAL_PKG" != "$D_FINAL_PKG" ]; then mv "$D_INITIAL_PKG" "$D_FINAL_PKG"; fi
  cp -v $D_FINAL_PKG /tmp/reproduced || true

  echo "Reproducing run package..."
  # Reset cmake config to affect cpack settings
  rm CMakeCache.txt
  cmake -G Ninja -DCOMPILE_TARGET="$PLATFORM"  -DCMAKE_BUILD_TYPE=Release -DCCF_DEVEL=OFF ..
  cmake -L .. 2>/dev/null | grep CMAKE_INSTALL_PREFIX: | cut -d = -f 2 > /tmp/install_prefix
  cpack -V -G RPM
  for f in *.rpm; do
    if [[ "$f" != *devel* ]]; then
      INITIAL_PKG="$f"
      break
    fi
  done
  FINAL_PKG=${INITIAL_PKG//\~/_}
  if [ "$INITIAL_PKG" != "$FINAL_PKG" ]; then mv "$INITIAL_PKG" "$FINAL_PKG"; fi
  cp -v $FINAL_PKG /tmp/reproduced || true

}

if [ "$#" -ne 1 ]; then
  usage
fi

REPRO_JSON="$1"
setup_env
install_deps
build_pkg

