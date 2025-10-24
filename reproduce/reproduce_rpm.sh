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
  SOURCE_DATE_EPOCH=$(jq -r '.tdnf_snapshottime' "$REPRO_JSON")
  export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
  echo "Reproducing using SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

install_deps() {
  ./scripts/setup-ci.sh
}

build_pkg() {
  mkdir -p /tmp/reproduced
  mkdir -p build && cd build
  echo "Reproducing CCF package..."
  cmake -G Ninja -DCLIENT_PROTOCOLS_TEST=ON -DCMAKE_BUILD_TYPE=Release ..
  ninja -v
  rm CMakeCache.txt
  cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
  cmake -L .. 2>/dev/null | grep CMAKE_INSTALL_PREFIX: | cut -d = -f 2 > /tmp/install_prefix
  cpack -V -G RPM
  D_INITIAL_PKG=`ls *.rpm`
  D_FINAL_PKG=${D_INITIAL_PKG//\~/_}
  if [ "$D_INITIAL_PKG" != "$D_FINAL_PKG" ]; then mv "$D_INITIAL_PKG" "$D_FINAL_PKG"; fi
  cp -v $D_FINAL_PKG /tmp/reproduced || true
}

if [ "$#" -ne 1 ]; then
  usage
fi

REPRO_JSON="$1"
setup_env
install_deps
build_pkg

