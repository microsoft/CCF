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
  cmake -G Ninja -DCOMPILE_TARGET="$PLATFORM" -DCMAKE_BUILD_TYPE=Release -DCCF_DEVEL=OFF ..
  ninja -v
  cmake -L .. 2>/dev/null | grep CMAKE_INSTALL_PREFIX: | cut -d = -f 2 > /tmp/install_prefix
  cpack -V -G RPM
  for f in *.rpm; do
    if [[ "$f" != *devel*.rpm ]]; then
      initial_repro_run_pkg="$f"
      break
    fi
  done
  final_repro_run_pkg=${initial_repro_run_pkg//\~/_}
  if [ "$initial_repro_run_pkg" != "$final_repro_run_pkg" ]; then
    mv "$initial_repro_run_pkg" "$final_repro_run_pkg"
  fi
  cp -v $final_repro_run_pkg /tmp/reproduced || true
}

if [ "$#" -ne 1 ]; then
  usage
fi

REPRO_JSON="$1"
setup_env
install_deps
build_pkg

