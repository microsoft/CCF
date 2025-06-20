#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exuo pipefail


usage() {
  echo "Usage: $0 <platform>"
  exit 1
}

setup_env() {
  PLATFORM="$1"
  COMMIT_ID=${COMMIT_ID:-$(jq -r '.commit_sha' reproduce-"$PLATFORM".json)}
  snapshottime=${SOURCE_DATE_EPOCH:-$(jq -r 'tdnf_snapshottime' reproduce-"$PLATFORM".json)}
  export SOURCE_DATE_EPOCH="$snapshottime"
  echo "Reproducing using SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

install_deps() {
  ./scripts/setup-ci.sh
}

clone_repo() {
  # REPO_URL="https://github.com/microsoft/CCF"
  REPO_URL="/home/CCF"
  git config --global --add safe.directory /home/CCF/.git #deleteme when repourl is updated
  git clone -b "reproducibility-tests" "$REPO_URL" /CCF #deleteme
  # git clone "$REPO_URL" /CCF
  git config --global --add safe.directory /CCF
  cd /CCF
  
  echo "checking again 1"
  tail -n 10  cmake/cpack_settings.cmake
  git checkout "$COMMIT_ID"
  echo "checking again 2"
  tail -n 10  cmake/cpack_settings.cmake
}

build_devel_pkg() {
  mkdir -p build && cd build
  cmake -G Ninja -DCOMPILE_TARGET="$PLATFORM" -DCLIENT_PROTOCOLS_TEST=ON -DCMAKE_BUILD_TYPE=Release ..
  ninja -v
  cmake -L .. 2>/dev/null | grep CMAKE_INSTALL_PREFIX: | cut -d = -f 2 > /tmp/install_prefix
  cpack -V -G RPM
  INITIAL_PKG_DEVEL=$(ls *devel*.rpm)
  FINAL_PKG_DEVEL=${INITIAL_PKG_DEVEL//\~/_}
  if [ "$INITIAL_PKG_DEVEL" != "$FINAL_PKG_DEVEL" ]; then
    mv "$INITIAL_PKG_DEVEL" "$FINAL_PKG_DEVEL"
  fi
}

build_run_pkg() {
  rm -f CMakeCache.txt
  cmake -G Ninja -DCOMPILE_TARGET="$PLATFORM" -DCMAKE_BUILD_TYPE=Release -DCCF_DEVEL=OFF ..
  cmake -L .. 2>/dev/null | grep CMAKE_INSTALL_PREFIX: | cut -d = -f 2 > /tmp/install_prefix
  cpack -V -G RPM
  INITIAL_PKG_RUN=$(ls *.rpm | grep -v devel)
  FINAL_PKG_RUN=${INITIAL_PKG_RUN//\~/_}
  if [ "$INITIAL_PKG_RUN" != "$FINAL_PKG_RUN" ]; then
    mv "$INITIAL_PKG_RUN" "$FINAL_PKG_RUN"
  fi
}

verify_reproducibility() {
  OUTPUT_DIR=${OUTPUT_DIR:-/tmp/reproduced}
  DOWNLOAD_DIR=${DOWNLOAD_DIR:-/tmp/prebuilt}

  mkdir -p "$OUTPUT_DIR"
  cp "$FINAL_PKG_DEVEL" "$OUTPUT_DIR/"
  cp "$FINAL_PKG_RUN" "$OUTPUT_DIR/"
  cd ..

  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "FINAL_PKG_DEVEL=$FINAL_PKG_DEVEL" >> "$OUTPUT_DIR/rpm_output.env"
    echo "FINAL_PKG_RUN=$FINAL_PKG_RUN" >> "$OUTPUT_DIR/rpm_output.env"
    return
  fi


  for reproduced_pkg in "$FINAL_PKG_DEVEL" "$FINAL_PKG_RUN"; do
    tag=$(curl -s https://api.github.com/repos/microsoft/CCF/releases/latest | jq -r .tag_name)
    url="$REPO_URL/releases/download/$tag/$reproduced_pkg"
    echo "Downloading $url"
    mkdir -p "$DOWNLOAD_DIR"
    curl -sSL -o "$DOWNLOAD_DIR/$reproduced_pkg" "$url"
  done

  echo "Verifying reproducibility..."
    for reproduced_pkg in "${{ steps.reproduce.outputs.rpm_devel }}" "${{ steps.reproduce.outputs.rpm_run }}"; do
    echo "Checking $reproduced_pkg"
    sha256sum "$OUTPUT_DIR/$reproduced_pkg"
    sha256sum "$DOWNLOAD_DIR/$reproduced_pkg"
    if ! diff <(sha256sum "$OUTPUT_DIR/$reproduced_pkg" | awk '{print $1}') <(sha256sum "$DOWNLOAD_DIR/$reproduced_pkg" | awk '{print $1}'); then
        echo "Failed to reproduce $reproduced_pkg!"
        exit 1
    fi
    echo "Reproducibility verified for $reproduced_pkg"
    done
}

if [ "$#" -ne 1 ]; then usage; fi


PLATFORM="$1"
setup_env "$PLATFORM"
install_deps
clone_repo
build_devel_pkg
build_run_pkg
verify_reproducibility
