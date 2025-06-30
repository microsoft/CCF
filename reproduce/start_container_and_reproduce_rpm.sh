#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# This script runs the build inside a container using info from the JSON file.
# Clones the repo at the specified commit and runs the reproduce_rpm.sh script.


set -exu

usage() {
  echo "Usage: $0 <reproduce_platform.json>"
  exit 1
}

setup_env() {
  IMAGE=$(jq -r '.build_container_image' "$REPRO_JSON")
  SOURCE_DATE_EPOCH=$(jq -r '.tdnf_snapshottime' "$REPRO_JSON")
  export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
}

if [ "$#" -ne 1 ]; then
  usage
fi

REPRO_JSON="$1"
setup_env

docker run --rm -it \
  -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -v "$(pwd)/reproduced":/tmp/reproduced \
  -v $REPRO_JSON:/reproduce.json \
  "$IMAGE" \
  bash -c '
    set -ex
    tdnf install --snapshottime=$SOURCE_DATE_EPOCH -y git jq
    COMMIT_ID=$(jq -r '.commit_sha' "/reproduce.json")
    echo "Cloning repo and checking out commit $COMMIT_ID"
    REPO_URL="https://github.com/microsoft/CCF"
    git clone "$REPO_URL" /CCF
    git config --global --add safe.directory /CCF
    cd /CCF
    git checkout "$COMMIT_ID"
    
    echo "Running reproduce script..."
    chmod +x ./reproduce/reproduce_rpm.sh
    ./reproduce/reproduce_rpm.sh /reproduce.json
  '
