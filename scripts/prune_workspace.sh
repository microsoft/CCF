#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -u

if [ "$#" -eq 0 ]; then
  echo "No args given - specify dir(s) to be formatted"
  exit 1
fi

WORKSPACE_DIR=$1
echo "Pruning ${WORKSPACE_DIR}"

size_before="$(du -sh ${WORKSPACE_DIR} | awk '{print $1}')"

find ${WORKSPACE_DIR} -type l -delete
find ${WORKSPACE_DIR} -type f -name cchost -delete
find ${WORKSPACE_DIR} -type f -name "*.so" -delete
find ${WORKSPACE_DIR} -type f -name "*.parquet" -delete
rm -rf ${WORKSPACE_DIR}/.npm

# Remove all but the latest snapshot
function prune_snapshot_dir(){
  pushd "${1}"
  ls -v | head -n -1 | xargs -d '\n' -r rm --
  popd
}

for snapshot_dir in $( find ${WORKSPACE_DIR} -type d -name "*.snapshots*" )
do
  prune_snapshot_dir $snapshot_dir
done

size_after="$(du -sh ${WORKSPACE_DIR} | awk '{print $1}')"

echo "Pruned from ${size_before} to ${size_after}"
