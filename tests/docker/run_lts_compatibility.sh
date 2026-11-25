#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

# With --check-ledger-compatibility, the test also recovers the ledger and
# snapshots of each supported LTS release in turn, up to TO_INSTALL_TAR. It
# downloads those releases, and runs each in a container built from the base
# image of the distribution it was built for.
CHECK_LEDGER_COMPATIBILITY=false
if [[ "${1:-}" == "--check-ledger-compatibility" ]]; then
  CHECK_LEDGER_COMPATIBILITY=true
  shift
fi

if (( $# != 5 )); then
  echo "Usage: $0 [--check-ledger-compatibility] FROM_INSTALL_TAR FROM_BASE_IMAGE TO_INSTALL_TAR TO_BASE_IMAGE WORKSPACE" >&2
  exit 1
fi

FROM_INSTALL_TAR=$(realpath "$1")
FROM_BASE_IMAGE=$2
TO_INSTALL_TAR=$(realpath "$3")
TO_BASE_IMAGE=$4
WORKSPACE=$(realpath -m "$5")

for archive in "$FROM_INSTALL_TAR" "$TO_INSTALL_TAR"; do
  if [[ ! -f "$archive" ]]; then
    echo "Install archive not found: $archive" >&2
    exit 1
  fi
done

REQUIRED_COMMANDS=(docker python3 tar)
EXTRA_TEST_ARGS=()
if [[ "$CHECK_LEDGER_COMPATIBILITY" == true ]]; then
  # Release packages are unpacked on the host
  REQUIRED_COMMANDS+=(rpm2cpio cpio)
  EXTRA_TEST_ARGS+=(
    --check-ledger-compatibility
    --azure-linux-3-base-image "$FROM_BASE_IMAGE"
    --azure-linux-4-base-image "$TO_BASE_IMAGE"
  )
fi

for command in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done
docker info >/dev/null

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEMP_DIR=$(mktemp -d)
FROM_IMAGE="ccf-lts-from-$$"
TO_IMAGE="ccf-lts-to-$$"

cleanup() {
  docker image rm --force "$FROM_IMAGE" "$TO_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR/from" "$TEMP_DIR/to" "$WORKSPACE"
tar -xzf "$FROM_INSTALL_TAR" -C "$TEMP_DIR/from"
tar -xzf "$TO_INSTALL_TAR" -C "$TEMP_DIR/to"

for install_dir in "$TEMP_DIR/from/opt/ccf" "$TEMP_DIR/to/opt/ccf"; do
  if [[ ! -f "$install_dir/share/VERSION" ]]; then
    echo "Archive does not contain opt/ccf/share/VERSION: $install_dir" >&2
    exit 1
  fi
done

docker build \
  --build-arg "BASE_IMAGE=$FROM_BASE_IMAGE" \
  --file "$REPO_ROOT/tests/docker/lts_compatibility/Dockerfile" \
  --tag "$FROM_IMAGE" \
  "$TEMP_DIR/from"
docker build \
  --build-arg "BASE_IMAGE=$TO_BASE_IMAGE" \
  --file "$REPO_ROOT/tests/docker/lts_compatibility/Dockerfile" \
  --tag "$TO_IMAGE" \
  "$TEMP_DIR/to"

TO_VERSION=$(<"$TEMP_DIR/to/opt/ccf/share/VERSION_LONG")

cd "$REPO_ROOT"
python3 tests/lts_compatibility.py \
  --ccf-version "$TO_VERSION" \
  --release-install-path "$TEMP_DIR/from/opt/ccf" \
  --release-install-image "$FROM_IMAGE" \
  --local-install-path "$TEMP_DIR/to/opt/ccf" \
  --local-install-image "$TO_IMAGE" \
  --constitution "$REPO_ROOT/samples/constitutions/default/actions.js" \
  --constitution "$REPO_ROOT/samples/constitutions/default/validate.js" \
  --constitution "$REPO_ROOT/samples/constitutions/default/resolve.js" \
  --constitution "$REPO_ROOT/samples/constitutions/default/apply.js" \
  --constitution "$REPO_ROOT/samples/constitutions/virtual/virtual_attestation_actions.js" \
  --workspace "$WORKSPACE" \
  --label cross_platform_lts \
  --compatibility-report-file "$WORKSPACE/compatibility_report.json" \
  "${EXTRA_TEST_ARGS[@]}"
