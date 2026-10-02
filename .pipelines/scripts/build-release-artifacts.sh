#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

build_image=mcr.microsoft.com/azurelinux/base/core:3.0

for command in docker git jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "The release agent requires $command" >&2
        exit 1
    fi
done

case "${BUILD_SOURCEBRANCH:-}" in
    refs/tags/ccf-*)
        release_tag=${BUILD_SOURCEBRANCH#refs/tags/}
        ;;
    *)
        echo "Release artifacts must be built from a ccf-* tag" >&2
        exit 1
        ;;
esac

source_date_epoch=$(date +%s)
docker pull "$build_image"
build_image_digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$build_image")

docker run --rm \
    --user root \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    --cap-add SYS_PTRACE \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    -e BUILD_SOURCEBRANCH="$BUILD_SOURCEBRANCH" \
    -e BUILD_SOURCESDIRECTORY=/workspace \
    -e CI=true \
    -e SOURCE_DATE_EPOCH="$source_date_epoch" \
    -v "$PWD:/workspace" \
    -w /workspace \
    "$build_image_digest" \
    bash .pipelines/scripts/build-release-in-container.sh

commit_sha=$(git rev-parse HEAD)
jq -n \
    --arg build_container_image "$build_image_digest" \
    --argjson tdnf_snapshottime "$source_date_epoch" \
    --arg commit_sha "$commit_sha" \
    '{
        build_container_image: $build_container_image,
        tdnf_snapshottime: $tdnf_snapshottime,
        commit_sha: $commit_sha
    }' > out/reproduce.json

reproduced_dir=$PWD/out/reproduced
mkdir -p "$reproduced_dir"
docker run --rm \
    --user root \
    -e SOURCE_DATE_EPOCH="$source_date_epoch" \
    -v "$reproduced_dir:/tmp/reproduced" \
    -v "$PWD/out/reproduce.json:/reproduce.json:ro" \
    "$build_image_digest" \
    bash -c '
        set -euo pipefail
        tdnf install --snapshottime="$SOURCE_DATE_EPOCH" -y git jq ca-certificates
        git clone https://github.com/microsoft/CCF CCF
        cd CCF
        git checkout "$(jq -r .commit_sha /reproduce.json)"
        find . -type f -exec touch {} +
        ./reproduce/reproduce_rpm.sh /reproduce.json
    '

mapfile -t packages < <(find out/rpm -maxdepth 1 -type f -name '*.rpm' -print)
mapfile -t reproduced_packages < <(
    find out/reproduced -maxdepth 1 -type f -name '*.rpm' -print
)
if [[ ${#packages[@]} -ne 1 || ${#reproduced_packages[@]} -ne 1 ]]; then
    echo "Expected exactly one original and one reproduced RPM" >&2
    exit 1
fi
cmp "${packages[0]}" "${reproduced_packages[0]}"
