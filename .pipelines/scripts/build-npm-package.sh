#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

case "${BUILD_SOURCEBRANCH:-}" in
    refs/tags/ccf-*)
        ;;
    *)
        echo "npm releases must be queued from a ccf-* tag" >&2
        exit 1
        ;;
esac

package_version=${BUILD_SOURCEBRANCH#refs/tags/ccf-}
if [[ ! "$package_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Expected a stable or prerelease npm version, got $package_version" >&2
    exit 1
fi

output_dir=${BUILD_SOURCESDIRECTORY:-$PWD}/out
mkdir -p "$output_dir"

cd js/ccf-app
npm version "$package_version" --no-git-tag-version --ignore-scripts
if [[ "$(node -p 'require("./package.json").version')" != "$package_version" ]]; then
    echo "npm package version does not match the release tag" >&2
    exit 1
fi
npm install --no-package-lock --no-audit --no-fund
npm pack --pack-destination "$output_dir"

dist_tag=latest
if [[ "$package_version" == *-* ]]; then
    dist_tag=dev
fi
echo "##vso[task.setvariable variable=npm_dist_tag;isOutput=true]$dist_tag"
