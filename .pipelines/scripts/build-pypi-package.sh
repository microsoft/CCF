#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

case "${BUILD_SOURCEBRANCH:-}" in
    refs/tags/ccf-*)
        ;;
    *)
        echo "PyPI releases must be queued from a ccf-* tag" >&2
        exit 1
        ;;
esac

output_dir=${BUILD_SOURCESDIRECTORY:-$PWD}/out
mkdir -p "$output_dir"

python3 -c 'import sys; sys.exit("CCF requires Python 3.12 or newer") if sys.version_info < (3, 12) else None'
./scripts/extract-release-notes.py --target-git-version >/dev/null

uv_install_dir=/tmp/ccf-uv
export PATH="$uv_install_dir:$PATH"
bash scripts/install_uv.sh "$uv_install_dir"
uv=$(command -v uv)

package_version=$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("python/pyproject.toml", "rb"))["project"]["version"])'
)

pypi_status=$(
    curl -sS -o /dev/null -w '%{http_code}' \
        "https://pypi.org/pypi/ccf/$package_version/json"
)
case "$pypi_status" in
    200)
        echo "ccf $package_version already exists on PyPI" >&2
        exit 1
        ;;
    404)
        ;;
    *)
        echo "Unexpected PyPI response for ccf $package_version: $pypi_status" >&2
        exit 1
        ;;
esac

rm -rf python/dist
"$uv" build --wheel python
mapfile -t wheels < <(
    find python/dist -maxdepth 1 -type f -name 'ccf-*.whl' -print
)
if [[ ${#wheels[@]} -ne 1 ]]; then
    echo "Expected exactly one CCF wheel" >&2
    exit 1
fi
wheel=${wheels[0]}

python3 scripts/validate_python_package.py "$wheel" "$package_version"

venv_dir=$(mktemp -d /tmp/ccf-wheel-test.XXXXXX)
cleanup() {
    if [[ -d "$venv_dir" && "$venv_dir" == /tmp/ccf-wheel-test.* ]]; then
        find "$venv_dir" -depth -delete
    fi
}
trap cleanup EXIT

"$uv" venv "$venv_dir"
"$uv" pip install --python "$venv_dir/bin/python" "$wheel"
"$venv_dir/bin/python" -c "import ccf.cose, ccf.ledger"

cp "$wheel" "$output_dir/"
wheel_sha256=$(sha256sum "$wheel")
echo "##vso[task.setvariable variable=wheel_sha256;isOutput=true]${wheel_sha256%% *}"
echo "##vso[task.setvariable variable=package_version;isOutput=true]$package_version"
