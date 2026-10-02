#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

case "${BUILD_SOURCEBRANCH:-}" in
    refs/tags/ccf-*)
        release_tag=${BUILD_SOURCEBRANCH#refs/tags/}
        ;;
    *)
        echo "PyPI releases must be queued from a ccf-* tag" >&2
        exit 1
        ;;
esac

output_dir=${BUILD_SOURCESDIRECTORY:-$PWD}/out
mkdir -p "$output_dir"

bash scripts/install_uv.sh /tmp/ccf-uv
uv=/tmp/ccf-uv/uv

package_version=$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("python/pyproject.toml", "rb"))["project"]["version"])'
)
expected_version=${release_tag#ccf-}
expected_version=${expected_version/-/.}
if [[ "$package_version" != "$expected_version" ]]; then
    echo "$release_tag maps to Python version $expected_version, but pyproject.toml contains $package_version" >&2
    exit 1
fi

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

"$uv" build --wheel python
mapfile -t wheels < <(
    find python/dist -maxdepth 1 -type f -name 'ccf-*.whl' -print
)
if [[ ${#wheels[@]} -ne 1 ]]; then
    echo "Expected exactly one CCF wheel" >&2
    exit 1
fi
wheel=${wheels[0]}

WHEEL="$wheel" EXPECTED_VERSION="$package_version" python3 - <<'PY'
import email.parser
import os
import zipfile

wheel_path = os.environ["WHEEL"]
with zipfile.ZipFile(wheel_path) as wheel:
    metadata_paths = [
        name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
    ]
    if len(metadata_paths) != 1:
        raise SystemExit(
            f"Expected one METADATA file in {wheel_path}, found {len(metadata_paths)}"
        )
    metadata = email.parser.BytesParser().parsebytes(wheel.read(metadata_paths[0]))

if metadata["Name"] != "ccf":
    raise SystemExit(f"Expected project name ccf, found {metadata['Name']}")
if metadata["Version"] != os.environ["EXPECTED_VERSION"]:
    raise SystemExit(
        f"Expected version {os.environ['EXPECTED_VERSION']}, "
        f"found {metadata['Version']}"
    )
PY

"$uv" venv /tmp/ccf-wheel-test
"$uv" pip install --python /tmp/ccf-wheel-test/bin/python "$wheel"
/tmp/ccf-wheel-test/bin/python -c "import ccf.cose, ccf.ledger"

cp "$wheel" "$output_dir/"
