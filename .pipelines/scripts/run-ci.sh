#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

usage() {
    echo "Usage: $0 <virtual-a|virtual-b|virtual-c>" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi
workload=$1

output_dir=${BUILD_SOURCESDIRECTORY:-$PWD}/out
mkdir -p "$output_dir/logs"

copy_logs() {
    if [[ -d build/workspace ]]; then
        while IFS= read -r -d '' path; do
            relative_path=${path#build/workspace/}
            case "$relative_path" in
                *.config.json | */out | */err | */stack_trace | \
                    */openapi_coverage.json | *.ledger/* | *.ledger.*/*)
                    mkdir -p "$output_dir/logs/$(dirname "$relative_path")"
                    cp -a "$path" "$output_dir/logs/$relative_path" || true
                    ;;
            esac
        done < <(find build/workspace -type f -print0)
    fi
    return 0
}
trap copy_logs EXIT

if [[ $(id -u) -ne 0 ]] || ! command -v tdnf >/dev/null 2>&1; then
    echo "Virtual CI must run as root in an Azure Linux environment" >&2
    exit 1
fi
gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
tdnf -y update
./scripts/setup-ci.sh

case "$workload" in
    virtual-a)
        ./scripts/setup-dev.sh
        ./scripts/ci-checks.sh

        python3 -m venv --without-pip env
        # shellcheck disable=SC1091
        source env/bin/activate
        uv pip install -q pytest
        uv pip install -q -e python
        uv pip install -r doc/requirements.txt
        uv pip install -r doc/historical_ccf_requirements.txt

        cmake -S . -B build -GNinja \
            -DCMAKE_BUILD_TYPE=Debug \
            -DCLANG_TIDY=ON \
            -DDOCS_PYTHON="$PWD/env/bin/python"
        cmake --build build

        (
            cd python
            pytest
        )
        (
            cd build
            ./tests.sh --output-on-failure -L unit -j"$(nproc --all)"
            ./tests.sh --timeout 360 --output-on-failure -L bucket_a -j2
        )
        ;;
    virtual-b)
        python3 tests/infra/platform_detection.py virtual
        cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug
        cmake --build build --target bucket_b
        (
            cd build
            ./tests.sh --timeout 360 --output-on-failure -L bucket_b
        )
        ;;
    virtual-c)
        cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug
        cmake --build build --target bucket_c partitions
        (
            cd build
            ./tests.sh --timeout 360 --output-on-failure -L bucket_c
            ./tests.sh --timeout 360 --output-on-failure -L partitions -C partitions
        )
        ;;
    *)
        usage
        ;;
esac
