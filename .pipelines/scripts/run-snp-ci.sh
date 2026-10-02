#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

output_dir=${BUILD_SOURCESDIRECTORY:-$PWD}/out
mkdir -p "$output_dir/logs"

capture_diagnostics() {
    df -kh > "$output_dir/logs/disk-usage.log" || true
    mount > "$output_dir/logs/mounts.log" || true
    cat /proc/cpuinfo > "$output_dir/logs/cpuinfo.log" || true
    dmesg > "$output_dir/logs/dmesg.log" || true
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
trap capture_diagnostics EXIT

{ cat /proc/*/environ 2>/dev/null || true; } |
    tr '\000' '\n' |
    sort -u |
    grep Fabric_NodeIPOrFQDN > /Fabric_NodeIPOrFQDN

python3 tests/infra/platform_detection.py snp genoa

cmake -S . -B build -GNinja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWORKER_THREADS=1
cmake --build build --target snp code_update_test ledger_bench

(
    cd build
    ./tests.sh --timeout 360 --output-on-failure -C snp -L snp
    ./tests.sh --timeout 360 --output-on-failure -R code_update
    ./tests.sh --timeout 360 -V -R '^ledger_bench$'
)
