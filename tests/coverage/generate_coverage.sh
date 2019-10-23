#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

suffix=$1

LLVM_VER=8
LLVM_COV=llvm-cov-${LLVM_VER}
LLVM_PROFDATA=llvm-profdata-${LLVM_VER}

objects=()
for f in *_test; do
    objects+=( -object "$f")
    echo "$f".profraw >> prof_files
done

# Merge coverage report for all unit tests
${LLVM_PROFDATA} merge -sparse -f prof_files -o coverage.profdata

# Generate combined coverage report
${LLVM_COV} show -instr-profile coverage.profdata -output-dir=coverage -format=html "${objects[@]}" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(openenclave|3rdparty|/test/)"
${LLVM_COV} export -instr-profile coverage.profdata -format=text "${objects[@]}" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(openenclave|3rdparty|/test/)" -summary-only > coverage.json

# Generate and upload combined coverage report for Codecov
${LLVM_COV} show -instr-profile coverage.profdata "${objects[@]}" -ignore-filename-regex="(openenclave|3rdparty|/test/)" > codecov.txt
bash <(curl -s https://codecov.io/bash) -t "${CODECOV_TOKEN}" -f codecov.txt -F "unit_${suffix}"

for e2e in *.virtual.so; do
    if compgen -G "./*_$e2e.profraw"; then
        ${LLVM_PROFDATA} merge -sparse ./*_"$e2e".profraw -o "$e2e".profdata
        ${LLVM_COV} show -instr-profile "$e2e".profdata -object cchost.virtual -object "$e2e" -ignore-filename-regex="(openenclave|3rdparty|/test/)" > "$e2e".txt
        bash <(curl -s https://codecov.io/bash) -t "${CODECOV_TOKEN}" -f "$e2e".txt -F "$(echo $"e2e" | cut -d. -f1)_$suffix"
    fi
done