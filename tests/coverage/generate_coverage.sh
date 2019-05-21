#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

for f in *profraw; do
    echo "$f" >> prof_files
done

# Generate html coverage report for individual unit test
objects=()
for f in *_test; do
    objects+=( -object "$f")
    llvm-cov-7 show -instr-profile "$f".profdata -output-dir=cov_"$f" -format=html "$f" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)"
done

# Merge coverage report for all unit tests
llvm-profdata-7 merge -sparse -f prof_files -o coverage.profdata

# Generate combined coverage report
llvm-cov-7 show -instr-profile coverage.profdata -output-dir=coverage -format=html "${objects[@]}" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)"
llvm-cov-7 export -instr-profile coverage.profdata -format=text "${objects[@]}" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)" -summary-only > coverage.json

# Generate and upload combined coverage report for Codecov
llvm-cov-7 show -instr-profile coverage.profdata "${objects[@]}" -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)" > codecov.txt
bash <(curl -s https://codecov.io/bash) -t "${CODECOV_TOKEN}" -f codecov.txt

# Generate html for Azure Devops
mv cov_* coverage/
python3.7 ../tests/coverage/cobertura_generator.py
python3.7 ../tests/coverage/style_html.py

# Add coverage results to perf summary file
python3.7 ../tests/coverage/add_perf_summary.py