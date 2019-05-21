#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

CODECOV_TOKEN=cabeafff-d9e7-47cb-96b0-cb545e4b3ad9
for f in *profraw; do
    echo "$f" >> prof_files
done

llvm-profdata-7 merge -sparse -f prof_files -o coverage.profdata

objects=()
for f in *_test; do
    objects+=( -object "$f")
    llvm-cov-7 show -instr-profile "$f".profdata -output-dir=cov_"$f" -format=html "$f" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)"
done

llvm-cov-7 show -instr-profile coverage.profdata -output-dir=coverage -format=html ds_test "${objects[@]}" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)"
llvm-cov-7 export -instr-profile coverage.profdata -format=text ds_test "${objects[@]}" -Xdemangler c++filt -Xdemangler -n -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)" -summary-only > coverage.json

llvm-cov-7 show -instr-profile coverage.profdata -object channels_test -ignore-filename-regex="(boost|openenclave|3rdparty|/test/)" > coverage2.txt

bash <(curl -s https://codecov.io/bash) -t ${CODECOV_TOKEN} -f coverage2.txt || echo "Codecov did not collect coverage reports"

# mv cov_* coverage/

python3.7 ../tests/coverage/cobertura_generator.py
python3.7 ../tests/coverage/style_html.py
python3.7 ../tests/coverage/add_perf_summary.py