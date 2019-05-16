#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

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

mv cov_* coverage/

python3.7 ../tests/coverage/cobertura_generator.py
python3.7 ../tests/coverage/style_html.py