#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3.7 -m venv env
fi
source env/bin/activate

PATH_HERE=$(dirname "$(realpath -s "$0")")

pip install -q -U -r "${PATH_HERE}"/tests/requirements.txt
echo "Python environment successfully setup"

CURL_CLIENT=ON \
    python "${PATH_HERE}"/tests/start_network.py \
    --gov-script "${PATH_HERE}"/src/runtime_config/gov.lua \
    --label test_network \
    "$@"