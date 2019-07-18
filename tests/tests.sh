#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ ! -f "env/bin/activate" ]
    then
        python3.7 -m venv env
fi

source env/bin/activate
pip install -q -U -r ../tests/requirements.txt

ctest "$@"
