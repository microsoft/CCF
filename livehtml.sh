#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

echo "Generate version.py if it doesn't already exist"
if [ ! -f "python/version.py" ]
    then
        mkdir -p tmp_build
        cd tmp_build
        cmake -L -GNinja -DCOMPILE_TARGET=virtual ..
        cd ..
        rm -rf tmp_build
fi

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3.8 -m venv env
fi

source env/bin/activate
pip install -U pip
pip install -q -U -e ./python/
pip install -q -U -r ./doc/requirements.txt
echo "Python environment successfully setup"

sphinx-autobuild -b html doc doc/html --host localhost --port 8080