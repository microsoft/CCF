#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3.8 -m venv env
fi

source env/bin/activate
pip install --disable-pip-version-check -q -U -e ./python/
pip install --disable-pip-version-check -q -U -r ./doc/requirements.txt
npm install typescript typedoc@0.19.2
NPM_BIN=$(pwd)/node_modules/.bin
export PATH="$NPM_BIN:$PATH"
echo "Python environment successfully setup"

sphinx-autobuild -b html doc doc/html --host localhost --port 8080