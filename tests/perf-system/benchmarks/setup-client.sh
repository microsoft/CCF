#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Prepares the client to run piccolo

# https://microsoft.github.io/CCF/main/build_apps/install_bin.html

git clone https://github.com/microsoft/CCF.git
cd CCF/getting_started/setup_vm/ || exit
./run.sh ccf-dev.yml
cd ../.. || exit

# https://microsoft.github.io/CCF/main/architecture/performance/generator.html
cd tests/perf-system || exit
sudo apt install python3-pip
pip install -r requirements.txt
cd ../..

# https://microsoft.github.io/CCF/main/architecture/performance/submitter.html
mkdir build
cd build || exit
cmake -GNinja -DCOMPILE_TARGET=virtual ..
ninja submit
