#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Build CCF main from source for virtual and sgx

# Based on the following instructions:
# https://microsoft.github.io/CCF/main/build_apps/install_bin.html
# https://microsoft.github.io/CCF/main/contribute/build_ccf.html

git clone https://github.com/microsoft/CCF.git
cd CCF || exit
git pull

cd getting_started/setup_vm/ || exit
./run.sh ccf-dev.yml --extra-vars "clang_version=15"
cd ../.. || exit

mkdir build-virtual
cd build-virtual || exit
cmake -GNinja -DCOMPILE_TARGET=virtual ..
ninja
cd ..

cd getting_started/setup_vm/ || exit
./run.sh ccf-dev.yml
cd ../.. || exit

mkdir build-sgx
cd build-sgx || exit
cmake -GNinja ..
ninja