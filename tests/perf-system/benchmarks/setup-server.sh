#!/bin/bash
# Build CCF main from source for virtual and sgx

# Based on the following instructions:
# https://microsoft.github.io/CCF/main/build_apps/install_bin.html
# https://microsoft.github.io/CCF/main/contribute/build_ccf.html

git clone https://github.com/microsoft/CCF.git
cd CCF
git pull

cd getting_started/setup_vm/
./run.sh ccf-dev.yml --extra-vars "clang_version=15"
cd ../..

mkdir build-virtual
cd build-virtual
cmake -GNinja -DCOMPILE_TARGET=virtual ..
ninja
cd ..

cd getting_started/setup_vm/
./run.sh ccf-dev.yml
cd ../..

mkdir build-sgx
cd build-sgx
cmake -GNinja ..
ninja