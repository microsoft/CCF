#!/bin/bash

set -e

LLVM_VERSION=10

echo " + Installing build dependencies"
sudo apt-get update
sudo apt-get install -y llvm-$LLVM_VERSION-dev liblldb-$LLVM_VERSION-dev

echo " + Fetching sources"
git clone https://github.com/lldb-tools/lldb-mi --depth 1
cd lldb-mi

echo " + Building"
export CC=clang-$LLVM_VERSION
export CXX=clang++-$LLVM_VERSION
cmake \
  -GNinja \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_PREFIX_PATH=/usr/lib/llvm-$LLVM_VERSION .
ninja

echo " + Installing"
sudo ninja install

echo " + Cleaning up"
cd ..
rm -rf lldb-mi

echo " + All done"
