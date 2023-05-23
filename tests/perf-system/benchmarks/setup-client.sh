#!/bin/bash
# Prepares the client to run piccolo

# https://microsoft.github.io/CCF/main/build_apps/install_bin.html

git clone https://github.com/microsoft/CCF.git
cd CCF
cd getting_started/setup_vm/
./run.sh ccf-dev.yml
cd ../..

# https://microsoft.github.io/CCF/main/architecture/performance/generator.html
cd tests/perf-system
sudo apt install python3-pip
pip install -r requirements.txt
cd ../..

# https://microsoft.github.io/CCF/main/architecture/performance/submitter.html
mkdir build
cd build
cmake -GNinja -DCOMPILE_TARGET=virtual ..
ninja submit
