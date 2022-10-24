#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

## Install TLA+ Tools
{
    echo "alias tlcrepl='java -XX:+UseParallelGC -cp ~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar tlc2.REPL'"
    echo "alias tlc='java -XX:+UseParallelGC -cp ~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar tlc2.TLC'"
    echo "alias tlcmax4='java -XX:+UseParallelGC -XX:MaxDirectMemorySize=4g -Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet -Dtlc2.tool.ModelChecker.BAQueue=true -cp ~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar tlc2.TLC'"
    echo "alias tlcmax8='java -XX:+UseParallelGC -XX:MaxDirectMemorySize=8g -Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet -Dtlc2.tool.ModelChecker.BAQueue=true -cp ~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar tlc2.TLC'"
    echo "alias tlcmax16='java -XX:+UseParallelGC -XX:MaxDirectMemorySize=16g -Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet -Dtlc2.tool.ModelChecker.BAQueue=true -cp ~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar tlc2.TLC'"
    echo "alias tlcmax32='java -XX:+UseParallelGC -XX:MaxDirectMemorySize=32g -Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet -Dtlc2.tool.ModelChecker.BAQueue=true -cp ~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar tlc2.TLC'"
} >> "$HOME"/.bashrc

## Place to install TLAPS, Apalache, ...
mkdir -p tla/tools

## PATH below has two locations because of inconsistencies between Gitpod and Codespaces.
## Gitpod:     /workspace/...
## Codespaces: /workspaces/...

## Install TLAPS (proof system)
wget -N https://github.com/tlaplus/tlapm/releases/download/v1.4.5/tlaps-1.4.5-x86_64-linux-gnu-inst.bin -P /tmp
chmod +x /tmp/tlaps-1.4.5-x86_64-linux-gnu-inst.bin
/tmp/tlaps-1.4.5-x86_64-linux-gnu-inst.bin -d tla/tools/tlaps
echo "export PATH=\$PATH:/workspace/CCF/tla/tools/tlaps/bin:/workspaces/CCF/tla/tools/tlaps/bin" >> "$HOME"/.bashrc

## Install Apalache
wget -qN https://github.com/informalsystems/apalache/releases/latest/download/apalache.tgz -P /tmp
tar xvfz /tmp/apalache.tgz --directory tla/tools/
echo "export PATH=\$PATH:/workspace/CCF/tla/tools/apalache/bin:/workspaces/CCF/tla/tools/apalache/bin" >> "$HOME"/.bashrc

## (Moved to the end to let it run in the background while we get started)
## - graphviz to visualize TLC's state graphs
## - htop to show system load
## - texlive-latex-recommended to generate pretty-printed specs
## - z3 for Apalache (comes with z3 turnkey) (TLAPS brings its own install)
## - r-base iff tutorial covers statistics (TODO)
sudo apt-get install -y graphviz htop
## No need because Apalache comes with z3 turnkey
#sudo apt-get install -y z3 libz3-java
sudo apt-get install -y --no-install-recommends texlive-latex-recommended
#sudo apt-get install -y r-base
