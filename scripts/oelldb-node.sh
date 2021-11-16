#!/bin/bash

# Debug a single node with oelldb after starting tests with -d.

THIS_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")

NODE=$1
if [ "$NODE" == "" ]; then
  NODE=0
fi

/opt/openenclave/bin/oelldb \
  -o "command script import ${THIS_DIR}/oelldb_helper.py" \
  -o "settings set target.process.stop-on-exec false" \
  -- /bin/bash /tmp/vscode-gdb.sh "$NODE"
