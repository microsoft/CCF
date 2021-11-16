#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# This script is adapted from /opt/openenclave/bin/oelldb.
# It is used to run oelldb within the VS Code debugger.
# See .vscode/launch.json for details.

if ! command -v lldb-mi > /dev/null; then
  echo "lldb-mi not in PATH"
  echo "Run ./scripts/install-lldb-mi.sh to install"
  exit 1
fi

OE_LLDB_DIR=/opt/openenclave/bin

# Get the path to the debugger libraries relative to the oegdb path.
# Normalize the path by cd-ing and doing a pwd -P.
OE_LLDB_LIB_DIR=$(cd "$OE_LLDB_DIR/../lib/openenclave/debugger" || exit; pwd -P)

OE_LLDB_PLUGIN_DIR=$OE_LLDB_LIB_DIR/lldb-sgx-plugin
OE_LLDB_PTRACE_PATH=$OE_LLDB_LIB_DIR/liboe_ptrace.so

export PYTHONPATH=$OE_LLDB_PLUGIN_DIR
export LD_PRELOAD=$OE_LLDB_PTRACE_PATH

# Assume lldb-mi is on PATH
exec lldb-mi "$@"
