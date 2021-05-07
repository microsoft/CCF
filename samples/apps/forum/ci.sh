#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

CCF_APP_PKG_DIR="$SCRIPT_DIR/../../../js/ccf-app"
pushd "$CCF_APP_PKG_DIR"
npm install --no-package-lock
popd

pushd "$SCRIPT_DIR"
npm install --no-package-lock
unbuffer npm test
popd