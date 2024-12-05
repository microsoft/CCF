#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex
BASEDIR=$(dirname "$0")
docker build -t "ccf:js-virtual" -f $BASEDIR/app_virtual_cchost $BASEDIR/../build
