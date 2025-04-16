#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

./scripts/setup-ci.sh
./scripts/setup-dev.sh

git config --global --add safe.directory /workspaces/CCF