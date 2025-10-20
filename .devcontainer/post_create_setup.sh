#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

./scripts/setup-ci.sh
./scripts/setup-dev.sh

git config --global --add safe.directory /workspaces/CCF

git config --global alias.st status
git config --global alias.ci commit
git config --global alias.br branch
git config --global alias.co checkout
