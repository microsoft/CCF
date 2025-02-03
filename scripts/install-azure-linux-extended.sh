#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

H2SPEC_VERSION="v2.6.0"

# protocoltest dependency
tdnf install -y bind-utils

# protocoltest dependency
curl -L --output h2spec_linux_amd64.tar.gz https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz
tar -xvf h2spec_linux_amd64.tar.gz
mkdir /opt/h2spec
mv h2spec /opt/h2spec/h2spec
