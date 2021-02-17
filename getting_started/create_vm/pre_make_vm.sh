#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

OE_ENGINE_URL=https://oejenkinsciartifacts.blob.core.windows.net/oe-engine/latest/bin/oe-engine
OE_ENGINE_PATH=/usr/local/bin

if ! type az > /dev/null; then
    echo "Installing Azure CLI..."
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    echo "Azure CLI installed"
fi

if ! type $OE_ENGINE_PATH/oe-engine > /dev/null; then
    echo "Downloading oe-engine binary..."
    sudo wget "$OE_ENGINE_URL" -P "$OE_ENGINE_PATH"
    sudo chmod 755 "$OE_ENGINE_PATH"/oe-engine
    echo "oe-engine installed to ${OE_ENGINE_PATH}"
fi

echo "Azure CLI and oe-engine successfully installed."
echo "Run ./make_vm.sh to create CCF VM"