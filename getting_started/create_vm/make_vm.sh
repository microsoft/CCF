#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Azure Resource Group
RG=ccf-dev
# Region, only eastus and westeurope are supported at the moment
REGION=eastus
CFG=vm.json

# By default, use current ssh public key
DEFAULT_PUBLIC_KEY_PATH=~/.ssh/id_rsa.pub
PUBLIC_KEY_PATH=${1:-${DEFAULT_PUBLIC_KEY_PATH}}

az login
az group create --name "$RG" --location "$REGION" --subscription "$SUBSCRIPTION"
oe-engine generate --api-model "$CFG" --ssh-public-key "$PUBLIC_KEY_PATH" --output-directory generated
az group deployment create --name "$RG-$REGION" --resource-group "$RG" --template-file generated/azuredeploy.json --parameters @generated/azuredeploy.parameters.json --subscription "$SUBSCRIPTION"
