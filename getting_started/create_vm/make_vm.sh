#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 SUBSCRIPTION_NAME [path/to/ssh/public/key]"
  exit 1
fi

# Azure Resource Group
RG=ccf-dev-rg
REGION=uksouth
CFG=vm.json

# By default, use current ssh public key
DEFAULT_PUBLIC_KEY_PATH=~/.ssh/id_rsa.pub
PUBLIC_KEY_PATH=${2:-${DEFAULT_PUBLIC_KEY_PATH}}

az login
az group create --name "$RG" --location "$REGION" --subscription "$1"
oe-engine generate --api-model "$CFG" --ssh-public-key "$PUBLIC_KEY_PATH" --output-directory generated
az deployment group create --name "$RG-$REGION" --resource-group "$RG" --template-file generated/azuredeploy.json --parameters @generated/azuredeploy.parameters.json --subscription "$1"
