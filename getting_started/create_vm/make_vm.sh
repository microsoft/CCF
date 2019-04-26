#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Azure Resource Group
RG=ccf-dev
# Region, only eastus and westeurope are supported at the moment
REGION=eastus
CFG=vm.json

az group create --name "$RG" --location "$REGION" --subscription "$SUBSCRIPTION"
oe-engine generate --api-model "$CFG" --ssh-public-key ~/.ssh/id_rsa.pub --output-directory generated
az group deployment create --name "$RG-$REGION" --resource-group "$RG" --template-file generated/azuredeploy.json --parameters @generated/azuredeploy.parameters.json --subscription "$SUBSCRIPTION"
