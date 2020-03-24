#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 SUBSCRIPTION_NAME"
  exit 1
fi

read -p "Are you sure [y/N]? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

# Azure Resource Group
RG=ccf-dev-rg

az group delete --name "$RG" --subscription "$1" -y
