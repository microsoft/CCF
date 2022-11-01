# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import argparse

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

parser = argparse.ArgumentParser(
    description="Deploy an Azure Container Instance",
)

parser.add_argument(
    "--subscription-id",
    help="The subscription ID used to provision the container instance",
    type=str,
)

args = parser.parse_args()

RESOURCE_GROUP = "ccf-aci"
IMAGE = "ccfmsrc.azurecr.io/ccf/ci/sgx:oe-0.18.2-protoc"
DEPLOYMENT = "snp-ci"

resource_client = ResourceManagementClient(DefaultAzureCredential(), args.subscription_id)

try:
    deletion = resource_client.deployments.begin_delete(RESOURCE_GROUP, DEPLOYMENT)
    deletion.wait()
except Exception:
    ...
