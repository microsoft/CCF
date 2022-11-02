# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

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

parser.add_argument(
    "--deployment-name",
    help="The name of the ACI deployment, used for agent names and cleanup",
    type=str,
)

args = parser.parse_args()

RESOURCE_GROUP = "ccf-aci"

resource_client = ResourceManagementClient(DefaultAzureCredential(), args.subscription_id)

try:
    deletion = resource_client.deployments.begin_delete(RESOURCE_GROUP, args.deployment_name)
    deletion.wait()
except Exception as e:
    print(e)
