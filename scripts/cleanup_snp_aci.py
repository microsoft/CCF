# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient

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
container_client = ContainerInstanceManagementClient(DefaultAzureCredential(), args.subscription_id)

try:
    # Delete the container groups
    for resource in resource_client.deployments.get(RESOURCE_GROUP, args.deployment_name).properties.output_resources:
        container_name = resource.id.split("/")[-1]
        container_group = container_client.container_groups.get(RESOURCE_GROUP, container_name)
        container_client.container_groups.begin_delete(RESOURCE_GROUP, container_name).wait()
    # Delete the deployment
    resource_client.deployments.begin_delete(RESOURCE_GROUP, args.deployment_name).wait()
except Exception as e:
    print(e)
