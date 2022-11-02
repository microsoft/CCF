# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentProperties,
    DeploymentMode,
)

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
# TODO: Use "ubuntu:20.04" for faster deployment
IMAGE = "ccfmsrc.azurecr.io/ccf/ci/sgx:oe-0.18.2-protoc"

resource_client = ResourceManagementClient(DefaultAzureCredential(), args.subscription_id)

creation = resource_client.deployments.begin_create_or_update(
    RESOURCE_GROUP,
    args.deployment_name,
    Deployment(
        properties=DeploymentProperties(
            mode=DeploymentMode.INCREMENTAL,
            parameters={},
            template={
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {},
                "variables": {},
                "resources": [
                    {
                        "type": "Microsoft.ContainerInstance/containerGroups",
                        "apiVersion": "2022-04-01-preview",
                        "name": f"{args.deployment_name}",
                        "location": "westeurope",
                        "properties": {
                            "sku": "Standard",
                            "confidentialComputeProperties": {
                                "isolationType": "SevSnp",
                                "ccePolicy": "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19",
                            },
                            "containers": [
                                {
                                    "name": f"{args.deployment_name}",
                                    "properties": {
                                        "image": IMAGE,
                                        "command": ["tail", "-f", "/dev/null"],
                                        "ports": [
                                            {"protocol": "TCP", "port": 8000},
                                            {"protocol": "TCP", "port": 22},
                                        ],
                                        "environmentVariables": [],
                                        "resources": {
                                            "requests": {"memoryInGB": 16, "cpu": 4}
                                        },
                                    },
                                }
                            ],
                            "initContainers": [],
                            "restartPolicy": "Never",
                            "ipAddress": {
                                "ports": [
                                    {"protocol": "TCP", "port": 8000},
                                    {"protocol": "TCP", "port": 22},
                                ],
                                "type": "Public",
                            },
                            "osType": "Linux",
                        },
                    }
                ],
            },
        )
    ),
)
creation.wait()
