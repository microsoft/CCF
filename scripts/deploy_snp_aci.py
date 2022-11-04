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
    "--storage-key",
    help="The key for the CCF ACI mounted volume",
    type=str,
)

parser.add_argument(
    "--deployment-name",
    help="The name of the ACI deployment, used for agent names and cleanup",
    type=str,
)

parser.add_argument(
    "--count",
    "-c",
    help="The number of container instances to deploy",
    type=int,
    default=1,
)

args = parser.parse_args()

RESOURCE_GROUP = "ccf-aci"
# TODO: Use "ubuntu:20.04" for faster deployment
# IMAGE = "ubuntu:20.04"
IMAGE = "ccfmsrc.azurecr.io/ccf/ci:oe-0.18.2-snp"
HOST_PUB_KEY = open("/root/.ssh/id_rsa.pub", "r").read().replace("\n", "")

resource_client = ResourceManagementClient(DefaultAzureCredential(), args.subscription_id)
container_client = ContainerInstanceManagementClient(DefaultAzureCredential(), args.subscription_id)

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
                        "name": f"{args.deployment_name}-{i}",
                        "location": "westeurope",
                        "properties": {
                            "sku": "Standard",
                            "confidentialComputeProperties": {
                                "isolationType": "SevSnp",
                                "ccePolicy": "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19",
                            },
                            "containers": [
                                {
                                    "name": f"{args.deployment_name}-{i}",
                                    "properties": {
                                        "image": IMAGE,
                                        "command": [
                                            "/bin/sh",
                                            "-c",
                                            " && ".join([
                                                "apt-get update",
                                                "apt-get install -y openssh-server",
                                                "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
                                                "sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/g' /etc/ssh/sshd_config",
                                                "service ssh restart",
                                                "mkdir /root/.ssh",
                                                f"echo {HOST_PUB_KEY} >> /root/.ssh/authorized_keys",
                                                "tail -f /dev/null",
                                            ]),
                                        ],
                                        "ports": [
                                            {"protocol": "TCP", "port": 8000},
                                            {"protocol": "TCP", "port": 22},
                                        ],
                                        "environmentVariables": [],
                                        "resources": {
                                            "requests": {"memoryInGB": 16, "cpu": 4}
                                        },
                                        "volumeMounts": [
                                            {
                                            "name": "ccfacivolume",
                                            "mountPath": "/aci/vol/"
                                            }
                                        ],
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
                            "volumes": [
                            {
                                "name": "ccfacivolume",
                                "azureFile": {
                                    "shareName": "ccfacifileshare",
                                    "storageAccountName": "ccfacistorage",
                                    "storageAccountKey": args.storage_key,
                                }
                            }
                            ]
                        },
                    } for i in range(args.count)
                ],
            },
        )
    ),
).wait()
for resource in resource_client.deployments.get(RESOURCE_GROUP, args.deployment_name).properties.output_resources:
    container_name = resource.id.split("/")[-1]
    container_group = container_client.container_groups.get(RESOURCE_GROUP, container_name)
    print(container_group.ip_address.ip)