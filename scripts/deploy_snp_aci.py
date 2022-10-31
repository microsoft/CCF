# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import Deployment, DeploymentProperties, DeploymentMode

SUB_ID = os.environ.get("CCFAZURESUBSCRIPTIONID")
RESOURCE_GROUP = "ccf-aci"
IMAGE = "ccfmsrc.azurecr.io/ccf/ci/sgx:oe-0.18.2-protoc"
DEPLOYMENT = "snp-ci"

resource_client = ResourceManagementClient(DefaultAzureCredential(), SUB_ID)

creation = resource_client.deployments.begin_create_or_update(
    RESOURCE_GROUP,
    DEPLOYMENT,
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
                        "name": "test-agent",
                        "location": "westeurope",
                        "properties": {
                            "sku": "Standard",
                            "confidentialComputeProperties": {
                                "isolationType": "SevSnp",
                                "ccePolicy": "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19"
                            },
                            "containers": [
                                {
                                    "name": "test-agent",
                                    "properties": {
                                        "image": IMAGE,
                                        "command": [
                                            "tail",
                                            "-f",
                                            "/dev/null"
                                        ],
                                        "ports": [
                                            {
                                                "protocol": "TCP",
                                                "port": 8000
                                            },
                                            {
                                                "protocol": "TCP",
                                                "port": 22
                                            }
                                        ],
                                        "environmentVariables": [],
                                        "resources": {
                                            "requests": {
                                                "memoryInGB": 16,
                                                "cpu": 4
                                            }
                                        }
                                    }
                                }
                            ],
                            "initContainers": [],
                            "restartPolicy": "Never",
                            "ipAddress": {
                                "ports": [
                                    {
                                        "protocol": "TCP",
                                        "port": 8000
                                    },
                                    {
                                        "protocol": "TCP",
                                        "port": 22
                                    }
                                ],
                                "type": "Public"
                            },
                            "osType": "Linux"
                        }
                    }
                ]
            }
        )
    )
)
creation.wait()
