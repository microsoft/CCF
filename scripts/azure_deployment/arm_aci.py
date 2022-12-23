# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from argparse import ArgumentParser, Namespace

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentProperties,
    DeploymentMode,
    DeploymentPropertiesExtended,
)
from azure.mgmt.containerinstance import ContainerInstanceManagementClient


def get_pubkey():
    pubkey_path = os.path.expanduser("~/.ssh/id_rsa.pub")
    return (
        open(pubkey_path, "r").read().replace("\n", "")
        if os.path.exists(pubkey_path)
        else ""
    )


STARTUP_COMMANDS = {
    "dynamic-agent": lambda args, i: [
        "apt-get update",
        "apt-get install -y openssh-server rsync",
        "sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/g' /etc/ssh/sshd_config",
        "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
        "useradd -m agent",
        'echo "agent ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers',
        "service ssh restart",
        "mkdir /home/agent/.ssh",
        *[
            f"echo {ssh_key} >> /home/agent/.ssh/authorized_keys"
            for ssh_key in [get_pubkey(), *args.aci_ssh_keys]
            if ssh_key
        ],
    ],
}


def make_aci_deployment(parser: ArgumentParser) -> Deployment:

    parser.add_argument(
        "--aci-image",
        help="The name of the image to deploy in the ACI",
        type=str,
        default="ccfmsrc.azurecr.io/ccf/ci:oe-0.18.4-snp",
    )

    parser.add_argument(
        "--aci-type",
        help="The type of ACI to deploy",
        type=str,
        choices=STARTUP_COMMANDS.keys(),
    )

    parser.add_argument(
        "--aci-pat",
        help="The PAT to deploy an ACI with",
        type=str,
    )

    parser.add_argument(
        "--aci-ms-user",
        help="The Microsoft User",
        type=str,
    )

    parser.add_argument(
        "--aci-github-user",
        help="The Github User who owns a CCF clone to checkout",
        type=str,
    )

    parser.add_argument(
        "--aci-github-name",
        help="The name to commit with",
        type=str,
    )

    parser.add_argument(
        "--aci-ssh-keys",
        help="The ssh keys to add to the dev box",
        default="",
        type=lambda comma_sep_str: comma_sep_str.split(","),
    )

    parser.add_argument(
        "--aci-deploy-external-executer",
        help="Deploy external executer container if true. Default=False",
        default=False,
        type=bool,
    )

    args = parser.parse_args()

    common_resource_attributes = {
        "type": "Microsoft.ContainerInstance/containerGroups",
        "apiVersion": "2022-04-01-preview",
        "location": "westeurope",
    }

    common_resource_properties = {
        "sku": "Standard",
        "confidentialComputeProperties": {
            "isolationType": "SevSnp",
            "ccePolicy": "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19",
        },
        "initContainers": [],
        "restartPolicy": "Never",
        "osType": "Linux",
    }

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {},
        "variables": {},
        "resources": [
            {
                **common_resource_attributes,
                "name": f"{args.deployment_name}-{i}",
                "properties": {
                    **common_resource_properties,
                    "containers": [
                        {
                            "name": f"{args.deployment_name}-{i}",
                            "properties": {
                                "image": args.aci_image,
                                "command": [
                                    "/bin/sh",
                                    "-c",
                                    " && ".join(
                                        [
                                            *STARTUP_COMMANDS[args.aci_type](
                                                args,
                                                i,
                                            ),
                                            "tail -f /dev/null",
                                        ]
                                    ),
                                ],
                                "ports": [
                                    {"protocol": "TCP", "port": 8000},
                                    {"protocol": "TCP", "port": 22},
                                ],
                                "environmentVariables": [],
                                "resources": {"requests": {"memoryInGB": 16, "cpu": 4}},
                            },
                        }
                    ],
                    "ipAddress": {
                        "ports": [
                            {"protocol": "TCP", "port": 8000},
                            {"protocol": "TCP", "port": 22},
                        ],
                        "type": "Public",
                    },
                },
            }
            for i in range(args.count)
        ],
    }

    if args.aci_deploy_blc:
        template["resources"].append(
            {
                **common_resource_attributes,
                "name": f"{args.deployment_name}-business-logic",
                "properties": {
                    **common_resource_properties,
                    "containers": [
                        {
                            "name": f"{args.deployment_name}-attestation-container",
                            "properties": {
                                "image": f"attestationcontainerregistry.azurecr.io/attestation-container:{args.deployment_name}",
                                "command": [
                                    "/bin/sh",
                                    "-c",
                                    " && ".join(
                                        [
                                            *STARTUP_COMMANDS[args.aci_type](
                                                args,
                                                None,
                                            ),
                                            "app",
                                        ]
                                    ),
                                ],
                                "ports": [
                                    {"protocol": "TCP", "port": 22},
                                    {"protocol": "TCP", "port": 50051},
                                ],
                                "environmentVariables": [],
                                "resources": {"requests": {"memoryInGB": 16, "cpu": 4}},
                            },
                        }
                    ],
                    "ipAddress": {
                        "ports": [
                            {"protocol": "TCP", "port": 22},
                            {"protocol": "TCP", "port": 50051},
                        ],
                        "type": "Public",
                    },
                },
            }
        )
    return Deployment(
        properties=DeploymentProperties(
            mode=DeploymentMode.INCREMENTAL, parameters={}, template=template
        )
    )


def remove_aci_deployment(args: Namespace, deployment: Deployment):

    container_client = ContainerInstanceManagementClient(
        DefaultAzureCredential(), args.subscription_id
    )

    for resource in deployment.properties.output_resources:
        container_name = resource.id.split("/")[-1]
        container_client.container_groups.begin_delete(
            args.resource_group, container_name
        ).wait()


def check_aci_deployment(
    args: Namespace, deployment: DeploymentPropertiesExtended
) -> str:
    """
    Outputs the list of container group deployed to stdout.
    The format of each line is `<container group name> <IP address>`.

    example output:
    container_group_a 10.10.10.10
    container_group_b 10.10.10.11
    """

    container_client = ContainerInstanceManagementClient(
        DefaultAzureCredential(), args.subscription_id
    )

    for resource in deployment.properties.output_resources:
        container_group_name = resource.id.split("/")[-1]
        container_group = container_client.container_groups.get(
            args.resource_group, container_group_name
        )
        print(container_group_name, container_group.ip_address.ip)
