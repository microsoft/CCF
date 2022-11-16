# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from argparse import ArgumentParser, Namespace

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentProperties,
    DeploymentMode,
)
from azure.mgmt.containerinstance import ContainerInstanceManagementClient

try:
    HOST_PUB_KEY = open(os.path.expanduser("~/.ssh/id_rsa.pub"), "r").read().replace("\n", "")
except Exception as e:
    ...

def make_passwd(password):
    return repr(password + "\n" + password)

STARTUP_COMMANDS = {
    "dynamic-agent": lambda args, i: [
        "apt-get update",
        "apt-get install -y openssh-server",
        "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config",
        "useradd -m agent",
        "echo \"agent ALL=(ALL) NOPASSWD: ALL\" >> /etc/sudoers",
        # f"echo {args.aci_dynamic_agent_password}\n{args.aci_dynamic_agent_password}",
        f'echo -e {make_passwd(args.aci_dynamic_agent_password)} | passwd agent',
        "service ssh restart",
        # "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config",
        # "sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/g' /etc/ssh/sshd_config",
        # "service ssh restart",
        # "mkdir /root/.ssh",
        # f"echo {HOST_PUB_KEY} >> /root/.ssh/authorized_keys",
        # f"echo \"{args.aci_dynamic_agent_password}\n{args.aci_dynamic_agent_password}\" | passwd root"
    ],
    "static-agent": lambda args, i: [
        "apt-get install wget",
        "wget https://gist.github.com/DomAyre/98d3a229870f4947fc99a2aa7ed995b4/raw -O setup_agent.sh",
        "chmod 777 setup_agent.sh",
        f"AGENT_NAME={args.deployment_name}-{i} PAT={args.aci_pat} ./setup_agent.sh",
    ],
    "dev": lambda args, i: [
        "apt-get install wget",
        "wget https://gist.github.com/DomAyre/ea2c07a9cb790bf17da05d4ca1674c8c/raw -O setup_dev.sh",
        "chmod 777 setup_dev.sh",
        " ".join([
            f"MSUSER=\"{args.aci_ms_user}-{i}\"",
            f"GITHUBUSER=\"{args.aci_github_user}\"",
            f"GITHUBNAME=\"{args.aci_github_name}\"",
            f"SSHKEYS=\"{args.aci_ssh_keys}\"",
            "./setup_dev.sh"
        ]),
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
        type=str,
    )

    parser.add_argument(
        "--aci-dynamic-agent-password",
        help="The password to set on the ACI",
        type=str,
    )

    args = parser.parse_args()

    return Deployment(
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
                    for i in range(args.count)
                ],
            },
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


def check_aci_deployment(args: Namespace, deployment: Deployment) -> str:

    container_client = ContainerInstanceManagementClient(
        DefaultAzureCredential(), args.subscription_id
    )

    for resource in deployment.properties.output_resources:
        container_name = resource.id.split("/")[-1]
        container_group = container_client.container_groups.get(
            args.resource_group, container_name
        )
        print(container_group.ip_address.ip)
