# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from argparse import ArgumentParser, Namespace
import base64
import json

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentProperties,
    DeploymentMode,
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
    "dynamic-agent": lambda args: [
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

DEFAULT_REGO_SECURITY_POLICY = """package policy

api_svn := "0.10.0"

mount_device := {"allowed": true}
mount_overlay := {"allowed": true}
create_container := {"allowed": true, "allow_stdio_access": true}
unmount_device := {"allowed": true}
unmount_overlay := {"allowed": true}
exec_in_container := {"allowed": true}
exec_external := {"allowed": true, "allow_stdio_access": true}
shutdown_container := {"allowed": true}
signal_container_process := {"allowed": true}
plan9_mount := {"allowed": true}
plan9_unmount := {"allowed": true}
get_properties := {"allowed": true}
dump_stacks := {"allowed": true}
runtime_logging := {"allowed": true}
load_fragment := {"allowed": true}
scratch_mount := {"allowed": true}
scratch_unmount := {"allowed": true}
"""


def make_dev_container_command(args):
    return [
        "/bin/sh",
        "-c",
        " && ".join([*STARTUP_COMMANDS["dynamic-agent"](args), "tail -f /dev/null"]),
    ]


def make_dev_container_template(id, name, image, command, with_volume):
    t = {
        "name": f"{name}-{id}",
        "properties": {
            "image": image,
            "command": command,
            "ports": [
                {"protocol": "TCP", "port": 8000},
                {"protocol": "TCP", "port": 22},
            ],
            "environmentVariables": [],
            "resources": {"requests": {"memoryInGB": 16, "cpu": 4}},
        },
    }
    if with_volume:
        t["properties"]["volumeMounts"] = [
            {"name": "ccfcivolume", "mountPath": "/ccfci"}
        ]
    return t


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
        "--aci-ssh-keys",
        help="The ssh keys to add to the dev box",
        default="",
        type=lambda comma_sep_str: comma_sep_str.split(","),
    )

    parser.add_argument(
        "--aci-storage-account-key",
        help="The storage account key used to authorise access to the file share",
        type=str,
    )

    parser.add_argument(
        "--non-confidential",
        help="If set, disable confidential SEV-SNP (insecure!)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--region",
        help="Region to deploy to",
        type=str,
        default="eastus2euap",
    )
    parser.add_argument(
        "--security-policy-file",
        help="Path to security path file policy. If unset, defaults to most permissive policy",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--no-volume",
        help="If set, no shared volume is attached to containers",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    # Note: Using ARM templates rather than Python SDK here to be able to specify confidentialComputeProperties
    arm_template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {},
        "variables": {},
        "resources": [],
    }

    containers = [
        make_dev_container_template(
            i,
            args.deployment_name,
            args.aci_image,
            make_dev_container_command(args),
            not args.no_volume,
        )
        for i in range(args.count)
    ]

    container_group_properties = {
        "sku": "Standard",
        "containers": containers,
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
    }

    if not args.no_volume:
        container_group_properties["volumes"] = [
            {
                "name": "ccfcivolume",
                "azureFile": {
                    "shareName": "ccfcishare",
                    "storageAccountName": "ccfcistorage",
                    "storageAccountKey": args.aci_storage_account_key,
                },
            }
        ]

    if not args.non_confidential:
        if args.security_policy_file is not None:
            with open(args.security_policy_file, "r") as f:
                security_policy = f.read()
        else:
            # Otherwise, default to most permissive policy
            security_policy = DEFAULT_REGO_SECURITY_POLICY

        container_group_properties["confidentialComputeProperties"] = {
            "isolationType": "SevSnp",
            "ccePolicy": base64.b64encode(security_policy.encode()).decode(),
        }

    container_group = {
        "type": "Microsoft.ContainerInstance/containerGroups",
        "apiVersion": "2022-04-01-preview",
        "name": args.deployment_name,
        "location": args.region,
        "properties": container_group_properties,
    }

    arm_template["resources"].append(container_group)

    print(json.dumps(arm_template, indent=2))

    return Deployment(
        properties=DeploymentProperties(
            mode=DeploymentMode.INCREMENTAL, parameters={}, template=arm_template
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
