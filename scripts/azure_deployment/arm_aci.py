# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import subprocess
import time
from argparse import ArgumentParser, Namespace
import base64

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


def make_dev_container_template(id, name, image, command, ports, with_volume):
    t = {
        "name": f"{name}-{id}",
        "properties": {
            "image": image,
            "command": command,
            "ports": [{"protocol": "TCP", "port": p} for p in ports],
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

    # Generic options
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
        "--region",
        help="Region to deploy to",
        type=str,
        default="eastus2euap",
    )
    parser.add_argument(
        "--ports",
        help="List of TCP ports to expose publicly on each container",
        action="append",
        default=[22],
    )

    # SEV-SNP options
    parser.add_argument(
        "--non-confidential",
        help="If set, disable confidential SEV-SNP (insecure!)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--security-policy-file",
        help="Path to security path file policy. If unset, defaults to most permissive policy",
        type=str,
        default=None,
    )

    # File share options
    parser.add_argument(
        "--aci-file-share-name",
        help="Name of file share. If none is set, no file share is mounted to containers",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--aci-file-share-account-name",
        help="Name of file share account",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--attestation-container-e2e",
        help="Deploy attestation container for its E2E test if this flag is true. Default=False",
        default=False,
        type=bool,
    )

    parser.add_argument(
        "--aci-storage-account-key",
        help="The storage account key used to authorise access to the file share",
        type=str,
    )

    args = parser.parse_args()

    # Note: Using ARM templates rather than Python SDK as ConfidentialComputeProperties does not work yet
    # with Python SDK (it should but isolationType cannot be specified - bug has been reported!)
    arm_template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {},
        "variables": {},
        "resources": [],
    }

    for i in range(args.count):

        containers = [
            make_dev_container_template(
                i,
                args.deployment_name,
                args.aci_image,
                make_dev_container_command(args),
                args.ports,
                args.aci_file_share_name is not None,
            )
        ]

        container_group_properties = {
            "sku": "Standard",
            "containers": containers,
            "initContainers": [],
            "restartPolicy": "Never",
            "ipAddress": {
                "ports": [{"protocol": "TCP", "port": p} for p in args.ports],
                "type": "Public",
            },
            "osType": "Linux",
        }

        if args.aci_file_share_name is not None:
            container_group_properties["volumes"] = [
                {
                    "name": "ccfcivolume",
                    "azureFile": {
                        "shareName": args.aci_file_share_name,
                        "storageAccountName": args.aci_file_share_account_name,
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
            "name": f"{args.deployment_name}-{i}",
            "location": args.region,
            "properties": container_group_properties,
        }

        arm_template["resources"].append(container_group)

    print(arm_template)

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

        # Check that container commands have been completed
        timeout = 3 * 60  # 3 minutes
        start_time = time.time()
        end_time = start_time + timeout
        current_time = start_time

        while current_time < end_time:
            try:
                assert (
                    subprocess.check_output(
                        [
                            "ssh",
                            f"agent@{container_group.ip_address.ip}",
                            "-o",
                            "StrictHostKeyChecking no",
                            "echo test",
                        ]
                    )
                    == b"test\n"
                )
                print(container_group_name, container_group.ip_address.ip)
                break
            except Exception:
                time.sleep(5)
                current_time = time.time()

        assert (
            current_time < end_time
        ), "Timed out waiting for container commands to run"
