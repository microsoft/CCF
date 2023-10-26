# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import subprocess
import time
from argparse import ArgumentParser, Namespace
import base64
import tempfile

from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources.models import (
    Deployment,
    DeploymentProperties,
    DeploymentMode,
    DeploymentPropertiesExtended,
)
from azure.mgmt.containerinstance import ContainerInstanceManagementClient

# Required API version to access Confidential ACI public preview
ACI_SEV_SNP_API_VERSION = "2022-10-01-preview"

WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH = "/aci_env"


def get_pubkey():
    pubkey_path = os.path.expanduser("~/.ssh/id_rsa.pub")
    return (
        open(pubkey_path, "r").read().replace("\n", "")
        if os.path.exists(pubkey_path)
        else ""
    )


def setup_environment_command():
    # ACI SEV-SNP environment variables are only set for the PID of the container's
    # command so record these in a file accessible to the Python infra
    def append_envvar_to_well_known_file(envvar):
        return f'[ -n "${envvar}" ] && echo {envvar}=${envvar} >> {WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH} || true'

    return [
        append_envvar_to_well_known_file("UVM_SECURITY_POLICY"),
        append_envvar_to_well_known_file("UVM_REFERENCE_INFO"),
        append_envvar_to_well_known_file("UVM_HOST_AMD_CERTIFICATE"),
        append_envvar_to_well_known_file("UVM_SECURITY_CONTEXT_DIR"),
    ]


STARTUP_COMMANDS = {
    "dynamic-agent": lambda args: [
        *[
            f"echo {ssh_key} >> /home/agent/.ssh/authorized_keys"
            for ssh_key in [get_pubkey(), *args.aci_ssh_keys]
            if ssh_key
        ],
        *(
            [
                f"echo {args.aci_private_key_b64} | base64 -d > /home/agent/.ssh/id_rsa",
                "chmod 600 /home/agent/.ssh/id_rsa",
                "ssh-keygen -y -f /home/agent/.ssh/id_rsa > /home/agent/.ssh/id_rsa.pub",
                "chmod 600 /home/agent/.ssh/id_rsa.pub",
            ]
            if args.aci_private_key_b64 is not None
            else []
        ),
        *[
            '[ -n "$UVM_SECURITY_CONTEXT_DIR" ] && chmod 745 $UVM_SECURITY_CONTEXT_DIR || true'
        ],  # https://github.com/microsoft/hcsshim/pull/1729
        *setup_environment_command(),
    ],
}

DEFAULT_JSON_SECURITY_POLICY = (
    '{"allow_all":true,"containers":{"length":0,"elements":null}}'
)

DEFAULT_REGO_SECURITY_POLICY = """package policy

api_svn := "0.10.0"
framework_svn := "0.1.0"

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
        " && ".join([*STARTUP_COMMANDS["dynamic-agent"](args), "/usr/sbin/sshd -D"]),
    ]


def make_dev_container(id, name, image, command, ports, with_volume):
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


def parse_aci_args(parser: ArgumentParser) -> Namespace:
    # Generic options
    parser.add_argument(
        "--aci-image",
        help="The name of the image to deploy in the ACI",
        type=str,
        default="ccfmsrc.azurecr.io/ccf/ci:26-10-2023-snp",
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
        "--aci-private-key-b64",
        help="The base 64 representation of the private ssh key to use on the container instance",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--region",
        help="Region to deploy to",
        type=str,
        default="northeurope",
    )
    parser.add_argument(
        "--ports",
        help="List of TCP ports to expose publicly on each container",
        action="append",
        default=[],
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
    parser.add_argument(
        "--generate-security-policy",
        help="Use security policy generated by `az confcom acipolicygen` if this flag is true.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--default-security-policy-format",
        help="Default security policy format (only if --security-policy-file is not set)",
        type=str,
        choices=["json", "rego"],
        default="rego",
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
        "--aci-storage-account-key",
        help="The storage account key used to authorise access to the file share",
        type=str,
    )

    parser.add_argument(
        "--aci-setup-timeout",
        help="The amount of time in seconds to wait for the ACI to be ready",
        type=int,
        default=3 * 60,  # 3 minutes
    )

    return parser.parse_args()


def make_aci_deployment(args: Namespace) -> Deployment:
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
        deployment_name = args.deployment_name
        container_name = args.deployment_name
        container_image = args.aci_image
        command = make_dev_container_command(args)
        containers = [
            make_dev_container(
                i,
                container_name,
                container_image,
                command,
                args.ports,
                with_volume=True,
            )
        ]

        container_group_properties = {
            "sku": "Standard" if args.non_confidential else "Confidential",
            "containers": containers,
            "initContainers": [],
            "restartPolicy": "Never",
            "osType": "Linux",
        }

        if args.ports:
            container_group_properties["ipAddress"] = {
                "ports": [{"protocol": "TCP", "port": p} for p in args.ports],
                "type": "Public",
            }

        # Volume
        container_group_properties["volumes"] = [
            {"name": "udsemptydir", "emptyDir": {}}
        ]
        if args.aci_file_share_name is not None:
            container_group_properties["volumes"].append(
                {
                    "name": "ccfcivolume",
                    "azureFile": {
                        "shareName": args.aci_file_share_name,
                        "storageAccountName": args.aci_file_share_account_name,
                        "storageAccountKey": args.aci_storage_account_key,
                    },
                }
            )
        else:
            container_group_properties["volumes"].append(
                {"name": "ccfcivolume", "emptyDir": {}}
            )

        # Security policy
        if args.generate_security_policy:
            # Empty ccePolicy is required by acipolicygen tool
            container_group_properties["confidentialComputeProperties"] = {
                "ccePolicy": ""
            }
        elif not args.non_confidential:
            if args.security_policy_file is not None:
                with open(args.security_policy_file, "r") as f:
                    security_policy = f.read()
            else:
                # Otherwise, default to most permissive policy
                if args.default_security_policy_format == "rego":
                    security_policy = DEFAULT_REGO_SECURITY_POLICY
                else:
                    security_policy = DEFAULT_JSON_SECURITY_POLICY

            container_group_properties["confidentialComputeProperties"] = {
                "ccePolicy": base64.b64encode(security_policy.encode()).decode(),
            }

        container_group = {
            "type": "Microsoft.ContainerInstance/containerGroups",
            "apiVersion": ACI_SEV_SNP_API_VERSION,
            "name": f"{deployment_name}-{i}",
            "location": args.region,
            "properties": container_group_properties,
        }

        arm_template["resources"].append(container_group)

        if not args.non_confidential and args.generate_security_policy:
            with tempfile.TemporaryDirectory() as tmpdirname:
                arm_template_path = f"{tmpdirname}/arm_template.json"
                output_policy_path = f"{tmpdirname}/security_policy"
                modified_policy_path = f"{tmpdirname}/modified_security_policy"
                with open(arm_template_path, "w") as f:
                    json.dump(arm_template, f)
                # sudo is necessary for docker to avoid error "The current user does not have permission".
                # The recommended solution is 'sudo usermod -aG docker', but it requires re-login.
                # https://docs.docker.com/engine/install/linux-postinstall/
                # We use sudo instead as a workaround.
                completed_process = subprocess.run(
                    [
                        "sudo",
                        "az",
                        "confcom",
                        "acipolicygen",
                        "-a",
                        arm_template_path,
                        "--outraw",
                        "--save-to-file",
                        output_policy_path,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                if completed_process.returncode != 0:
                    arm_template_string = json.dumps(arm_template, indent=4)
                    raise RuntimeError(
                        f"Generating security policy failed with status code {completed_process.returncode}: {completed_process.stdout}, arm_template: {arm_template_string}"
                    )

                # Allow execution of commands post-creation
                with open(output_policy_path, "r") as f:
                    lines = f.readlines()
                    lines = [
                        'exec_in_container := {"allowed": true}\n'
                        if l.startswith("exec_in_container")
                        else l
                        for l in lines
                    ]

                with open(modified_policy_path, "w") as f:
                    print(f"lines: {lines}")
                    f.writelines(lines)

                # Set security policy
                with open(modified_policy_path, "r") as f:
                    arm_template["resources"][0]["properties"][
                        "confidentialComputeProperties"
                    ]["ccePolicy"] = base64.b64encode(f.read().encode()).decode()

    return Deployment(
        properties=DeploymentProperties(
            mode=DeploymentMode.INCREMENTAL, parameters={}, template=arm_template
        )
    )


def remove_aci_deployment(args: Namespace, deployment: Deployment):
    container_client = ContainerInstanceManagementClient(
        AzureCliCredential(), args.subscription_id
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
        AzureCliCredential(), args.subscription_id
    )

    for resource in deployment.properties.output_resources:
        container_group_name = resource.id.split("/")[-1]
        container_group = container_client.container_groups.get(
            args.resource_group, container_group_name
        )

        start_time = time.time()
        end_time = start_time + args.aci_setup_timeout
        current_time = start_time

        while current_time < end_time:
            try:
                print(
                    f"Attempting SSH connection to container {container_group.ip_address.ip}"
                )
                assert (
                    subprocess.check_output(
                        [
                            "ssh",
                            f"agent@{container_group.ip_address.ip}",
                            "-o",
                            "StrictHostKeyChecking=no",
                            "-o",
                            "ConnectTimeout=100",
                            "echo test",
                        ]
                    )
                    == b"test\n"
                )
                if args.out:
                    with open(os.path.expanduser(args.out), "w") as f:
                        f.write(
                            f"{container_group_name}, {container_group.ip_address.ip}{os.linesep}"
                        )
                print(container_group_name, container_group.ip_address.ip)
                break
            except Exception as e:
                print(f"Error during SSH connection: {e}")
                time.sleep(5)
                current_time = time.time()

        assert (
            current_time < end_time
        ), "Timed out waiting for container commands to run"
