# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from arm_aci import (
    check_aci_deployment,
    make_aci_deployment,
    parse_aci_args,
    remove_aci_deployment,
)

parser = argparse.ArgumentParser(
    description="Python interface for Azure ARM deployments",
)

parser.add_argument(
    "operation",
    help="Whether to deploy or remove template",
    type=str,
    choices=["deploy", "remove", "check"],
)

parser.add_argument(
    "deployment_type",
    help="The type of Azure deployment to deploy",
    type=str,
    choices=[
        "aci",
    ],
)

parser.add_argument(
    "--count",
    help="The number of deployments",
    type=int,
    default=1,
)

parser.add_argument(
    "--subscription-id",
    help="The subscription ID used to deploy",
    type=str,
)

parser.add_argument(
    "--resource-group",
    help="The resource group used to deploy",
    default="ccf-aci",
    type=str,
)

parser.add_argument(
    "--deployment-name",
    help="The name of the Azure deployment, used for agent names and cleanup",
    type=lambda in_str: str(in_str).replace(".", ""),
)

parser.add_argument(
    "--out",
    help="Location to write the ARM template that was used",
    type=str,
)

args, unknown_args = parser.parse_known_args()

resource_client = ResourceManagementClient(
    DefaultAzureCredential(), args.subscription_id
)

deployment_type_to_funcs = {
    "aci": (
        parse_aci_args,
        make_aci_deployment,
        check_aci_deployment,
        remove_aci_deployment,
    ),
}


def deploy(args, make_template) -> str:
    template = make_template(args)
    if args.out:
        with open(args.out, "w") as f:
            f.write(template)
    resource_client.deployments.begin_create_or_update(
        args.resource_group,
        args.deployment_name,
        template,
    ).wait()


def remove(args, remove_deployment, deployment):
    try:
        # Call deployement type specific removal
        remove_deployment(
            args,
            deployment,
        )
        # Remove deployment
        resource_client.deployments.begin_delete(
            args.resource_group,
            args.deployment_name,
        ).wait()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    parse, make_template, check, remove_deployment = deployment_type_to_funcs[
        args.deployment_type
    ]
    args = parse(parser)

    def get_deployment(args):
        return resource_client.deployments.get(
            args.resource_group,
            args.deployment_name,
        )

    if args.operation == "deploy":
        deploy(args, make_template)
        check(args, get_deployment(args))
    elif args.operation == "check":
        check(args, get_deployment(args))
    elif args.operation == "remove":
        remove(args, remove_deployment, get_deployment(args))
