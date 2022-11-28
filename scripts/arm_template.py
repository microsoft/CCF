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
from arm_aci import (
    check_aci_deployment,
    make_aci_deployment,
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

args, unknown_args = parser.parse_known_args()

resource_client = ResourceManagementClient(
    DefaultAzureCredential(), args.subscription_id
)

deployment_type_to_funcs = {
    "aci": (make_aci_deployment, check_aci_deployment, remove_aci_deployment),
}


def deploy(make_template, print_status) -> str:

    try:
        resource_client.deployments.begin_create_or_update(
            args.resource_group,
            args.deployment_name,
            make_template(parser),
        ).wait()
        print_status(
            args,
            resource_client.deployments.get(
                args.resource_group,
                args.deployment_name,
            ),
        )
    except Exception as e:
        print(e)


def remove(args, remove_deployment_items):

    try:
        remove_deployment_items(
            args,
            resource_client.deployments.get(
                args.resource_group,
                args.deployment_name,
            ),
        )
        resource_client.deployments.begin_delete(
            args.resource_group,
            args.deployment_name,
        ).wait()
    except Exception as e:
        print(e)


if __name__ == "__main__":

    if args.operation == "deploy":
        deploy(*deployment_type_to_funcs[args.deployment_type][:2])
    elif args.operation == "check":
        deployment_type_to_funcs[args.deployment_type][1](
            args,
            resource_client.deployments.get(
                args.resource_group,
                args.deployment_name,
            ),
        )
    elif args.operation == "remove":
        remove(args, deployment_type_to_funcs[args.deployment_type][2])
