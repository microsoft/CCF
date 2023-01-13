# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

# Notes:
# 1. Activate owner role for SC account
# 2. In Cloud Shell terminal, run:
# $ az ad sp create-for-rbac --scopes /subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730 --role contributor
# 3. In the main terminal, login using service principal created
# $ az login --service-principal -u <app_id> -p <password> --tenant <tenant>


def main():

    SUBSCRIPTION_ID = "12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730"
    GROUP_NAME = "test-group"
    VIRTUAL_NETWORK_NAME = "vnet-test"
    SUBNET_NAME = "aci-subnet"

    # Create client
    resource_client = ResourceManagementClient(
        DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID
    )
    # network_client = NetworkManagementClient(
    #     DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID
    # )

    # Create resource group
    resource_client.resource_groups.create_or_update(
        GROUP_NAME, {"location": "west europe"}
    )

    # # Create virtual network
    # network = network_client.virtual_networks.begin_create_or_update(
    #     GROUP_NAME,
    #     VIRTUAL_NETWORK_NAME,
    #     {
    #         "address_space": {"address_prefixes": ["10.0.0.0/16"]},
    #         "location": "west europe",
    #         "subnets": [
    #             {
    #                 "name": SUBNET_NAME,
    #                 "address_prefix": "10.0.0.0/24",
    #                 "delegation": "Microsoft.ContainerInstance/containerGroups",
    #             }
    #         ],
    #     },
    # ).result()
    # print(f"Create virtual network: {VIRTUAL_NETWORK_NAME}")

    # Get virtual network
    # network = network_client.virtual_networks.get(GROUP_NAME, VIRTUAL_NETWORK_NAME)
    # print(f"Virtual network: {network}")

    # subnet = network_client.subnets.get(GROUP_NAME, VIRTUAL_NETWORK_NAME, SUBNET_NAME)
    # print(f"Subnet: {subnet}")

    # Delete virtual network
    # network_client.virtual_networks.begin_delete(
    #     GROUP_NAME, VIRTUAL_NETWORK_NAME
    # ).result()
    # print("Delete virtual network.\n")

    # # Delete Group
    # resource_client.resource_groups.begin_delete(GROUP_NAME).result()


if __name__ == "__main__":
    main()
