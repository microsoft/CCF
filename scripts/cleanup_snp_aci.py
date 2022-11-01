# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

SUB_ID = os.environ.get("CCFAZURESUBSCRIPTIONID")
RESOURCE_GROUP = "ccf-aci"
IMAGE = "ccfmsrc.azurecr.io/ccf/ci/sgx:oe-0.18.2-protoc"
DEPLOYMENT = "snp-ci"

resource_client = ResourceManagementClient(DefaultAzureCredential(), SUB_ID)

try:
    deletion = resource_client.deployments.begin_delete(RESOURCE_GROUP, DEPLOYMENT)
    deletion.wait()
except Exception:
    ...
