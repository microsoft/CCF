# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os

IS_SNP = os.path.exists("/dev/sev")
# 4070: Get these from the container
DEFAULT_SNP_HOST_DATA = (
    "cadd74f71ebb8fbf9782baab649612520f3c416bc5ce9ac768808ddc8d9b031c"
)
DEFAULT_SNP_SECURITY_POLICY = (
    '{"allow_all":true,"containers":{"length":0,"elements":null}}'
)
DEFAULT_SNP_SECURITY_POLICY_B64 = (
    "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19"
)
