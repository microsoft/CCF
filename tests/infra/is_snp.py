# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os

IS_SNP = os.path.exists("/dev/sev")
# 4070: Get these from the container
DEFAULT_SNP_HOST_DATA = (
    "ab6ccfea6e8c9c6233b1a4631cfd6440ecf910694b34d7e92e0236738758831e"
)
DEFAULT_SNP_SECURITY_POLICY = (
    '{"allow_all":true,"containers":{"length":0,"elements":null}}'
)
DEFAULT_SNP_SECURITY_POLICY_B64 = (
    "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19"
)