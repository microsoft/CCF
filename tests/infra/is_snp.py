# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os

IS_SNP = os.path.exists("/dev/sev")
# TODO: Get these from the container
DEFAULT_SNP_SECURITY_POLICY_DIGEST = (
    "ab6ccfea6e8c9c6233b1a4631cfd6440ecf910694b34d7e92e0236738758831e"
)
DEFAULT_SNP_SECURITY_POLICY = (
    '{"allow_all":true,"containers":{"length":0,"elements":null}}'
)
