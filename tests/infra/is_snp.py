# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os

IS_SNP = os.path.exists("/dev/sev")
# 4070: Get these from the container

# JSON:
DEFAULT_SNP_HOST_DATA = (
    "ab6ccfea6e8c9c6233b1a4631cfd6440ecf910694b34d7e92e0236738758831e"
)
DEFAULT_SNP_SECURITY_POLICY = (
    '{"allow_all":true,"containers":{"length":0,"elements":null}}'
)
DEFAULT_SNP_SECURITY_POLICY_B64 = (
    "eyJhbGxvd19hbGwiOnRydWUsImNvbnRhaW5lcnMiOnsibGVuZ3RoIjowLCJlbGVtZW50cyI6bnVsbH19"
)

# REGO:
# DEFAULT_SNP_HOST_DATA = (
#     "cadd74f71ebb8fbf9782baab649612520f3c416bc5ce9ac768808ddc8d9b031c"
# )
# DEFAULT_SNP_SECURITY_POLICY = 'package policy\n\napi_svn := "0.10.0"\n\nmount_device := {"allowed": true}\nmount_overlay := {"allowed": true}\ncreate_container := {"allowed": true, "allow_stdio_access": true}\nunmount_device := {"allowed": true}\nunmount_overlay := {"allowed": true}\nexec_in_container := {"allowed": true}\nexec_external := {"allowed": true, "allow_stdio_access": true}\nshutdown_container := {"allowed": true}\nsignal_container_process := {"allowed": true}\nplan9_mount := {"allowed": true}\nplan9_unmount := {"allowed": true}\nget_properties := {"allowed": true}\ndump_stacks := {"allowed": true}\nruntime_logging := {"allowed": true}\nload_fragment := {"allowed": true}\nscratch_mount := {"allowed": true}\nscratch_unmount := {"allowed": true}\n'
# DEFAULT_SNP_SECURITY_POLICY_B64 = "cGFja2FnZSBwb2xpY3kKCmFwaV9zdm4gOj0gIjAuMTAuMCIKCm1vdW50X2RldmljZSA6PSB7ImFsbG93ZWQiOiB0cnVlfQptb3VudF9vdmVybGF5IDo9IHsiYWxsb3dlZCI6IHRydWV9CmNyZWF0ZV9jb250YWluZXIgOj0geyJhbGxvd2VkIjogdHJ1ZSwgImFsbG93X3N0ZGlvX2FjY2VzcyI6IHRydWV9CnVubW91bnRfZGV2aWNlIDo9IHsiYWxsb3dlZCI6IHRydWV9CnVubW91bnRfb3ZlcmxheSA6PSB7ImFsbG93ZWQiOiB0cnVlfQpleGVjX2luX2NvbnRhaW5lciA6PSB7ImFsbG93ZWQiOiB0cnVlfQpleGVjX2V4dGVybmFsIDo9IHsiYWxsb3dlZCI6IHRydWUsICJhbGxvd19zdGRpb19hY2Nlc3MiOiB0cnVlfQpzaHV0ZG93bl9jb250YWluZXIgOj0geyJhbGxvd2VkIjogdHJ1ZX0Kc2lnbmFsX2NvbnRhaW5lcl9wcm9jZXNzIDo9IHsiYWxsb3dlZCI6IHRydWV9CnBsYW45X21vdW50IDo9IHsiYWxsb3dlZCI6IHRydWV9CnBsYW45X3VubW91bnQgOj0geyJhbGxvd2VkIjogdHJ1ZX0KZ2V0X3Byb3BlcnRpZXMgOj0geyJhbGxvd2VkIjogdHJ1ZX0KZHVtcF9zdGFja3MgOj0geyJhbGxvd2VkIjogdHJ1ZX0KcnVudGltZV9sb2dnaW5nIDo9IHsiYWxsb3dlZCI6IHRydWV9CmxvYWRfZnJhZ21lbnQgOj0geyJhbGxvd2VkIjogdHJ1ZX0Kc2NyYXRjaF9tb3VudCA6PSB7ImFsbG93ZWQiOiB0cnVlfQpzY3JhdGNoX3VubW91bnQgOj0geyJhbGxvd2VkIjogdHJ1ZX0K"
