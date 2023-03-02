# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
from base64 import b64decode

from ccf.executors.registration import register_new_executor

from wiki_cacher.wiki_cacher import WikiCacherExecutor

if __name__ == "__main__":
    # Retrieve CCF node address and service certificate from environment
    ccf_address = os.environ.get("CCF_CORE_NODE_RPC_ADDRESS")
    service_certificate_bytes = b64decode(
        os.environ.get("CCF_CORE_SERVICE_CERTIFICATE")
    )
    credentials = register_new_executor(
        ccf_address,
        service_certificate_bytes,
        WikiCacherExecutor.get_supported_endpoints({"Earth"}),
    )
    e = WikiCacherExecutor(ccf_address, credentials)
    e.run_loop()
