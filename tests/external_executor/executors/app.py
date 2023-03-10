# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
from base64 import b64decode
import signal

# pylint: disable=import-error, no-name-in-module
from ccf.executors.registration import register_new_executor

# pylint: disable=import-error, no-name-in-module
from logging_app.logging_app import LoggingExecutor

# Entrypoint for Python-based CCF external executors
if __name__ == "__main__":
    # Retrieve CCF node address and service certificate from environment
    ccf_address = os.environ.get("CCF_CORE_NODE_RPC_ADDRESS")
    service_certificate_bytes = b64decode(
        os.environ.get("CCF_CORE_SERVICE_CERTIFICATE")
    )
    credentials = register_new_executor(
        ccf_address,
        service_certificate_bytes,
        LoggingExecutor.get_supported_endpoints(),
    )
    e = LoggingExecutor(ccf_address, credentials)
    signal.signal(signal.SIGTERM, e.terminate)
    e.run_loop()
