# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
import hashlib
import os
import subprocess


def get_measurement(enclave_type, enclave_platform, package, library_dir="."):
    lib_path = infra.path.build_lib_path(
        package, enclave_type, enclave_platform, library_dir
    )

    if enclave_platform == "virtual":
        hash = hashlib.sha256(open(lib_path, "rb").read())
        return hash.hexdigest()

    else:
        raise ValueError(f"Cannot get measurement on {enclave_platform}")
