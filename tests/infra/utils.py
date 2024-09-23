# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
import hashlib


def get_code_id(enclave_type, enclave_platform, package, library_dir="."):
    lib_path = infra.path.build_lib_path(
        package, enclave_type, enclave_platform, library_dir
    )

    return hashlib.sha256(lib_path.encode()).hexdigest()
