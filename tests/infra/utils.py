# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
from hashlib import sha256
import infra.snp as snp
import infra.proc


def get_measurement(enclave_type, enclave_platform, package, library_dir="."):
    lib_path = infra.path.build_lib_path(
        package, enclave_type, enclave_platform, library_dir
    )

    if enclave_platform == "virtual":
        result = infra.proc.ccall("uname", "-a")
        return result.stdout.decode().strip()

    else:
        raise ValueError(f"Cannot get measurement on {enclave_platform}")


def get_host_data_and_security_policy(
    enclave_type, enclave_platform, package, library_dir="."
):
    lib_path = infra.path.build_lib_path(
        package, enclave_type, enclave_platform, library_dir
    )
    if enclave_platform == "snp":
        security_policy = snp.get_container_group_security_policy()
        host_data = sha256(security_policy.encode()).hexdigest()
        return host_data, security_policy
    elif enclave_platform == "virtual":
        hash = sha256(open(lib_path, "rb").read())
        return hash.hexdigest(), None
    else:
        raise ValueError(f"Cannot get security policy on {enclave_platform}")
