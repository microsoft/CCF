# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
from hashlib import sha256
import infra.snp as snp
from infra.node import strip_version
from packaging.version import Version  # type: ignore
import os


def get_measurement(enclave_platform, package, library_dir="."):
    if enclave_platform == "virtual":
        return "Insecure hard-coded virtual measurement v1"

    else:
        raise ValueError(f"Cannot get measurement on {enclave_platform}")


def get_host_data_and_security_policy(
    enclave_platform, package, *, library_dir=".", binary_dir=".", version=None
):
    if enclave_platform == "snp":
        security_policy = snp.get_container_group_security_policy()
        host_data = sha256(security_policy.encode()).hexdigest()
        return host_data, security_policy
    elif enclave_platform == "virtual":
        if version is None or Version(strip_version(version)) > Version("7.0.0-dev0"):
            lib_path = os.path.join(binary_dir, package)
        else:
            lib_path = infra.path.build_lib_path(package, library_dir, version=version)
        hash = sha256(open(lib_path, "rb").read())
        return hash.hexdigest(), None
    else:
        raise ValueError(f"Cannot get security policy on {enclave_platform}")
