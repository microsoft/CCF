# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
import hashlib
import os
import subprocess


def get_code_id(
    enclave_type, enclave_platform, oe_binary_dir, package, library_dir="."
):
    lib_path = infra.path.build_lib_path(
        package, enclave_type, enclave_platform, library_dir
    )

    if enclave_platform == "sgx":
        res = subprocess.run(
            [os.path.join(oe_binary_dir, "oesign"), "dump", "-e", lib_path],
            capture_output=True,
            check=True,
        )
        lines = [
            line
            for line in res.stdout.decode().split(os.linesep)
            if line.startswith("mrenclave=")
        ]

        return lines[0].split("=")[1]
    else:
        # Virtual and SNP
        return hashlib.sha384(lib_path.encode()).hexdigest()
