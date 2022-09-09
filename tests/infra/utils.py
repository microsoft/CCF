# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
import hashlib
import os
import subprocess
from is_snp import IS_SNP


def get_code_id(enclave_type, oe_binary_dir, package, library_dir="."):
    lib_path = infra.path.build_lib_path(package, enclave_type, library_dir)

    if enclave_type == "virtual" or IS_SNP:
        return hashlib.sha384(lib_path.encode()).hexdigest()
    else:
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
