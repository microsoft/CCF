# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from os import path
from setuptools import setup  # type: ignore

# pylint: disable=import-error
import version  # type: ignore

# pylint: disable=protected-access
import ccf._versionifier

PACKAGE_NAME = "ccf"
UTILITIES_PATH = "utils"
TEMPLATES_PATH = path.join(PACKAGE_NAME, "templates")

path_here = path.abspath(path.dirname(__file__))

with open(path.join(path_here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name=PACKAGE_NAME,
    version=str(ccf._versionifier.to_python_version(version.CCF_VERSION)),
    description="Set of tools and utilities for the Confidential Consortium Framework (CCF)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/microsoft/CCF/tree/main/python",
    license="Apache License 2.0",
    author="CCF Team",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
    packages=[PACKAGE_NAME],
    python_requires=">=3.8",
    install_requires=requirements,
    scripts=[
        path.join(PACKAGE_NAME, "read_ledger.py"),
        path.join(PACKAGE_NAME, "ledger_viz.py"),
        path.join(PACKAGE_NAME, "split_ledger.py"),
        path.join(UTILITIES_PATH, "keygenerator.sh"),
        path.join(UTILITIES_PATH, "scurl.sh"),
        path.join(UTILITIES_PATH, "submit_recovery_share.sh"),
        path.join(UTILITIES_PATH, "verify_quote.sh"),
    ],
    entry_points={
        "console_scripts": [
            "ccf_cose_sign1 = ccf.cose:sign_cli",
            "ccf_cose_sign1_prepare = ccf.cose:prepare_cli",
            "ccf_cose_sign1_finish = ccf.cose:finish_cli",
        ]
    },
    include_package_data=True,
)
