# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from setuptools import setup
from os import path

PACKAGE_NAME = "ccf"

path_here = path.abspath(path.dirname(__file__))
package_path = path.join(path_here, PACKAGE_NAME)
utilities_path = path.join(path_here, "../tests")

with open(
    path.join(path_here, "README.md"), encoding="utf-8"
) as f:
    long_description = f.read()

setup(
    name=PACKAGE_NAME,
    version="0.11.7",
    description="Set of tools and utilities for the Confidential Consortium Framework (CCF)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/microsoft/CCF",
    license="Apache License 2.0",
    author="CCF Team",
    author_email="ccfeng@microsoft.com",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
    packages=[PACKAGE_NAME],
    python_requires=">=3.7",
    install_requires=[
        "msgpack",
        "loguru",
        "requests",
        "requests-http-signature",
        "websocket-client",
        "cryptography",
    ],
    scripts=[
        path.join(package_path, "proposal_generator.py"),
        path.join(utilities_path, "keygenerator.sh"),
        path.join(utilities_path, "scurl.sh"),
        path.join(utilities_path, "submit_recovery_share.sh"),
    ],
    include_package_data=True,
)
