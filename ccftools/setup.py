# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from setuptools import setup
from os import path

PACKAGE_NAME = "ccf"

with open(path.join(path.abspath(path.dirname(__file__)), "README.md"), encoding="utf-8") as f:
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
)
