# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="ccf",
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
    packages=["ccf"],
    python_requires=">=3.7",
    install_requires=["msgpack", "loguru"],
)
