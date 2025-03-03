# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

ARG BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core:3.0
FROM ${BASE_IMAGE}

# Trust Microsoft-signed packages
RUN gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY  \
    && tdnf -y update

# Basic dev deps, helps smoothly install VSCode server.
RUN tdnf -y install build-essential
