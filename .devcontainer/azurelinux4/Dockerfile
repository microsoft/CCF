# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Azure Linux 4.0 is still in beta, published under the public azurelinux-beta
# MCR repository. Switch BASE_IMAGE to mcr.microsoft.com/azurelinux/base/core:4.0
# once 4.0 is generally available (mirroring the 3.0 image the default dev
# container uses).
ARG BASE_IMAGE=mcr.microsoft.com/azurelinux-beta/base/core:4.0
FROM ${BASE_IMAGE}

# Azure Linux 4 uses dnf (not tdnf) and already trusts the Microsoft signing
# keys, so a plain refresh is enough.
RUN dnf -y update

# Basic dev deps, helps smoothly install VSCode server. Azure Linux 4 has no
# build-essential meta-package, so install the equivalent toolchain explicitly.
# gawk provides awk, which the VSCode server's check-requirements.sh needs; the
# minimal Azure Linux 4 base image ships without it (unlike Azure Linux 3, where
# build-essential pulled it in transitively).
RUN dnf -y install gcc gcc-c++ make binutils gawk tar gzip ca-certificates git
