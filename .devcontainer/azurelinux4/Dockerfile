# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Azure Linux 4.0 is currently in beta and only published to the staging ACR
# used by CI (see .github/workflows/ci-al4.yml). Override BASE_IMAGE with
# mcr.microsoft.com/azurelinux/base/core:4.0 once 4.0 is generally available.
ARG BASE_IMAGE=azlpubstagingacroxz2o4gw.azurecr.io/azurelinux/base/core:4.0
FROM ${BASE_IMAGE}

# Azure Linux 4 uses dnf (not tdnf) and already trusts the Microsoft signing
# keys, so a plain refresh is enough.
RUN dnf -y update

# Basic dev deps, helps smoothly install VSCode server. Azure Linux 4 has no
# build-essential meta-package, so install the equivalent toolchain explicitly.
RUN dnf -y install gcc gcc-c++ make binutils tar gzip ca-certificates git
