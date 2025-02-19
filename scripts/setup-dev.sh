#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

tdnf -y install  \
    vim  \
    cpio # Used by LTS test to extract binaries from rpms