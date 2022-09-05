#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set +e

AMD_SEV_SNP_DEVICE="/dev/sev"
echo "AMD SEV-SNP DEVICE:"
if test -c "$AMD_SEV_SNP_DEVICE"; then
    echo "$AMD_SEV_SNP_DEVICE detected."
    exit 0
else
    echo "$AMD_SEV_SNP_DEVICE not detected."
    exit 1
fi