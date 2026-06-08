#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set +e

# Path to the SEV guest device on patched 5.x kernels
AMD_SEV_DEVICE="/dev/sev"
# Path to the SEV guest device from 6.0 onwards
# https://www.kernel.org/doc/html/v6.0/virt/coco/sev-guest.html
AMD_SEV_GUEST_DEVICE="/dev/sev-guest"

echo "AMD SEV-SNP DEVICE:"
if test -c "$AMD_SEV_DEVICE"; then
    echo "$AMD_SEV_DEVICE detected."
elif test -c "$AMD_SEV_GUEST_DEVICE"; then
    echo "$AMD_SEV_GUEST_DEVICE detected."
else
    echo "Neither $AMD_SEV_DEVICE, nor $AMD_SEV_GUEST_DEVICE detected."
fi