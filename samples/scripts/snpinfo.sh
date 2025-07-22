#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set +e


# Path to the SEV guest device from 6.0 onwards
# https://www.kernel.org/doc/html/v6.0/virt/coco/sev-guest.html
AMD_SEV_GUEST_DEVICE="/dev/sev-guest"

echo "AMD SEV-SNP DEVICE:"
if test -c "$AMD_SEV_GUEST_DEVICE"; then
    echo "$AMD_SEV_GUEST_DEVICE detected."
else
    echo "$AMD_SEV_GUEST_DEVICE was not detected."
fi