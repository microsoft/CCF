#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set +e

kernel_version=$(uname -r)
major_version=$(echo ${kernel_version} | cut -d '.' -f 1)
minor_version=$(echo ${kernel_version} | cut -d '.' -f 2)

if [ ${major_version} -gt 5 ] || [[ ${major_version} -eq 5 && ${minor_version} -ge 11 ]]; then
    echo "LINUX KERNEL WITH SGX SUPPORT (5.11+):"
    echo "${kernel_version}"
else
    # Pre 5.11 kernel
    echo "DRIVER INFO:"
    modinfo intel_sgx 2>/dev/null
    echo ""
    echo ""
    echo "DRIVER LOADED:"
    lsmod | grep intel_sgx || echo "Not loaded"
fi
echo ""
echo ""

echo "PSW INFO:"
apt list --installed 2>/dev/null | grep libsgx
echo ""
echo ""

echo "DCAP CLIENT INFO:"
apt list --installed 2>/dev/null | grep az-dcap
echo ""
echo ""

echo "SGX INFO:"
/opt/openenclave/bin/oesgx