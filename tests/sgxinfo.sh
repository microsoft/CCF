#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set +e

if grep -q "^flags.*sgx.*" < /proc/cpuinfo ; then
    echo "LINUX KERNEL WITH BUILT-IN SGX SUPPORT (5.11+):"
    uname -r
else
    # Pre 5.11 kernel
    echo "DRIVER INFO:"
    modinfo intel_sgx
    echo ""
    echo ""
    echo "DRIVER LOADED:"
    lsmod | grep intel_sgx || echo "Not loaded"
fi
echo ""
echo ""

echo "AESM DAEMON:"
systemctl --no-pager status aesmd 2>/dev/null || echo "Not running"
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