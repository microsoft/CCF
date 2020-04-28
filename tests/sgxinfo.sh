#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set +e

echo "DRIVER INFO:"
modinfo intel_sgx
echo ""
echo ""

echo "DRIVER LOADED:"
lsmod | grep intel_sgx || echo "Not loaded"
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