#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Very crude and incomplete check, but should catch at least egregiously
# uncompiled but exported headers.

find src/ include/ -type f -print0 | xargs -0 grep -h "#include" | grep -E "include .?ccf/" | cut -d " " -f 2 | jq -r . | grep -v "version\.h" | sort -u  > /tmp/CCF_INCLUDED

pushd include/ || exit 1
find ccf -type f -name "*.h" | sort -u > /tmp/CCF_HEADERS
popd || exit 1

diff -y --suppress-common-lines /tmp/CCF_HEADERS /tmp/CCF_INCLUDED