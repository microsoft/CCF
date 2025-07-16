#!/bin/sh
# Very crude and incomplete check, but should catch at least egregiously
# uncompiled but exported headers.

find src/ include/ -type f | xargs grep -h "#include" | grep -E "include .?ccf/" | cut -d " " -f 2 | jq -r . | sort -u  > /tmp/CCF_INCLUDED

pushd include/
find ccf -type f -name "*.h" | sort -u > /tmp/CCF_HEADERS
popd

diff -y --suppress-common-lines /tmp/CCF_HEADERS /tmp/CCF_INCLUDED