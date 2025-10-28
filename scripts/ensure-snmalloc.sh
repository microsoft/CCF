#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# 
# Make sure that the resulting binary contains snmalloc-overwritten allocators.
# 
# A typical snmalloc assembly looks on Azure Linux 3.0 x86_64 as:
# 0000000000565b70 <malloc>:
#   565bb3:	e9 b8 10 00 00       	jmp    566c70 <_ZN8snmalloc9Allocator ...
#   565c97:	e9 f4 6e 00 00       	jmp    56cb90 <_ZN8snmalloc6Ticker ...
#   565c9f:	e9 ec 11 00 00       	jmp    566e90 <_ZN8snmalloc9Allocator ...
#   565cb0:	e9 db 13 00 00       	jmp    567090 <_ZN8snmalloc9Allocator ...
#00000000005707b0 <_Znwm>:
#   5707f3:	e9 38 1c 00 00       	jmp    572430 <_ZN8snmalloc9Allocator ...
#   5708d7:	e9 b4 c2 ff ff       	jmp    56cb90 <_ZN8snmalloc6Ticker ...
#   5708df:	e9 8c 1d 00 00       	jmp    572670 <_ZN8snmalloc9Allocator ...
#   5708f0:	e9 6b 1f 00 00       	jmp    572860 <_ZN8snmalloc9Allocator ...

set -e

BINARY=$1

functions=("malloc" "operator new(unsigned long)")
failed_functions=()

for func in "${functions[@]}"; do
    output=$(objdump -d -C "$BINARY"  \
        | grep -A 101 " <${func}>:"  \
        | grep -E "(jmp|call)"  \
        | grep "snmalloc" || true)
    
    lines=$(echo "$output" | wc -l)
    
    if [ -z "$output" ] || [ "$lines" -eq 0 ]; then
        failed_functions+=("$func")
    else
        echo "Found snmalloc markers in $func"
    fi
done

if [ ${#failed_functions[@]} -gt 0 ]; then
    echo "Error: no snmalloc markers found in: ${failed_functions[*]}"
    exit 1
fi
