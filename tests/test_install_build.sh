#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

mkdir -p build_against_install
cd build_against_install

CC=$(command -v clang-12)                                                       
CCX=$(command -v clang++-12)                                                    
                                                                                
if [ "$CC" = "" ]; then                                                         
    CC=$(command -v clang-10)                                                   
    CCX=$(command -v clang++-10)                                                
fi

CC=$CC CCX=$CCX cmake -GNinja "$@" ../samples/apps/logging/
ninja