#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

LLVM_PROFILE_FILE="${1}.profraw" "./${1}" -nv
