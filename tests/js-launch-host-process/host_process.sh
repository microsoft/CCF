#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

echo "Writing to stdout"
echo >&2 "Writing to stderr"

STDIN=$(cat)
echo -n "$1$STDIN" > "$2"
