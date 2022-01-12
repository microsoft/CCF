#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

# This only checks that the following commands do not throw errors.
# It is expected that other tests cover correctness of the generated
# proposals, this just checks the basic usability of the CLI.

keygenerator.sh --help
keygenerator.sh --name alice
keygenerator.sh --name bob --gen-enc-key
