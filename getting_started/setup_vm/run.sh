#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

sudo apt install python3-pip
pip install ansible-base
ansible-playbook "$@"
