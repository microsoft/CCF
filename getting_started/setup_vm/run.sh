#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

sudo apt-get update
sudo apt install ansible-base -y
ansible-playbook "$@"
