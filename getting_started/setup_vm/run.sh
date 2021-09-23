#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

sudo apt-get update
sudo apt install software-properties-common
sudo add-apt-repository -y --update ppa:ansible/ansible
sudo apt install ansible -y
ansible-playbook "$@"
