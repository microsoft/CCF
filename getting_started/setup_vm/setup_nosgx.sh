#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex
sudo add-apt-repository ppa:ansible/ansible -y
sudo apt-get update
sudo apt install ansible -y
ansible-playbook ccf-dependencies-no-sgx.yml
