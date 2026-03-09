#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Install ansible from ppa because service_facts
# is broken on Ubuntu 20.04 with the default apt package.
# See https://github.com/ansible/ansible/issues/68536 (fixed in ansible >= 2.10)
sudo apt-get -y update
sudo apt install software-properties-common -y
sudo add-apt-repository -y --update ppa:ansible/ansible
sudo apt install ansible -y
ansible-playbook "$@"