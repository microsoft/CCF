#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Bionic/18.04 ships ansible 2.5, which does not support some of
# the features our playbooks need like apt_repository. Once we
# upgrade to 20.4, the following two lines can be removed.
sudo add-apt-repository ppa:ansible/ansible -y
sudo apt-get update

sudo apt install ansible -y
ansible-playbook "$@"
