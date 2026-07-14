#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

install -d -m 0755 /run/sshd
ssh-keygen -A
/usr/sbin/sshd \
  -p 22 \
  -o PidFile=/run/sshd.pid \
  -o PermitRootLogin=prohibit-password \
  -o PasswordAuthentication=no \
  -o PubkeyAuthentication=yes \
  -E /tmp/sshd-codespaces.log

exec "$@"
