#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

install -d -m 0755 /run/sshd
ssh-keygen -A
/usr/sbin/sshd \
  -o PidFile=/run/sshd.pid \
  -E /tmp/sshd-codespaces.log

exec "$@"
