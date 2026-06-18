#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Enable the IPv6 loopback address (::1) inside a CI job container.
#
# The IPv6 end-to-end tests (common_ipv6, reconfiguration_ipv6) bind every node
# to ::1. Docker disables IPv6 in a container's network namespace by default, so
# ::1 is never assigned to the loopback interface. This script re-enables it
# using the container's NET_ADMIN capability (granted in .github/workflows/ci.yml).
#
# It is deliberately tolerant: if the host kernel itself has IPv6 disabled there
# is nothing a container can do about it, so we only warn here. The IPv6 e2e
# tests check for ::1 availability themselves and skip gracefully when it is
# missing, so this setup step never takes down the whole job.

set -uo pipefail

if [ -d /proc/sys/net/ipv6 ]; then
    echo 0 >/proc/sys/net/ipv6/conf/all/disable_ipv6 || true
    echo 0 >/proc/sys/net/ipv6/conf/default/disable_ipv6 || true
    echo 0 >/proc/sys/net/ipv6/conf/lo/disable_ipv6 || true
else
    echo "WARNING: /proc/sys/net/ipv6 is absent; the host kernel has IPv6 disabled"
fi

if python3 -c "import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.bind(('::1', 0)); s.close()"; then
    echo "IPv6 loopback ::1 is available"
else
    echo "WARNING: IPv6 loopback ::1 is not available; IPv6 e2e tests will be skipped"
fi
