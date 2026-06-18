#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Enable the IPv6 loopback address (::1) inside a CI job container.
#
# The IPv6 end-to-end tests (common_ipv6, reconfiguration_ipv6) bind every node
# to ::1. Docker disables IPv6 in a container's network namespace by default, so
# ::1 is never assigned to the loopback interface.
#
# IPv6 is enabled at container creation via the
# "--sysctl net.ipv6.conf.*.disable_ipv6=0" options on the job container (see the
# workflows under .github/workflows). On privileged containers the runtime writes
# below also enable it. This script then asserts that ::1 is bindable and fails
# the step if it is not, since the IPv6 e2e tests require it and must not be
# silently skipped.

set -uo pipefail

# Best-effort runtime enable. On privileged containers /proc/sys is writable and
# these writes turn IPv6 back on for the loopback interface. On non-privileged
# containers /proc/sys is mounted read-only, so the writes fail harmlessly; IPv6
# is instead enabled at container creation via the
# "--sysctl net.ipv6.conf.*.disable_ipv6=0" options on the job container. The
# stderr redirection is placed before the output redirection so the
# "Read-only file system" message is suppressed when the write is not possible.
if [ -d /proc/sys/net/ipv6 ]; then
    echo 0 2>/dev/null >/proc/sys/net/ipv6/conf/all/disable_ipv6 || true
    echo 0 2>/dev/null >/proc/sys/net/ipv6/conf/default/disable_ipv6 || true
    echo 0 2>/dev/null >/proc/sys/net/ipv6/conf/lo/disable_ipv6 || true
fi

# The IPv6 e2e tests require ::1 and must not be silently skipped, so fail loudly
# if the loopback address is still unavailable.
if python3 -c "import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.bind(('::1', 0)); s.close()"; then
    echo "IPv6 loopback ::1 is available"
else
    echo "ERROR: IPv6 loopback ::1 is not available; IPv6 e2e tests cannot run" >&2
    exit 1
fi
