#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Prints the ctest `-j` budget to use for CCF's end-to-end test buckets.
#
# Each e2e test declares a PROCESSORS weight (see add_e2e_test in
# cmake/common.cmake) in units of concurrently live CCF node processes, and
# ctest keeps the sum of those weights within this budget. CCF nodes in e2e
# tests spend most of their time waiting on timers, sockets and disk rather
# than burning CPU, so the budget is deliberately larger than the core count.
#
# The multiplier is the safety knob: raising it packs more tests together and
# shortens the bucket, but starving nodes of CPU shows up as spurious
# leadership elections and flaky tests. Lower it if that happens.
#
# Override with CCF_CI_TEST_JOBS to pin an exact value.

set -euo pipefail

if [ -n "${CCF_CI_TEST_JOBS:-}" ]; then
    echo "$CCF_CI_TEST_JOBS"
    exit 0
fi

NODES_PER_CORE_NUMERATOR=3
NODES_PER_CORE_DENOMINATOR=2

cores=$(nproc --all)
jobs=$((cores * NODES_PER_CORE_NUMERATOR / NODES_PER_CORE_DENOMINATOR))

# Never drop below the heaviest single test's weight, so that a test is never
# left unable to be scheduled alongside anything else on a small machine.
if [ "$jobs" -lt 16 ]; then
    jobs=16
fi

echo "$jobs"
