#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

grep -rin Throughput | cut -d ' ' -f 7 | awk '{s+=$1} END {print s}'
grep -rin "Latency.*ms" | cut -d ' ' -f 7  | awk '{a+=$1} END{print a/NR}'
#find . -maxdepth 2 -type d \( ! -name . \) -exec bash -c "cd '{}' && pwd && ~/code/pbft/infra/summary.sh" \; > result.txt
