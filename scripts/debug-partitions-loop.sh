#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Temporary CI diagnostic, not a test-suite change. Run from the repository root.
set -euo pipefail

cd build
unset CR_FILTER
./tests.sh -N -R '^partitions$' -C partitions
source env/bin/activate
export VENV_DIR="$PWD/env"
export BETTER_EXCEPTIONS=1

printf 'iteration\tstarted_utc\telapsed_seconds\texit_status\n' > partitions-iterations.tsv
for iteration in $(seq 1 100); do
  started=$(date -u +%FT%TZ)
  start_seconds=$SECONDS
  echo "Partitions iteration $iteration/100 ($started)"
  status=0
  ctest --timeout 360 --verbose --output-on-failure \
    -R '^partitions$' -C partitions --no-tests=error \
    > partitions-current.log 2>&1 || status=$?
  elapsed=$((SECONDS - start_seconds))
  printf '%s\t%s\t%s\t%s\n' "$iteration" "$started" "$elapsed" "$status" >> partitions-iterations.tsv
  echo "Partitions iteration $iteration: exit=$status, elapsed=${elapsed}s"
  if [ "$status" -ne 0 ]; then
    echo "Stopping at first failure; preserving this iteration's logs and node artifacts."
    tail -n 80 partitions-current.log
    exit "$status"
  fi
  if [ "$iteration" -lt 100 ]; then
    # Networks have stopped. Do not accumulate successful node logs or ledgers.
    rm -rf -- workspace
  fi
done
echo "All 100 iterations passed; preserving only the final iteration."
