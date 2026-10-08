#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Replays each scenario's recorded traces, which must pass, and its valid and
# invalid traces, diffs against them in its valid/ and invalid/ directories,
# which must pass and fail.

set -euo pipefail
shopt -s nullglob

REPLAY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPLAYER=${1:-$REPLAY_DIR/.lake/build/bin/disaster-recovery-replay}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

runs=0
failures=0
for fixture in "$REPLAY_DIR"/fixtures/*/; do
  for case in "$fixture" "$fixture"valid/*.diff "$fixture"invalid/*.diff; do
    dir=$fixture
    expected=pass
    if [[ $case == *.diff ]]; then
      dir=$WORK/case
      if [[ $case == "$fixture"invalid/* ]]; then
        expected=fail
      fi
      rm -rf "$dir"
      mkdir "$dir"
      cp "$fixture"scenario.json "$fixture"*.out "$dir"
      git -C "$dir" apply --unidiff-zero "$case"
    fi
    status=0
    "$REPLAYER" --wait-ms 0 \
      --participants "$(jq -r .participants "$dir/scenario.json")" \
      --open-kind "$(jq -r .open_kind "$dir/scenario.json")" \
      "$dir"/*.out >"$WORK/output" 2>&1 || status=$?
    case $status in
    0) outcome=pass ;;
    1) outcome=fail ;;
    *) outcome="exit code $status" ;;
    esac
    runs=$((runs + 1))
    if [[ $outcome != "$expected" ]]; then
      echo "${case#"$REPLAY_DIR"/}: expected $expected, got $outcome: $(tail -n 1 "$WORK/output")"
      failures=$((failures + 1))
    fi
  done
done
echo "$((runs - failures))/$runs traces replayed as expected"
[[ $failures -eq 0 ]]
