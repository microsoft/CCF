#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Replays each fixture's trace.ndjson, which must be accepted, and the traces
# obtained by applying each diff in its valid/ and invalid/ directories. Valid
# diffs must be accepted. An invalid diff's name starts with its expected
# status: rejected., invalid-trace. or unsupported. Every replay must be
# deterministic, every failure must carry a diagnostic, and every rejection must
# identify the failing record. Rejected traces also run without diagnostic guards.

set -euo pipefail
shopt -s nullglob

REPLAY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPLAYER=${1:-$REPLAY_DIR/../.lake/build/bin/kv-replay}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/model-rejections"

runs=0
failures=0
for fixture in "$REPLAY_DIR"/fixtures/*/; do
  for case in "$fixture" "$fixture"valid/*.diff "$fixture"invalid/*.diff; do
    trace=$fixture/trace.ndjson
    expected=accepted
    if [[ $case == *.diff ]]; then
      rm -rf "$WORK/case"
      mkdir "$WORK/case"
      cp "$trace" "$WORK/case/"
      git -C "$WORK/case" apply --unidiff-zero "$case"
      trace=$WORK/case/trace.ndjson
      if [[ $case == "$fixture"invalid/* ]]; then
        expected=$(basename "$case")
        expected=${expected%%.*}
        expected=${expected//-/_}
      fi
    fi
    first=$("$REPLAYER" --json "$trace" || true)
    second=$("$REPLAYER" --json "$trace" || true)
    status=$(jq -r .status <<<"$first")
    problem=
    if [[ $status != "$expected" ]]; then
      problem="expected $expected, got $status: $(jq -r .message <<<"$first")"
    elif [[ $first != "$second" ]]; then
      problem="nondeterministic replay"
    elif [[ $status != accepted && -z $(jq -r .message <<<"$first") ]]; then
      problem="missing diagnostic"
    elif [[ $status == rejected && $(jq -r '.seq // empty' <<<"$first") == "" ]]; then
      problem="rejection does not identify the failing record"
    fi
    runs=$((runs + 1))
    if [[ -n $problem ]]; then
      echo "${case#"$REPLAY_DIR"/}: $problem"
      failures=$((failures + 1))
    fi
    if [[ $expected == rejected ]]; then
      cp "$trace" "$WORK/model-rejections/$(basename "$fixture").$(basename "$case" .diff).ndjson"
    fi
  done
done
echo "$((runs - failures))/$runs traces replayed as expected"
[[ $runs -gt 0 && $failures -eq 0 ]]

(
  cd "$REPLAY_DIR/.."
  CCF_KV_MODEL_FIXTURES="$WORK/model-rejections" lake env lean --stdin <<'EOF'
import Kv.Tests.Replay

#eval show IO Unit from do
  let some directory <- IO.getEnv "CCF_KV_MODEL_FIXTURES"
    | throw (IO.userError "missing model fixture directory")
  Kv.Tests.Replay.checkModelFixtures directory
EOF
)
