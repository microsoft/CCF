#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )

usage() {
  cat <<'EOF'
Usage: scripts/bench-ab.sh [run|report|local] [options]

No command means local: restore main perf, run benchmarks, and write a report.

Options:
  --build-dir DIR       Build directory. Default: build-bench-ab
  --results-dir DIR     Benchmark JSON directory. Default: build/bench-ab
  --main-perf-dir DIR   Main-branch perf JSON directory. Default: build/bench-ab/main
  --output FILE         Markdown report path. Default: RESULTS_DIR/report.md
  --iterations N        Benchmark repetitions. Default: 3
  --label LABEL         Report label. Default: run
  --summary             Append report to GITHUB_STEP_SUMMARY
EOF
}

abs_path() {
  if [[ "$1" == /* ]]; then
    echo "$1"
  else
    echo "$ROOT_DIR/$1"
  fi
}

cmd=local
case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  run|report|local)
    cmd=$1
    shift
    ;;
esac

build_dir=build-bench-ab
results_dir=build/bench-ab
main_perf_dir=build/bench-ab/main
output_file=
iterations=3
label=run
summary=false
repository=${GITHUB_REPOSITORY:-microsoft/CCF}
main_artifact=perf-bench-virtual-main

while [[ $# -gt 0 ]]; do
  opt=$1
  case "$opt" in
    --build-dir) build_dir=${2:?$opt requires a value}; shift 2 ;;
    --results-dir) results_dir=${2:?$opt requires a value}; shift 2 ;;
    --main-perf-dir) main_perf_dir=${2:?$opt requires a value}; shift 2 ;;
    --output) output_file=${2:?$opt requires a value}; shift 2 ;;
    --iterations) iterations=${2:?$opt requires a value}; shift 2 ;;
    --label) label=${2:?$opt requires a value}; shift 2 ;;
    --summary) summary=true; shift ;;
    *) echo "Unknown argument: $opt" >&2; usage >&2; exit 1 ;;
  esac
done

if ! [[ "$iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "--iterations must be a positive integer" >&2
  exit 1
fi

output_file=${output_file:-"$results_dir/report.md"}

build_dir=$(abs_path "$build_dir")
results_dir=$(abs_path "$results_dir")
main_perf_dir=$(abs_path "$main_perf_dir")
output_file=$(abs_path "$output_file")

restore_main_perf() {
  mkdir -p "$main_perf_dir"
  tmp_dir=$(mktemp -d)
  restored=false

  echo "Restoring latest main perf results..."
  if command -v gh >/dev/null 2>&1; then
    run_ids=$(gh api "repos/$repository/actions/artifacts?name=$main_artifact&per_page=100" \
      --jq '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | reverse | .[0:10] | .[].workflow_run.id') || run_ids=

    for run_id in $run_ids; do
      download_dir="$tmp_dir/$run_id"
      mkdir -p "$download_dir"
      if gh run download "$run_id" --repo "$repository" --name "$main_artifact" --dir "$download_dir" >/dev/null 2>&1; then
        [[ -n "$(find "$download_dir" -name '*.json' -print -quit)" ]] && restored=true
      fi
    done
  elif command -v curl >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
    artifacts_json="$tmp_dir/artifacts.json"
    if curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$repository/actions/artifacts?name=$main_artifact&per_page=100" \
      -o "$artifacts_json"; then
      python3 - "$artifacts_json" > "$tmp_dir/urls" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

artifacts = [
    artifact
    for artifact in data.get("artifacts", [])
    if not artifact.get("expired")
]
for artifact in sorted(
    artifacts, key=lambda artifact: artifact.get("created_at", ""), reverse=True
)[:10]:
    print(artifact["archive_download_url"])
PY

      index=0
      while IFS= read -r url; do
        index=$((index + 1))
        archive="$tmp_dir/$index.zip"
        download_dir="$tmp_dir/$index"
        mkdir -p "$download_dir"
        if curl -fsSL -L "$url" -o "$archive" &&
          unzip -q "$archive" -d "$download_dir"; then
          [[ -n "$(find "$download_dir" -name '*.json' -print -quit)" ]] && restored=true
        fi
      done < "$tmp_dir/urls"
    fi
  fi

  if [[ "$restored" == "true" ]]; then
    rm -f "$main_perf_dir"/*.json
    find "$tmp_dir" -mindepth 2 -name '*.json' -exec cp {} "$main_perf_dir"/ \;
    echo "Main perf results saved in $main_perf_dir"
  else
    echo "Could not restore main perf results; using $main_perf_dir" >&2
  fi
  rm -rf "$tmp_dir"
}

run_benchmarks() {
  mkdir -p "$build_dir" "$results_dir"
  rm -f "$results_dir"/bencher-pr-*.json
  log_dir="$results_dir/logs"
  mkdir -p "$log_dir"
  rm -f "$log_dir"/*.log

  build_log="$log_dir/build.log"
  echo "Building..."
  {
    cmake -S "$ROOT_DIR" -B "$build_dir" -GNinja -DWORKER_THREADS=2 &&
    cmake --build "$build_dir"
  } > "$build_log" 2>&1 || {
    echo "Build failed. See $build_log" >&2
    exit 1
  }

  pushd "$build_dir" >/dev/null
  for ((i = 1; i <= iterations; i++)); do
    echo "Running $i/$iterations..."
    run_log="$log_dir/iteration-${i}.log"
    rm -f bencher.json
    {
      ./tests.sh -VV -L benchmark &&
      ./tests.sh -VV -L perf -C perf &&
      PYTHONPATH="$ROOT_DIR/tests" env/bin/python convert_pico_to_bencher.py
    } > "$run_log" 2>&1 || {
      echo "Iteration $i failed. See $run_log" >&2
      exit 1
    }
    result="$results_dir/bencher-pr-${i}.json"
    mv bencher.json "$result"
  done
  popd >/dev/null

  echo "Benchmark results saved in $results_dir"
  echo "Logs saved in $log_dir"
}

write_report() {
  mkdir -p "$( dirname "$output_file" )"
  python3 "$ROOT_DIR/scripts/compare_bencher_ab.py" \
    "$main_perf_dir" \
    "$results_dir" \
    --label2 "$label" > "$output_file"

  if [[ "$summary" == "true" ]]; then
    if [[ -z "${GITHUB_STEP_SUMMARY:-}" ]]; then
      echo "GITHUB_STEP_SUMMARY is not set" >&2
      exit 1
    fi
    cat "$output_file" >> "$GITHUB_STEP_SUMMARY"
  fi

  echo "Report saved in $output_file"
}

case "$cmd" in
  run) run_benchmarks ;;
  report) write_report ;;
  local) restore_main_perf; run_benchmarks; write_report; echo "Done." ;;
esac
