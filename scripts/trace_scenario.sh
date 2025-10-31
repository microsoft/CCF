#!/usr/bin/env bash
set -euo pipefail

# trace_scenario.sh
# Build raft_driver with tracing enabled, run a scenario to produce a JSON trace,
# then validate the trace against the TLA+ spec using tlc.py.
#
# Usage:
#   ./do_tracing.sh <scenario_file> [trace_output_dir]
#
# Example:
#   ./do_tracing.sh ../tests/raft_scenarios/basic_election.txt
#
# Notes:
# - Must be located in a direct subdirectory of the root of the ccf repo (ie scripts).
# - Will (re)configure /build with -DCCF_RAFT_TRACING=ON if not already enabled.
# - Output trace file: <trace_output_dir>/trace_<scenario_basename_without_ext>.jsonl
# - Trace name passed to tlc.py matches scenario basename.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
TLA_DIR="${ROOT_DIR}/tla"

if [[ $# -lt 1 ]]; then
  echo "ERROR: Missing scenario file argument" >&2
  echo "Usage: $0 <scenario_file> [trace_output_dir]" >&2
  exit 1
fi

SCENARIO_PATH="$1"
if [[ ! -f "${SCENARIO_PATH}" ]]; then
  # Accept relative to tests/raft_scenarios if only basename provided
  ALT_PATH="${ROOT_DIR}/tests/raft_scenarios/${SCENARIO_PATH}"
  if [[ -f "${ALT_PATH}" ]]; then
    SCENARIO_PATH="${ALT_PATH}"
  else
    echo "ERROR: Scenario file not found: ${SCENARIO_PATH}" >&2
    exit 1
  fi
fi
SCENARIO_PATH="$(realpath "${SCENARIO_PATH}")"

TRACE_OUT_DIR="${2:-${BUILD_DIR}/traces}"
mkdir -p "${TRACE_OUT_DIR}"

SCENARIO_FILE="$(basename "${SCENARIO_PATH}")"
TRACE_NAME="${SCENARIO_FILE%.*}"  # strip last extension
TRACE_FILE="${TRACE_OUT_DIR}/trace_${TRACE_NAME}.jsonl"

# Ensure build directory exists
if [[ ! -d "${BUILD_DIR}" ]]; then
  echo "ERROR: build directory not found at ${BUILD_DIR}. Run cmake first." >&2
  exit 1
fi

cd "${BUILD_DIR}"

# Ensure tracing compile definition enabled
if ! grep -q 'CCF_RAFT_TRACING:BOOL=ON' CMakeCache.txt 2>/dev/null; then
  echo "[INFO] Re-configuring CMake with CCF_RAFT_TRACING=ON" >&2
  cmake -GNinja -DCCF_RAFT_TRACING=ON ..
fi

echo "[INFO] Building raft_driver target" >&2
ninja -j 8 raft_driver

if [[ ! -x "${BUILD_DIR}/raft_driver" ]]; then
  echo "ERROR: raft_driver binary not found after build." >&2
  exit 1
fi

echo "[INFO] Running raft_scenarios_runner.py for scenario: ${SCENARIO_PATH}" >&2

# The runner writes processed trace lines to ./consensus/<scenario_basename>.ndjson
# Capture its markdown/stdout separately for reference.
RUNNER_MD_OUT="${TRACE_OUT_DIR}/runner_${TRACE_NAME}.md"

python3 "${ROOT_DIR}/tests/raft_scenarios_runner.py" "${BUILD_DIR}/raft_driver" "${SCENARIO_PATH}" >"${RUNNER_MD_OUT}" 2>"${RUNNER_MD_OUT}.stderr" || {
  echo "ERROR: raft_scenarios_runner.py failed. See ${RUNNER_MD_OUT}.stderr" >&2
  exit 1
}

# Determine generated ndjson trace path produced by runner
GENERATED_TRACE_FILE="${BUILD_DIR}/consensus/${SCENARIO_FILE}.ndjson"
if [[ ! -f "${GENERATED_TRACE_FILE}" ]]; then
  echo "ERROR: Expected trace file not found: ${GENERATED_TRACE_FILE}" >&2
  exit 1
fi

# Copy or symlink to TRACE_FILE for uniform downstream usage
cp "${GENERATED_TRACE_FILE}" "${TRACE_FILE}"
echo "[INFO] Trace file: ${TRACE_FILE}" >&2

# Basic sanity: ensure at least one raft_trace line exists
if ! grep -q '"tag": "raft_trace"' "${TRACE_FILE}"; then
  echo "WARNING: No raft_trace lines found in ${TRACE_FILE}. Tracing may be disabled or scenario deprecated." >&2
fi

# Run TLA+ trace validation
if [[ ! -f "${TLA_DIR}/tlc.py" ]]; then
  echo "ERROR: tlc.py not found at ${TLA_DIR}/tlc.py" >&2
  exit 1
fi

SPEC_PATH="consensus/Traceccfraft.tla"
if [[ ! -f "${TLA_DIR}/${SPEC_PATH}" ]]; then
  echo "ERROR: Spec file missing: ${TLA_DIR}/${SPEC_PATH}" >&2
  exit 1
fi

echo "[INFO] Validating trace with tlc.py (trace name: ${TRACE_NAME})" >&2
cd "${TLA_DIR}"
python3 ./tlc.py --workers 1 --dot --trace-name "${TRACE_NAME}" tv --ccf-raft-trace "${TRACE_FILE}" "${SPEC_PATH}" || {
  echo "ERROR: Trace validation failed" >&2
  exit 2
}

echo "[SUCCESS] Trace validated: ${TRACE_FILE}" >&2
