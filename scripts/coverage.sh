#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Aggregate LLVM coverage data produced by test runs and produce coverage
# statistics, including overall summaries and details of uncovered lines.

set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] [<binary> ...]

Aggregate LLVM coverage data from test runs and produce coverage reports.

Build CCF with -DCOVERAGE=ON, run the desired tests (e.g. via ctest -L unit),
then call this script from the build directory.

Options:
  -d <dir>          Directory to search for .profraw files (default: .)
  -o <file>         Output merged profile file (default: <dir>/coverage.profdata)
  --html <dir>      Generate an HTML coverage report in <dir>
  --show-uncovered  Print files and line numbers with zero coverage
  -h, --help        Show this help

Binaries:
  One or more instrumented executables may be given as positional arguments.
  If none are given, the script reads the list from <dir>/coverage_binaries.txt,
  which is generated automatically by CMake when -DCOVERAGE=ON is set.

Examples:
  # From the build directory after running unit tests:
  ctest -L unit
  ../scripts/coverage.sh

  # Generate an HTML report:
  ../scripts/coverage.sh --html ./coverage_html

  # Show which specific lines are uncovered:
  ../scripts/coverage.sh --show-uncovered

  # Specify binaries explicitly:
  ../scripts/coverage.sh map_test crypto_test

Notes:
  - Tests must be built and run with -DCOVERAGE=ON. The build system
    automatically sets LLVM_PROFILE_FILE so each test writes its own
    uniquely-named .profraw file.
  - Coverage of code under 3rdparty/ is excluded from all reports.
  - Requires llvm-profdata and llvm-cov (any of -18 / -15 suffixed variants
    are also accepted).
EOF
  exit 0
}

PROFRAW_DIR="."
OUTPUT_FILE=""
HTML_DIR=""
SHOW_UNCOVERED=0
BINARIES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) PROFRAW_DIR="$2"; shift 2 ;;
    -o) OUTPUT_FILE="$2"; shift 2 ;;
    --html) HTML_DIR="$2"; shift 2 ;;
    --show-uncovered) SHOW_UNCOVERED=1; shift ;;
    -h|--help) usage ;;
    --) shift; BINARIES+=("$@"); break ;;
    -*) echo "Unknown option: $1" >&2; exit 1 ;;
    *) BINARIES+=("$1"); shift ;;
  esac
done

if [[ -z "${OUTPUT_FILE}" ]]; then
  OUTPUT_FILE="${PROFRAW_DIR}/coverage.profdata"
fi

# ---------------------------------------------------------------------------
# Locate llvm tools, accepting versioned suffixes
# ---------------------------------------------------------------------------
find_tool() {
  local tool="$1"
  for candidate in "${tool}" "${tool}-18" "${tool}-15"; do
    if command -v "${candidate}" &>/dev/null; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  echo "Error: '${tool}' not found in PATH (also tried -18 and -15 suffixes)" >&2
  return 1
}

LLVM_PROFDATA=$(find_tool llvm-profdata)
LLVM_COV=$(find_tool llvm-cov)

# ---------------------------------------------------------------------------
# Auto-discover binaries from coverage_binaries.txt if none given explicitly
# ---------------------------------------------------------------------------
if [[ ${#BINARIES[@]} -eq 0 ]]; then
  BINARIES_FILE="${PROFRAW_DIR}/coverage_binaries.txt"
  if [[ ! -f "${BINARIES_FILE}" ]]; then
    echo "Error: no binaries specified and '${BINARIES_FILE}' not found." >&2
    echo "Either pass binary paths as arguments or build with -DCOVERAGE=ON." >&2
    exit 1
  fi
  mapfile -t BINARIES < "${BINARIES_FILE}"
  # Drop blank lines (file(GENERATE) may add a trailing newline)
  readarray -t BINARIES < <(printf '%s\n' "${BINARIES[@]}" | grep -v '^[[:space:]]*$')
fi

if [[ ${#BINARIES[@]} -eq 0 ]]; then
  echo "Error: no instrumented binaries found." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Collect .profraw files
# ---------------------------------------------------------------------------
mapfile -t PROFRAW_FILES < <(find "${PROFRAW_DIR}" -name "*.profraw" -type f | sort)

if [[ ${#PROFRAW_FILES[@]} -eq 0 ]]; then
  echo "No .profraw files found in '${PROFRAW_DIR}'." >&2
  echo "Make sure tests were built and run with -DCOVERAGE=ON." >&2
  exit 1
fi

echo "Found ${#PROFRAW_FILES[@]} .profraw file(s) in '${PROFRAW_DIR}'"

# ---------------------------------------------------------------------------
# Merge profile data
# ---------------------------------------------------------------------------
echo "Merging coverage data into '${OUTPUT_FILE}'..."
"${LLVM_PROFDATA}" merge -sparse "${PROFRAW_FILES[@]}" -o "${OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# Build common llvm-cov argument list
# ---------------------------------------------------------------------------
build_cov_args() {
  # First binary is the positional argument; additional binaries use -object
  local args=("${BINARIES[0]}" "-instr-profile=${OUTPUT_FILE}")
  for bin in "${BINARIES[@]:1}"; do
    args+=("-object" "${bin}")
  done
  # Exclude third-party code from all reports
  args+=("-ignore-filename-regex=3rdparty/")
  printf '%s\n' "${args[@]}"
}

mapfile -t COV_ARGS < <(build_cov_args)

# ---------------------------------------------------------------------------
# Overall coverage summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Coverage Summary ==="
"${LLVM_COV}" report "${COV_ARGS[@]}"

# ---------------------------------------------------------------------------
# Uncovered lines detail
# ---------------------------------------------------------------------------
if [[ "${SHOW_UNCOVERED}" -eq 1 ]]; then
  echo ""
  echo "=== Uncovered Lines ==="
  # llvm-cov show --format=text emits blocks like:
  #     <spaces><line_num>|<count>|<source>
  # A file header line ends with a bare colon: "/path/to/file.cpp:"
  # Lines whose count field is exactly 0 are unexecuted executable lines.
  "${LLVM_COV}" show "${COV_ARGS[@]}" --format=text |
    awk '
      # Match a file header (ends with colon, no leading whitespace)
      /^[^[:space:]].*:$/ {
        current_file = substr($0, 1, length($0) - 1)
        printed_header = 0
        next
      }
      # Match lines with a zero execution count: " <N>| 0|<source>"
      /^[[:space:]]+[0-9]+\|[[:space:]]+0\|/ {
        if (!printed_header) {
          print current_file ":"
          printed_header = 1
        }
        # Strip leading whitespace and reformat as "  <line>: <source>"
        line = $0
        sub(/^[[:space:]]+/, "", line)
        n = split(line, parts, "|")
        printf "  %s: %s\n", parts[1], parts[3]
      }
    '
fi

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
if [[ -n "${HTML_DIR}" ]]; then
  echo ""
  echo "Generating HTML report in '${HTML_DIR}'..."
  mkdir -p "${HTML_DIR}"
  "${LLVM_COV}" show "${COV_ARGS[@]}" --format=html --output-dir="${HTML_DIR}"
  echo "HTML report written to '${HTML_DIR}/index.html'"
fi
