#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Run e2e tests from e2e_tests.json, bypassing CTest.

Usage (from the tests directory):
    uv run ./run_e2e.py [options]

Supports the same filtering semantics as CTest:
    -L / --label-include     Include tests matching label regex
    -LE / --label-exclude    Exclude tests matching label regex
    -R / --include           Include tests matching name regex
    -E / --exclude           Exclude tests matching name regex
    --timeout SECONDS        Per-test timeout (default: 360)
    -j / --parallel N        Run N tests in parallel (default: 1)
    --config CONFIG          Only include tests whose label matches CONFIG
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time


def load_tests(path):
    with open(path, "r") as f:
        return json.load(f)


def matches(pattern, value):
    """Check if a regex pattern matches anywhere in value."""
    if pattern is None:
        return False
    return re.search(pattern, value) is not None


def filter_tests(tests, args):
    """Apply CTest-like label and name filters."""
    selected = {}
    for name, info in tests.items():
        label = info.get("label", "")

        # -C / --config: only include if label matches config exactly
        if args.config and label != args.config:
            continue

        # -L: include only if label matches
        if args.label_include and not matches(args.label_include, label):
            continue

        # -LE: exclude if label matches
        if args.label_exclude and matches(args.label_exclude, label):
            continue

        # -R: include only if name matches
        if args.include and not matches(args.include, name):
            continue

        # -E: exclude if name matches
        if args.exclude and matches(args.exclude, name):
            continue

        selected[name] = info

    return selected


def run_test(name, info, build_dir, timeout):
    """Run a single e2e test. Returns (name, success, duration, output)."""
    script = info["python_script"]
    additional_args = info.get("additional_args", [])

    cmd = [
        sys.executable,
        script,
        "--label",
        name,
        *additional_args,
    ]

    env = os.environ.copy()
    tests_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = tests_dir + os.pathsep + env.get("PYTHONPATH", "")
    env["BETTER_EXCEPTIONS"] = "1"

    print(f"\n{'='*60}")
    print(f"START: {name}")
    print(f"  script: {script}")
    if additional_args:
        print(f"  args: {' '.join(additional_args)}")
    print(f"{'='*60}\n", flush=True)

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            cwd=build_dir,
            env=env,
            timeout=timeout,
        )
        duration = time.monotonic() - start
        success = result.returncode == 0
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        success = False
        print(f"\nTIMEOUT: {name} after {timeout}s")

    status = "PASS" if success else "FAIL"
    print(f"\n{'='*60}")
    print(f"{status}: {name} ({duration:.1f}s)")
    print(f"{'='*60}\n", flush=True)

    return name, success, duration


def main():
    parser = argparse.ArgumentParser(
        description="Run CCF e2e tests from e2e_tests.json"
    )
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_build_dir = os.path.join(script_dir, "..", "build")
    parser.add_argument(
        "--tests-json",
        default=os.path.join(default_build_dir, "e2e_tests.json"),
        help="Path to e2e_tests.json (default: ../build/e2e_tests.json relative to this script)",
    )
    parser.add_argument(
        "-L",
        "--label-include",
        help="Include tests whose label matches this regex",
    )
    parser.add_argument(
        "-LE",
        "--label-exclude",
        help="Exclude tests whose label matches this regex",
    )
    parser.add_argument(
        "-R", "--include", help="Include tests whose name matches this regex"
    )
    parser.add_argument(
        "-E", "--exclude", help="Exclude tests whose name matches this regex"
    )
    parser.add_argument(
        "-C", "--config", help="Only include tests whose label matches CONFIG"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=360,
        help="Per-test timeout in seconds (default: 360)",
    )
    parser.add_argument(
        "--build-dir",
        default=None,
        help="Build directory (default: directory containing tests-json)",
    )
    parser.add_argument(
        "--list", action="store_true", help="List matching tests and exit"
    )
    args = parser.parse_args()

    tests_json_path = os.path.abspath(args.tests_json)
    if not os.path.isfile(tests_json_path):
        print(f"Error: {tests_json_path} not found", file=sys.stderr)
        sys.exit(1)

    build_dir = args.build_dir or os.path.dirname(tests_json_path)

    tests = load_tests(tests_json_path)
    selected = filter_tests(tests, args)

    if not selected:
        print("No tests matched the given filters.")
        sys.exit(0)

    if args.list:
        for name, info in selected.items():
            label = info.get("label", "")
            print(f"  {name:<40s} [label={label or '(none)'}]")
        print(f"\n{len(selected)} test(s) matched.")
        sys.exit(0)

    print(f"Running {len(selected)} test(s) from {tests_json_path}")
    print(f"Build dir: {build_dir}")
    print(f"Timeout: {args.timeout}s\n")

    results = []
    for name, info in selected.items():
        result = run_test(name, info, build_dir, args.timeout)
        results.append(result)

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for _, s, _ in results if s)
    failed = sum(1 for _, s, _ in results if not s)
    total_time = sum(d for _, _, d in results)
    for name, success, duration in results:
        status = "PASS" if success else "FAIL"
        print(f"  {status}: {name} ({duration:.1f}s)")
    print(f"\n{passed} passed, {failed} failed, {len(results)} total ({total_time:.1f}s)")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
