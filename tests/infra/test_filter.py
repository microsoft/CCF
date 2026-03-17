# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Hierarchical test filtering via the CCF_TEST_FILTER environment variable.

The filter uses a slash-separated hierarchy:
  CCF_TEST_FILTER=operations           - run all tests in the "operations" runner thread
  CCF_TEST_FILTER=operations/snapshot  - run tests in "operations" whose name contains "snapshot"

The first segment is matched exactly against ConcurrentRunner thread names (the
prefix passed to cr.add()).  The second segment (if present) uses
case-insensitive substring matching against individual test function names and
is checked inside the @reqs.description decorator.

When a test-level filter is active, at least one test must match.  Call
check_any_matched() at the end of a run to raise if nothing ran (likely a
typo).  It also logs the list of tests that were executed.
"""

import os
import threading

from loguru import logger as LOG

_ENV_VAR = "CCF_TEST_FILTER"

# Track which test functions were executed while filtering was active.
# Access is guarded by a lock since tests may run on multiple threads.
_lock = threading.Lock()
_matched_tests = []


def get_filter():
    """Return the raw filter string, or None if unset."""
    return os.getenv(_ENV_VAR)


def get_runner_filter():
    """Return the first segment of the filter (runner/thread level), or None."""
    f = get_filter()
    if f is None:
        return None
    return f.split("/")[0]


def get_test_filter():
    """Return the second segment of the filter (test-function level), or None."""
    f = get_filter()
    if f is None:
        return None
    parts = f.split("/", 1)
    if len(parts) < 2:
        return None
    return parts[1]


def should_skip_test(func_name):
    """
    Return True if the current test function should be skipped based on the
    test-level (second segment) filter.  Returns False (don't skip) when no
    filter is set or no second segment is present.
    """
    substring = get_test_filter()
    if substring is None:
        return False
    return substring.lower() not in func_name.lower()


def record_match(func_name):
    """Record that a test function was executed."""
    with _lock:
        _matched_tests.append(func_name)


def check_any_matched():
    """
    If a test-level filter was active (second segment of CCF_TEST_FILTER),
    assert that at least one test ran.  Call this at the end of a test run.
    Raises RuntimeError on mismatch (likely a typo in the filter).

    A runner-only filter (e.g. CCF_TEST_FILTER=schema) does not require
    decorated sub-tests to have matched, since the runner thread itself
    is the unit being selected.

    When tests did run, logs the list of executed tests.
    """
    with _lock:
        matched = list(_matched_tests)

    if matched:
        LOG.info(f"Executed {len(matched)} test(s):")
        for name in matched:
            LOG.info(f"  - {name}")

    if get_test_filter() is None:
        return

    f = get_filter()
    if not matched:
        raise RuntimeError(
            f'{_ENV_VAR}="{f}" was set but no tests matched. '
            f"Check for typos in the filter value."
        )


def reset():
    """Reset match tracking (mainly useful for tests of the filter itself)."""
    with _lock:
        _matched_tests.clear()
