# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Tests for infra.cpu_isolation.

Run directly (see the cpu_isolation_test entry in CMakeLists.txt). The
interesting case is the last one, which actually launches a child process and
reads back the mask the kernel gave it: the arithmetic being right is not much
use if the mask never reaches the process.
"""

import json
import os
import subprocess
import sys
import tempfile

import infra.cpu_isolation as ci


def test_format_cpu_list():
    assert ci._format_cpu_list([]) == ""
    assert ci._format_cpu_list([3]) == "3"
    assert ci._format_cpu_list([0, 1, 2]) == "0-2"
    assert ci._format_cpu_list({5, 1, 0, 2}) == "0-2,5"
    assert ci._format_cpu_list([0, 2, 4]) == "0,2,4"


def test_parse_cpu_list():
    assert ci._parse_cpu_list("") == []
    assert ci._parse_cpu_list("3") == [3]
    assert ci._parse_cpu_list("0-2") == [0, 1, 2]
    assert ci._parse_cpu_list("0-2,5") == [0, 1, 2, 5]
    assert ci._parse_cpu_list(" 0-1,4 \n") == [0, 1, 4]


def test_sibling_groups():
    """Whole physical cores are grouped together, and CPUs the process may not
    use are dropped from the group rather than silently handed out."""
    with tempfile.TemporaryDirectory() as tmp:
        # Four CPUs, SMT siblings paired as (0,1) and (2,3).
        for cpu, siblings in ((0, "0-1"), (1, "0-1"), (2, "2-3"), (3, "2-3")):
            topology = os.path.join(tmp, f"cpu{cpu}", "topology")
            os.makedirs(topology)
            with open(os.path.join(topology, "thread_siblings_list"), "w") as f:
                f.write(siblings + "\n")

        original = ci.SIBLINGS_PATH
        ci.SIBLINGS_PATH = os.path.join(
            tmp, "cpu{}", "topology", "thread_siblings_list"
        )
        try:
            assert ci._sibling_groups([0, 1, 2, 3]) == [[0, 1], [2, 3]]
            # CPU 1 is not available, so the first core is only usable as CPU 0.
            assert ci._sibling_groups([0, 2, 3]) == [[0], [2, 3]]
        finally:
            ci.SIBLINGS_PATH = original


def test_sibling_groups_without_topology():
    """Machines which do not expose topology still get a usable split."""
    original = ci.SIBLINGS_PATH
    ci.SIBLINGS_PATH = os.path.join(
        tempfile.gettempdir(), "definitely-not-a-topology-{}"
    )
    try:
        assert ci._sibling_groups([0, 1, 2]) == [[0], [1], [2]]
    finally:
        ci.SIBLINGS_PATH = original


def test_plan_is_a_disjoint_partition():
    plan = ci.make_plan(2)
    if plan is None:
        print("Skipping: this machine is too small to partition")
        return
    available = frozenset(os.sched_getaffinity(0))
    assert plan.node_cpus & plan.client_cpus == frozenset(), "sets must be disjoint"
    assert plan.node_cpus | plan.client_cpus == available, "every CPU must be used"
    assert plan.node_cpus, "the node must get at least one CPU"
    assert len(plan.client_cpus) >= ci.MIN_CLIENT_CPUS


def test_plan_declines_when_too_few_cpus():
    """Degradation is graceful: an impossible request returns None rather than
    raising or handing out an unusable split."""
    assert ci.make_plan(len(os.sched_getaffinity(0))) is None


def test_enable_off_is_inert():
    try:
        assert ci.enable(ci.MODE_OFF) is None
        assert ci.current() is None
        assert ci.describe() == "off"
        assert ci.command_prefix(ci.NODE) == []
        assert ci.command_prefix(ci.CLIENT) == []
    finally:
        ci.disable()


def test_unknown_role_is_rejected():
    try:
        ci.command_prefix("nonsense")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an unknown role")

    # No role at all is fine, and means no isolation.
    assert ci.command_prefix(None) == []


def test_invalid_mode_is_rejected():
    try:
        ci.enable("sideways")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for an unknown mode")
    finally:
        ci.disable()


def test_environment_overrides_arguments():
    os.environ[ci.ENV_MODE] = ci.MODE_OFF
    try:
        assert ci.enable(ci.MODE_AUTO) is None
    finally:
        del os.environ[ci.ENV_MODE]
        ci.disable()

    plan = ci.make_plan(2)
    if plan is None:
        print("Skipping node CPU count override: machine too small")
        return

    os.environ[ci.ENV_MODE] = ci.MODE_AUTO
    os.environ[ci.ENV_NODE_CPUS] = "2"
    try:
        enabled = ci.enable(ci.MODE_OFF, 8)
        assert enabled is not None, "environment should have forced isolation on"
        assert enabled.node_cpus == plan.node_cpus
    finally:
        del os.environ[ci.ENV_MODE]
        del os.environ[ci.ENV_NODE_CPUS]
        ci.disable()


def test_child_process_is_actually_pinned():
    """The mask must reach the launched process, not just the plan.

    Also covers a grandchild, since locust pins its master and relies on the
    forked workers inheriting the mask.
    """
    plan = ci.enable(ci.MODE_AUTO, 2)
    if plan is None:
        print("Skipping: isolation unavailable on this machine")
        return

    report_affinity = (
        "import os, subprocess, sys;"
        "mine = sorted(os.sched_getaffinity(0));"
        "child = subprocess.run("
        "[sys.executable, '-c', "
        '"import os; print(sorted(os.sched_getaffinity(0)))"],'
        " capture_output=True, text=True).stdout.strip();"
        "print(mine); print(child)"
    )

    try:
        for role in (ci.NODE, ci.CLIENT):
            result = subprocess.run(
                ci.command_prefix(role) + [sys.executable, "-c", report_affinity],
                check=True,
                capture_output=True,
                text=True,
            )
            child, grandchild = result.stdout.strip().splitlines()
            expected = sorted(plan.cpus_for(role))
            assert child == str(
                expected
            ), f"{role} process ran on {child}, expected {expected}"
            assert grandchild == str(
                expected
            ), f"{role} grandchild ran on {grandchild}, expected {expected}"
    finally:
        ci.disable()


def test_isolation_metadata_survives_a_later_test():
    """Every perf test in a CI run appends to the same bencher.json, and each
    one constructs its own Bencher. A record of which mode produced a result is
    worthless if the next test erases it."""
    import infra.bencher

    original_dir = os.getcwd()
    original_sha = os.environ.get("GITHUB_SHA")
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        # Metadata is only written when there is some to write.
        os.environ["GITHUB_SHA"] = "0123456789abcdef"
        try:
            isolated = infra.bencher.Bencher()
            isolated.set_metadata("cpu_isolation_pi_basic_blocking_locust", "node=8-11")
            isolated.set("Basic Blocking Locust", infra.bencher.Throughput(1261.2))

            # A different perf test runs afterwards in the same job.
            later = infra.bencher.Bencher()
            later.set("Basic Blocking", infra.bencher.Throughput(468.5))

            with open(infra.bencher.BENCHER_FILE) as f:
                data = json.load(f)
        finally:
            os.chdir(original_dir)
            if original_sha is None:
                del os.environ["GITHUB_SHA"]
            else:
                os.environ["GITHUB_SHA"] = original_sha

    metadata = data[infra.bencher.METADATA_KEY]
    assert metadata.get("cpu_isolation_pi_basic_blocking_locust") == "node=8-11", (
        f"isolation metadata was lost when a later test ran: {metadata}"
    )
    assert metadata.get("commit") == "0123456789abcdef", "run metadata was lost"
    assert "Basic Blocking" in data and "Basic Blocking Locust" in data


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"--- {name}")
            fn()
    print("All cpu_isolation tests passed")
