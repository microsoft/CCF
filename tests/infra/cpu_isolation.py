# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
CPU isolation for performance tests.

Perf tests run the CCF node and their load generator on the same machine, so
both compete for the same cores. What gets measured is then partly a property
of the load generator: a client which spends CPU while waiting takes it away
from the node, and the reported throughput drops for reasons that have nothing
to do with the node.

Pinning the node and the clients to disjoint sets of CPUs removes that
coupling. It is always applied, on every machine, so that runs are comparable
wherever they happen. It is best-effort only in that a machine too small to
split usefully is reported loudly and runs unisolated rather than failing.

The mechanism is a `taskset` prefix on the launched command. taskset calls
sched_setaffinity(2) before exec, so the mask is inherited by the process
image, by every thread it creates, and by every process it goes on to spawn.
That last part matters: locust forks its workers after startup, so pinning the
master is only sufficient because the mask is inherited.

Two alternatives were considered and rejected:

- Applying the mask from a subprocess preexec_fn. That runs between fork and
  exec, where only async-signal-safe work is legal, while the test infra is
  threaded. A lock held by another thread at the moment of fork can deadlock
  the child, which would surface as a rare CI hang rather than an error.
- Narrowing the affinity of the test process itself and letting children
  inherit it. Fork-safe, but it silently captures any unrelated process
  spawned by another thread while the mask is narrowed.

Neither taskset nor sched_setaffinity needs any privilege to retarget a
process of your own, so this works unprivileged and inside a container with no
cgroup access. A cgroup v2 cpuset would be stronger, but needs a writable
/sys/fs/cgroup and the cpuset controller delegated down the hierarchy, neither
of which holds in an unprivileged CI container.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass

from loguru import logger as LOG

# The perf configuration runs two worker threads plus a host thread, so reserve
# one CPU for each. Deliberately modest: the point is to give the node a floor
# it cannot be pushed below, not to hand it the machine.
DEFAULT_NODE_CPUS = 3

# Below this many CPUs left over there is no point isolating, because the load
# generator becomes the bottleneck instead.
MIN_CLIENT_CPUS = 2

NODE = "node"
CLIENT = "client"
ROLES = (NODE, CLIENT)

TASKSET = "taskset"

SIBLINGS_PATH = "/sys/devices/system/cpu/cpu{}/topology/thread_siblings_list"


def _format_cpu_list(cpus) -> str:
    """Render a set of CPU ids the way Linux does, e.g. {0,1,2,5} -> '0-2,5'."""
    ranges: list[list[int]] = []
    for cpu in sorted(cpus):
        if ranges and cpu == ranges[-1][1] + 1:
            ranges[-1][1] = cpu
        else:
            ranges.append([cpu, cpu])
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ranges)


def _parse_cpu_list(value: str) -> list[int]:
    """Parse a Linux CPU list, e.g. '0-2,5' -> [0, 1, 2, 5]."""
    cpus = []
    for part in value.strip().split(","):
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(part))
    return cpus


def _sibling_groups(available: list[int]) -> list[list[int]] | None:
    """Group the available CPUs into physical cores.

    SMT siblings share execution resources, so handing the node one thread of a
    core while a client runs on the other would leave the two contending after
    all. Group by sibling set and allocate whole cores. If the topology is not
    exposed reliably, isolation cannot preserve that guarantee.
    """
    available_set = set(available)
    groups = []
    seen = set()
    for cpu in available:
        if cpu in seen:
            continue
        try:
            with open(SIBLINGS_PATH.format(cpu), "r") as f:
                siblings = _parse_cpu_list(f.read())
        except (OSError, ValueError) as exc:
            LOG.warning(
                f"CPU isolation unavailable: cannot read SMT siblings "
                f"for CPU {cpu} ({exc})"
            )
            return None
        # A sibling the process is not allowed to run on is of no use.
        group = sorted(set(siblings) & available_set)
        if cpu not in group or seen.intersection(group):
            LOG.warning(
                f"CPU isolation unavailable: inconsistent SMT topology "
                f"for CPU {cpu} ({_format_cpu_list(group)})"
            )
            return None
        seen.update(group)
        groups.append(group)
    return groups


@dataclass(frozen=True)
class IsolationPlan:
    """A disjoint split of the available CPUs between node and clients."""

    node_cpus: frozenset[int]
    client_cpus: frozenset[int]
    unassigned_cpus: frozenset[int]

    def cpus_for(self, role: str) -> frozenset[int]:
        if role == NODE:
            return self.node_cpus
        if role == CLIENT:
            return self.client_cpus
        raise ValueError(f"Unknown CPU isolation role: {role}")

    def describe(self) -> str:
        """One-line summary of the layout, for logging before anything starts."""
        total = len(self.node_cpus) + len(self.client_cpus) + len(self.unassigned_cpus)
        description = (
            f"node -> CPUs {_format_cpu_list(self.node_cpus)} "
            f"({len(self.node_cpus)} of {total}), "
            f"clients -> CPUs {_format_cpu_list(self.client_cpus)} "
            f"({len(self.client_cpus)} of {total})"
        )
        if self.unassigned_cpus:
            description += (
                f", unassigned -> CPUs {_format_cpu_list(self.unassigned_cpus)} "
                f"({len(self.unassigned_cpus)} of {total})"
            )
        return description


_plan: IsolationPlan | None = None


def _taskset_works(cpus) -> bool:
    """Check that taskset is present and allowed to apply a mask.

    More direct than inspecting capabilities: if `taskset -c ... true` succeeds
    then so will the real launches.
    """
    if shutil.which(TASKSET) is None:
        LOG.warning(
            f"CPU isolation unavailable: {TASKSET} is not on PATH "
            f"(it is provided by util-linux)"
        )
        return False
    try:
        subprocess.run(
            [TASKSET, "-c", _format_cpu_list(cpus), "true"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        LOG.warning(f"CPU isolation unavailable: {TASKSET} failed ({e})")
        return False
    return True


def make_plan(node_cpu_count: int = DEFAULT_NODE_CPUS) -> IsolationPlan | None:
    """Build a plan with an exact node CPU count, or return None if this
    machine cannot usefully be split.

    The clients never receive an SMT sibling of a node CPU. When the requested
    count does not fill the final sibling group, the remainder is unassigned.
    """
    if not hasattr(os, "sched_getaffinity"):
        LOG.warning("CPU isolation unavailable: no sched_getaffinity on this platform")
        return None

    # Start from the CPUs this process may actually use rather than from the
    # CPU count, so that an outer restriction (a container's --cpuset-cpus, or
    # a taskset around the test runner) is respected instead of overridden.
    available = sorted(os.sched_getaffinity(0))
    if len(available) < node_cpu_count + MIN_CLIENT_CPUS:
        LOG.warning(
            f"CPU isolation unavailable: {len(available)} CPUs available "
            f"({_format_cpu_list(available)}), need at least "
            f"{node_cpu_count + MIN_CLIENT_CPUS} to reserve {node_cpu_count} "
            f"for the node"
        )
        return None

    # Take the node's cores from the top, leaving CPU 0 - which the kernel
    # tends to favour for interrupt handling - out of the node's set.
    sibling_groups = _sibling_groups(available)
    if sibling_groups is None:
        return None

    node_cpus: set[int] = set()
    node_sibling_cpus: set[int] = set()
    for group in reversed(sibling_groups):
        if len(node_cpus) >= node_cpu_count:
            break
        remaining = node_cpu_count - len(node_cpus)
        node_cpus.update(group[-remaining:])
        node_sibling_cpus.update(group)

    client_cpus = set(available) - node_sibling_cpus
    unassigned_cpus = node_sibling_cpus - node_cpus
    if len(client_cpus) < MIN_CLIENT_CPUS:
        LOG.warning(
            "CPU isolation unavailable: only "
            f"{len(client_cpus)} CPUs would be left for clients"
        )
        return None

    if not _taskset_works(node_cpus):
        return None

    return IsolationPlan(
        frozenset(node_cpus),
        frozenset(client_cpus),
        frozenset(unassigned_cpus),
    )


def enable(node_cpu_count: int = DEFAULT_NODE_CPUS):
    """Split this machine's CPUs between the node and the clients.

    Call once, before any node or client process is launched. Returns the plan
    in force, or None if this machine cannot usefully be split and the run must
    go ahead unisolated.
    """
    global _plan

    if node_cpu_count < 1:
        raise ValueError(f"Invalid node CPU count {node_cpu_count}, must be at least 1")

    _plan = make_plan(node_cpu_count)
    if _plan is None:
        # Not an error: the test is still valid, it is just noisier and not
        # comparable with isolated runs. Say so unmissably.
        LOG.warning(
            "CPU isolation NOT applied: node and clients will share all CPUs, "
            "so these results are not comparable with isolated runs."
        )
    else:
        LOG.info(f"CPU isolation: {_plan.describe()}")
    return _plan


def command_prefix(role: str | None) -> list[str]:
    """Prefix which pins a command, and everything it spawns, to this role's
    CPUs.

    Empty when isolation is off, or when the caller has no role to declare, so
    callers can prepend it unconditionally.
    """
    if role is None:
        return []
    if role not in ROLES:
        raise ValueError(f"Unknown CPU isolation role: {role}")
    if _plan is None:
        return []
    return [TASKSET, "-c", _format_cpu_list(_plan.cpus_for(role))]
