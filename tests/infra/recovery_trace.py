# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import heapq
import itertools
import json
import logging
import os
import pathlib
import subprocess
import time

TRACE_MARKER = "RDP_TRACE "
TRACE_VALIDATOR_ENV = "CCF_LEAN_TRACE_VALIDATOR"
TRACE_VERSION = "ccf.recovery_decision_protocol.trace/1"
LOG = logging.getLogger(__name__)


def _event_from_log_line(line, path, line_number):
    message = line
    try:
        outer = json.loads(line)
        if isinstance(outer, dict) and isinstance(outer.get("msg"), str):
            message = outer["msg"]
    except json.JSONDecodeError:
        pass

    marker = message.find(TRACE_MARKER)
    if marker < 0:
        return None

    payload = message[marker + len(TRACE_MARKER) :].lstrip()
    try:
        event, _ = json.JSONDecoder().raw_decode(payload)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"{path}:{line_number}: invalid recovery trace JSON: {error}"
        ) from error
    if not isinstance(event, dict):
        raise TypeError(f"{path}:{line_number}: recovery trace is not an object")
    return event


def extract_events(nodes):
    events = []
    for node in nodes:
        out_path, _ = node.get_logs()
        if out_path is None or not os.path.isfile(out_path):
            continue
        with open(out_path, encoding="utf-8", errors="replace") as log:
            for line_number, line in enumerate(log, 1):
                event = _event_from_log_line(line, out_path, line_number)
                if event is not None:
                    events.append(event)
    if not events:
        raise ValueError("no recovery-decision-protocol trace events found")
    return events


def linearize(events):
    successors = [set() for _ in events]
    indegree = [0 for _ in events]

    def add_edge(source, destination):
        if destination not in successors[source]:
            successors[source].add(destination)
            indegree[destination] += 1

    by_node = {}
    message_ids = {}
    identity = None
    for index, event in enumerate(events):
        try:
            version = event["version"]
            instance = event["instance"]
            expected_locations = event["expected_locations"]
            node = event["node"]
            sequence = event["sequence"]
            kind = event["kind"]
        except KeyError as error:
            raise ValueError(
                f"trace event {index} is missing {error.args[0]}"
            ) from error
        if version != TRACE_VERSION:
            raise ValueError(f"trace event {index} has unsupported version {version}")
        if not isinstance(instance, str) or not instance:
            raise ValueError(f"trace event {index} has an invalid instance")
        if (
            not isinstance(expected_locations, list)
            or not expected_locations
            or any(
                not isinstance(location, str) or not location
                for location in expected_locations
            )
            or len(set(expected_locations)) != len(expected_locations)
        ):
            raise ValueError(f"trace event {index} has invalid expected_locations")
        event_identity = (instance, tuple(expected_locations))
        if identity is None:
            identity = event_identity
        elif event_identity != identity:
            raise ValueError(f"trace event {index} changes recovery identity")
        if (
            not isinstance(node, str)
            or not node
            or node not in expected_locations
            or type(sequence) is not int
            or sequence < 0
            or not isinstance(kind, str)
        ):
            raise TypeError(f"trace event {index} has an invalid node or sequence")
        by_node.setdefault(node, []).append((sequence, index))

        message_id = event.get("message_id")
        if message_id is not None:
            if not isinstance(message_id, str) or not message_id:
                raise ValueError(f"trace event {index} has an invalid message_id")
            if message_id in message_ids:
                raise ValueError(f"duplicate trace message_id {message_id}")
            message_ids[message_id] = (index, kind)

    for node, node_events in by_node.items():
        node_events.sort()
        sequences = [sequence for sequence, _ in node_events]
        if sequences != list(range(len(node_events))):
            raise ValueError(
                f"node {node} trace sequence is not contiguous from zero: {sequences}"
            )
        for (_, previous), (_, current) in itertools.pairwise(node_events):
            add_edge(previous, current)

    for index, event in enumerate(events):
        caused_by = event.get("caused_by")
        if caused_by is None:
            continue
        if not isinstance(caused_by, str) or not caused_by:
            raise ValueError(f"trace event {index} has an invalid caused_by")
        if caused_by not in message_ids:
            raise ValueError(f"caused_by {caused_by} has no matching send event")
        source, kind = message_ids[caused_by]
        if kind != "send":
            raise ValueError(f"caused_by {caused_by} does not identify a send event")
        add_edge(source, index)

    ready = []
    for index, degree in enumerate(indegree):
        if degree == 0:
            event = events[index]
            heapq.heappush(
                ready, (event["node"], event["sequence"], event["kind"], index)
            )

    ordered = []
    while ready:
        _, _, _, index = heapq.heappop(ready)
        ordered.append(events[index])
        for successor in successors[index]:
            indegree[successor] -= 1
            if indegree[successor] == 0:
                event = events[successor]
                heapq.heappush(
                    ready,
                    (event["node"], event["sequence"], event["kind"], successor),
                )

    if len(ordered) != len(events):
        raise ValueError("recovery trace contains a causal cycle")
    return ordered


def _validator_path():
    configured = os.getenv(TRACE_VALIDATOR_ENV)
    if configured:
        return pathlib.Path(configured)
    repository = pathlib.Path(__file__).resolve().parents[2]
    return (
        repository
        / "lean"
        / "disaster-recovery-trace"
        / ".lake"
        / "build"
        / "bin"
        / "trace-validator"
    )


def _participating_node_count(nodes):
    return sum(node.remote is not None for node in nodes)


def wait_for_terminal_events(network, expected_open_kind, timeout):
    expected_node_count = _participating_node_count(network.nodes)
    end_time = time.time() + timeout
    events = []
    while time.time() < end_time:
        try:
            events = extract_events(network.nodes)
        except ValueError:
            time.sleep(0.1)
            continue

        started = {event["node"] for event in events if event["kind"] == "start"}
        completed = {event["node"] for event in events if event["kind"] == "complete"}
        terminal = completed | {
            event["node"] for event in events if event["kind"] == "join_restart"
        }
        opened = [event for event in events if event["kind"] == "open"]
        if (
            len(started) == expected_node_count
            and started <= terminal
            and completed
            and opened
            and all(event.get("open_kind") == expected_open_kind for event in opened)
        ):
            return events
        time.sleep(0.1)

    raise TimeoutError(
        "timed out waiting for terminal recovery trace events: "
        f"expected_node_count={expected_node_count}, "
        f"started={sorted(started) if events else []}, "
        f"expected_open_kind={expected_open_kind}, events={events}"
    )


def validate_recovery_trace(network, label, expected_open_kind=None, timeout=20):
    if expected_open_kind is None:
        events = extract_events(network.nodes)
    else:
        events = wait_for_terminal_events(network, expected_open_kind, timeout)
    events = linearize(events)
    trace_path = pathlib.Path(network.common_dir) / f"{label}.recovery.ndjson"
    with open(trace_path, "w", encoding="utf-8") as trace:
        for event in events:
            trace.write(json.dumps(event, separators=(",", ":"), sort_keys=True))
            trace.write("\n")

    validator = _validator_path()
    if not validator.is_file():
        raise FileNotFoundError(
            f"Lean trace validator not found at {validator}; set {TRACE_VALIDATOR_ENV}"
        )
    result = subprocess.run(
        [validator, trace_path],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Lean recovery trace validation failed for {trace_path}:\n"
            f"{result.stdout}{result.stderr}"
        )
    LOG.info(result.stdout.strip())
    return trace_path


def validate_recovery_trace_if_enabled(network, label, expected_open_kind, timeout=20):
    if not os.getenv(TRACE_VALIDATOR_ENV):
        return None
    return validate_recovery_trace(
        network,
        label,
        expected_open_kind=expected_open_kind,
        timeout=timeout,
    )
