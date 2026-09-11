#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import filecmp
import subprocess
import sys
import tempfile
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

FORMAT = "ccf-legacy-dr-graph-v1"
PROPERTY_NAMES = (
    "Unanimous votes => no chance of a fork",
    "Open",
    "Majority votes => no fork",
    "No open with timeout, no fork",
    "Deadlock",
    "Persist committed txs",
    "Open is possible",
    "Unsafe open with timeout",
    "Majority vote still opens without timeout",
)
EXPECTED_COUNTS = {
    1: (1, 0),
    2: (54, 95),
    3: (105558, 552282),
}


@dataclass(frozen=True)
class Summary:
    initial_key: str
    states: int
    edges: int


@dataclass
class Graph:
    initial: str
    valuations: dict[str, str]
    edges: set[tuple[str, str, str]]


def run(command: list[str], cwd: Path, output: Path | None = None) -> None:
    print(f"+ (cd {cwd} && {' '.join(command)})", flush=True)
    if output is None:
        result = subprocess.run(
            command, cwd=cwd, text=True, capture_output=True, check=False
        )
    else:
        with output.open("w", encoding="ascii", newline="") as stream:
            result = subprocess.run(
                command,
                cwd=cwd,
                text=True,
                stdout=stream,
                stderr=subprocess.PIPE,
                check=False,
            )
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        raise RuntimeError(f"command exited with status {result.returncode}")


def validate(path: Path, expected_nodes: int) -> Summary:
    ids_to_keys: list[str] = []
    initial_id: int | None = None
    edge_count = 0
    previous_edge: tuple[int, str, int] | None = None
    section = "header"

    with path.open(encoding="ascii") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            fields = raw_line.rstrip("\n").split("\t")
            if fields == ["format", FORMAT] and line_number == 1:
                continue
            if fields == ["nodes", str(expected_nodes)] and line_number == 2:
                continue
            if len(fields) == 2 and fields[0] == "init" and line_number == 3:
                initial_id = int(fields[1])
                section = "states"
                continue
            if len(fields) == 4 and fields[0] == "state" and section == "states":
                state_id = int(fields[1])
                if state_id != len(ids_to_keys):
                    raise ValueError(
                        f"{path}:{line_number}: expected dense state id "
                        f"{len(ids_to_keys)}, found {state_id}"
                    )
                if ids_to_keys and fields[2] <= ids_to_keys[-1]:
                    raise ValueError(
                        f"{path}:{line_number}: state keys are unsorted or duplicated"
                    )
                bits = fields[3]
                if len(bits) != len(PROPERTY_NAMES) or set(bits) - {"0", "1"}:
                    raise ValueError(
                        f"{path}:{line_number}: invalid property bitstring"
                    )
                ids_to_keys.append(fields[2])
                continue
            if len(fields) == 4 and fields[0] == "edge":
                section = "edges"
                edge = (int(fields[1]), fields[2], int(fields[3]))
                if edge[0] >= len(ids_to_keys) or edge[2] >= len(ids_to_keys):
                    raise ValueError(
                        f"{path}:{line_number}: edge references unknown state"
                    )
                if previous_edge is not None and edge <= previous_edge:
                    raise ValueError(
                        f"{path}:{line_number}: edges are unsorted or duplicated"
                    )
                previous_edge = edge
                edge_count += 1
                continue
            raise ValueError(
                f"{path}:{line_number}: invalid record: {raw_line.rstrip()}"
            )

    if initial_id is None or initial_id >= len(ids_to_keys):
        raise ValueError(f"{path}: invalid or missing initial state")
    return Summary(ids_to_keys[initial_id], len(ids_to_keys), edge_count)


def load(path: Path) -> Graph:
    ids_to_keys: list[str] = []
    valuations: dict[str, str] = {}
    raw_edges: list[tuple[int, str, int]] = []
    initial_id = -1
    with path.open(encoding="ascii") as stream:
        for raw_line in stream:
            fields = raw_line.rstrip("\n").split("\t")
            if fields[0] == "init":
                initial_id = int(fields[1])
            elif fields[0] == "state":
                state_id = int(fields[1])
                key = fields[2]
                if state_id != len(ids_to_keys):
                    raise ValueError(f"{path}: non-dense state IDs")
                ids_to_keys.append(key)
                valuations[key] = fields[3]
            elif fields[0] == "edge":
                raw_edges.append((int(fields[1]), fields[2], int(fields[3])))
    edges = {
        (ids_to_keys[src], action, ids_to_keys[dst]) for src, action, dst in raw_edges
    }
    return Graph(ids_to_keys[initial_id], valuations, edges)


def shortest_paths(graph: Graph) -> tuple[dict[str, int], dict[str, tuple[str, str]]]:
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for src, action, dst in graph.edges:
        adjacency[src].append((action, dst))
    for outgoing in adjacency.values():
        outgoing.sort()

    distance = {graph.initial: 0}
    parent: dict[str, tuple[str, str]] = {}
    pending = deque([graph.initial])
    while pending:
        src = pending.popleft()
        for action, dst in adjacency[src]:
            if dst not in distance:
                distance[dst] = distance[src] + 1
                parent[dst] = (src, action)
                pending.append(dst)
    return distance, parent


def describe_path(
    graph: Graph, target: str, cached: tuple[dict[str, int], dict[str, tuple[str, str]]]
) -> str:
    distance, parent = cached
    if target not in distance:
        return f"unreachable target key {target}"
    actions: list[str] = []
    cursor = target
    while cursor != graph.initial:
        cursor, action = parent[cursor]
        actions.append(action)
    actions.reverse()
    rendered = "\n".join(
        f"  {index}. {action}" for index, action in enumerate(actions, 1)
    )
    return f"target: {target}\n{rendered or '  <initial state>'}"


def mismatch(rust: Graph, lean: Graph) -> str:
    if rust.initial != lean.initial:
        return f"initial state mismatch\nRust: {rust.initial}\nLean: {lean.initial}"

    rust_paths = lean_paths = None
    rust_states = set(rust.valuations)
    lean_states = set(lean.valuations)
    if rust_states != lean_states:
        rust_only = rust_states - lean_states
        lean_only = lean_states - rust_states
        candidates: list[tuple[int, str, str, Graph]] = []
        if rust_only:
            rust_paths = shortest_paths(rust)
            state = min(
                rust_only, key=lambda key: (rust_paths[0].get(key, sys.maxsize), key)
            )
            candidates.append(
                (rust_paths[0].get(state, sys.maxsize), "Rust-only", state, rust)
            )
        if lean_only:
            lean_paths = shortest_paths(lean)
            state = min(
                lean_only, key=lambda key: (lean_paths[0].get(key, sys.maxsize), key)
            )
            candidates.append(
                (lean_paths[0].get(state, sys.maxsize), "Lean-only", state, lean)
            )
        _, side, state, graph = min(candidates)
        paths = rust_paths if graph is rust else lean_paths
        return (
            f"reachable state mismatch ({len(rust_only)} Rust-only, "
            f"{len(lean_only)} Lean-only); shortest is {side}\n"
            f"{describe_path(graph, state, paths)}"
        )

    rust_only_edges = rust.edges - lean.edges
    lean_only_edges = lean.edges - rust.edges
    if rust_only_edges or lean_only_edges:
        candidates = []
        if rust_only_edges:
            rust_paths = shortest_paths(rust)
            edge = min(
                rust_only_edges,
                key=lambda value: (rust_paths[0].get(value[0], sys.maxsize), value),
            )
            candidates.append(
                (
                    rust_paths[0].get(edge[0], sys.maxsize),
                    "Rust-only",
                    edge,
                    rust,
                )
            )
        if lean_only_edges:
            lean_paths = shortest_paths(lean)
            edge = min(
                lean_only_edges,
                key=lambda value: (lean_paths[0].get(value[0], sys.maxsize), value),
            )
            candidates.append(
                (
                    lean_paths[0].get(edge[0], sys.maxsize),
                    "Lean-only",
                    edge,
                    lean,
                )
            )
        _, side, (src, action, dst), graph = min(candidates)
        paths = rust_paths if graph is rust else lean_paths
        return (
            f"labeled edge mismatch ({len(rust_only_edges)} Rust-only, "
            f"{len(lean_only_edges)} Lean-only); shortest source is {side}\n"
            f"{describe_path(graph, src, paths)}\n"
            f"missing edge action: {action}\ndestination: {dst}"
        )

    differing = {
        key for key in rust_states if rust.valuations[key] != lean.valuations[key]
    }
    if differing:
        rust_paths = shortest_paths(rust)
        state = min(
            differing, key=lambda key: (rust_paths[0].get(key, sys.maxsize), key)
        )
        rust_bits = rust.valuations[state]
        lean_bits = lean.valuations[state]
        details = [
            f"  {index + 1}. {name}: Rust={rust_bits[index]} Lean={lean_bits[index]}"
            for index, name in enumerate(PROPERTY_NAMES)
            if rust_bits[index] != lean_bits[index]
        ]
        return (
            f"property valuation mismatch in {len(differing)} states\n"
            f"{describe_path(rust, state, rust_paths)}\n" + "\n".join(details)
        )

    return "canonical files differ despite identical graph content"


def compare(nodes: int, lean_dir: Path, rust_dir: Path, temporary: Path) -> Summary:
    rust_path = temporary / f"rust-{nodes}.tsv"
    lean_path = temporary / f"lean-{nodes}.tsv"
    run(
        [
            "cargo",
            "run",
            "--quiet",
            "--",
            "export",
            "--nodes",
            str(nodes),
            "-o",
            str(rust_path),
        ],
        rust_dir,
    )
    run(
        ["lake", "exe", "migration-exporter", "--nodes", str(nodes)],
        lean_dir,
        lean_path,
    )
    rust_summary = validate(rust_path, nodes)
    lean_summary = validate(lean_path, nodes)
    if rust_summary != lean_summary or not filecmp.cmp(
        rust_path, lean_path, shallow=False
    ):
        raise AssertionError(mismatch(load(rust_path), load(lean_path)))
    expected = EXPECTED_COUNTS.get(nodes)
    if expected is not None and (rust_summary.states, rust_summary.edges) != expected:
        raise AssertionError(
            f"n={nodes}: expected {expected[0]} states/{expected[1]} edges, "
            f"found {rust_summary.states}/{rust_summary.edges}"
        )
    return rust_summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exhaustively compare Rust/Stateright and Lean legacy DR graphs"
    )
    parser.add_argument("--nodes", type=int, nargs="+", default=[1, 2, 3])
    args = parser.parse_args()
    if any(nodes < 1 for nodes in args.nodes):
        parser.error("node counts must be positive")

    lean_dir = Path(__file__).resolve().parent
    rust_dir = lean_dir.parents[1] / "tla" / "disaster-recovery"
    try:
        scratch = lean_dir / ".lake"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="ccf-legacy-dr-", dir=scratch
        ) as directory:
            for nodes in args.nodes:
                summary = compare(nodes, lean_dir, rust_dir, Path(directory))
                print(
                    f"n={nodes}: equivalent initial state, {summary.states} states, "
                    f"{summary.edges} labeled edges compared in both directions, "
                    f"{len(PROPERTY_NAMES)} valuations/state"
                )
    except (AssertionError, OSError, RuntimeError, ValueError) as error:
        print(f"equivalence failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
