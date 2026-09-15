#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Deterministic, fail-closed reduction of recorded CCF Raft events."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trace_io import Record, TraceError, read_trace

SCHEMA = "ccfraft-replay/v2"
MESSAGE_FIELDS = {
    "add_configuration": {"args", "configurations"},
    "become_candidate": {"configurations"},
    "become_follower": {"configurations"},
    "become_leader": {"configurations"},
    "become_pre_vote_candidate": {"configurations"},
    "commit": {"args", "configurations"},
    "drop_pending_to": {"from_node_id", "to_node_id", "packet"},
    "execute_append_entries_sync": {"from_node_id"},
    "recv_append_entries": {"from_node_id", "packet"},
    "recv_append_entries_response": {"from_node_id", "packet", "sent_idx", "match_idx"},
    "recv_propose_request_vote": {"from_node_id", "packet"},
    "recv_request_vote": {"from_node_id", "packet"},
    "recv_request_vote_response": {"from_node_id", "packet"},
    "replicate": {"view", "seqno", "globally_committable"},
    "send_append_entries": {"to_node_id", "packet", "sent_idx", "match_idx"},
    "send_append_entries_response": {"to_node_id", "packet"},
    "send_request_vote": {"to_node_id", "packet"},
    "step_down_and_nominate_successor": {"configurations"},
}
COMMANDS = {
    "pre_vote_enabled",
    "start_node",
    "trust_node",
    "trust_nodes",
    "cleanup_nodes",
    "swap_node",
    "swap_nodes",
    "nodes",
    "connect",
    "disconnect",
    "disconnect_node",
    "periodic_one",
    "periodic_all",
    "state_one",
    "state_all",
    "summarise_log",
    "summarise_logs_all",
    "summarise_messages",
    "dispatch_one",
    "dispatch_all",
    "dispatch_all_once",
    "dispatch_single",
    "drop_pending",
    "drop_pending_to",
    "replicate",
    "emit_signature",
    "assert_state_sync",
    "assert_detail",
    "assert_commit_idx",
    "assert_commit_safety",
    "assert_!detail",
    "assert_config",
    "assert_absent_config",
    "assert_last_txid",
    "replicate_new_configuration",
    "create_new_node",
    "loop_until_sync",
    "nominate_successor",
    "reconnect",
    "reconnect_node",
    "shuffle_one",
    "shuffle_all",
}
ROLES = {
    "None": "none",
    "Follower": "follower",
    "PreVoteCandidate": "preVoteCandidate",
    "Candidate": "candidate",
    "Leader": "leader",
}
PHASES = {
    "Ordered": "retirementOrdered",
    "Signed": "retirementSigned",
    "Completed": "retirementCompleted",
    "RetiredCommitted": "retiredCommitted",
}
STATE_KEYS = {
    "node_id",
    "leadership_state",
    "membership_state",
    "retirement_phase",
    "current_view",
    "last_idx",
    "commit_idx",
    "pre_vote_enabled",
    "retirement_idx",
    "retirement_committable_idx",
    "retired_committed_idx",
    "committable_indices",
}
PACKETS = {
    "raft_append_entries": {
        "msg",
        "term",
        "idx",
        "prev_idx",
        "prev_term",
        "leader_commit_idx",
        "term_of_idx",
        "contains_new_view",
    },
    "raft_append_entries_response": {"msg", "term", "last_log_idx", "success"},
    "raft_request_vote": {
        "msg",
        "term",
        "last_committable_idx",
        "term_of_last_committable_idx",
    },
    "raft_request_pre_vote": {
        "msg",
        "term",
        "last_committable_idx",
        "term_of_last_committable_idx",
    },
    "raft_request_vote_response": {"msg", "term", "vote_granted"},
    "raft_request_pre_vote_response": {"msg", "term", "vote_granted"},
    "raft_propose_request_vote": {"msg", "term"},
}
INDEX_KEYS = {
    "idx",
    "prev_idx",
    "leader_commit_idx",
    "last_log_idx",
    "last_committable_idx",
}
TERM_KEYS = {"term", "prev_term", "term_of_idx", "term_of_last_committable_idx"}
CALLBACK_FIELDS = {
    "execute_append_entries_sync": {"currentTerm", "preVoteEnabled"},
    "add_configuration": {"preVoteEnabled"},
    "commit": {"preVoteEnabled"},
    "become_follower": {"role", "membershipState", "preVoteEnabled"},
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TraceError(message)


def natural(value: Any, location: str) -> int:
    require(type(value) is int and value >= 0, f"{location}: expected natural number")
    return value


def node(value: Any, location: str) -> str:
    require(isinstance(value, str) and bool(value), f"{location}: expected node string")
    return value


def index(value: Any, location: str) -> int:
    return natural(value, location)


def term(value: Any, location: str) -> int:
    raw = natural(value, location)
    require(
        raw != 1, f"{location}: term 1 is outside the verified bootstrap projection"
    )
    return max(0, raw - 1)


@dataclass(frozen=True)
class Event:
    record: Record
    command: Record
    message: dict[str, Any]

    @property
    def function(self) -> str:
        return self.message["function"]

    @property
    def state(self) -> dict[str, Any]:
        return self.message["state"]

    @property
    def node(self) -> str:
        return self.state["node_id"]

    @property
    def location(self) -> str:
        return self.record.location

    def origin(self, rule: str) -> dict[str, Any]:
        return {
            "file": self.record.file,
            "line": self.record.line,
            "rule": rule,
            "function": self.function,
            "command": self.command.value["cmd"],
            "commandLine": self.command.line,
            **{
                name: self.record.value[key]
                for name, key in (
                    ("implementationFile", "file"),
                    ("implementationLine", "number"),
                )
                if key in self.record.value
            },
        }


def associate(records: list[Record]) -> tuple[list[Event], dict[str, bool]]:
    """Associate commands without sorting or discarding event records."""
    require(bool(records), "empty trace")
    events = []
    command = None
    timestamp = -1
    modes: dict[str, bool] = {}
    default_mode = True
    for record in records:
        row = record.value
        require(
            row.get("tag") == "raft_trace", f"{record.location}: expected raft_trace"
        )
        if "cmd" in row:
            require(set(row) == {"tag", "cmd"}, f"{record.location}: malformed command")
            require(
                isinstance(row["cmd"], str) and bool(row["cmd"]),
                f"{record.location}: empty command",
            )
            parts = row["cmd"].split(",")
            prefix = parts[0]
            require(
                prefix in COMMANDS, f"{record.location}: unsupported command {prefix!r}"
            )
            created = []
            if prefix == "pre_vote_enabled":
                require(
                    len(parts) == 2 and parts[1] in {"true", "false"},
                    f"{record.location}: malformed pre-vote command",
                )
                default_mode = parts[1] == "true"
            elif prefix in {"start_node", "create_new_node", "nodes"}:
                created = parts[1:]
            elif prefix in {"trust_node", "trust_nodes"}:
                created = parts[2:]
            elif prefix == "swap_node":
                require(len(parts) == 4, f"{record.location}: malformed swap_node")
                created = parts[3:]
            elif prefix == "swap_nodes":
                mode = None
                for part in parts[2:]:
                    if part in {"in", "out"}:
                        mode = part
                    else:
                        require(
                            mode is not None, f"{record.location}: malformed swap_nodes"
                        )
                        if mode == "in":
                            created.append(part)
            for name in created:
                node(name, record.location)
                require(
                    name not in modes,
                    f"{record.location}: duplicate node creation {name!r}",
                )
                modes[name] = default_mode
            command = record
            continue
        require(command is not None, f"{record.location}: event before command")
        require(
            not (
                row.keys()
                - {"tag", "h_ts", "thread_id", "level", "file", "number", "msg"}
            ),
            f"{record.location}: unknown record fields",
        )
        ts = row.get("h_ts")
        require(
            isinstance(ts, str) and ts.isascii() and ts.isdecimal(),
            f"{record.location}: invalid timestamp",
        )
        try:
            current_timestamp = int(ts)
        except ValueError as error:
            raise TraceError(
                f"{record.location}: invalid timestamp: {error}"
            ) from error
        require(
            current_timestamp > timestamp,
            f"{record.location}: non-increasing timestamp",
        )
        timestamp = current_timestamp
        message = row.get("msg")
        require(isinstance(message, dict), f"{record.location}: missing message")
        require(
            isinstance(message.get("function"), str)
            and message["function"] in MESSAGE_FIELDS,
            f"{record.location}: unsupported function {message.get('function')!r}",
        )
        require(
            not (
                message.keys()
                - {"function", "state"}
                - MESSAGE_FIELDS[message["function"]]
            ),
            f"{record.location}: unknown message fields",
        )
        require(
            isinstance(message.get("state"), dict),
            f"{record.location}: state is not an object",
        )
        event = Event(record, command, message)
        state_facts(event)
        mode = event.state["pre_vote_enabled"]
        require(
            event.node not in modes or modes[event.node] == mode,
            f"{record.location}: pre-vote mode changed for existing node",
        )
        modes[event.node] = mode
        events.append(event)
    require(bool(events), "trace contains commands but no events")
    for event in events:
        if event.function == "add_configuration":
            require(
                set(configuration(event)) <= modes.keys(),
                f"{event.location}: configuration contains nodes without recorded creation or mode",
            )
    return events, modes


def state_facts(event: Event) -> dict[str, Any]:
    state = event.state
    require(isinstance(state, dict), f"{event.location}: state is not an object")
    require(
        not state.keys() - STATE_KEYS,
        f"{event.location}: unsupported state fields {state.keys() - STATE_KEYS}",
    )
    node(state.get("node_id"), event.location)
    role = state.get("leadership_state")
    require(
        isinstance(role, str) and role in ROLES,
        f"{event.location}: invalid role {role!r}",
    )
    membership = state.get("membership_state")
    phase = state.get("retirement_phase")
    require(
        (membership == "Active" and phase is None)
        or (membership == "Retired" and isinstance(phase, str) and phase in PHASES),
        f"{event.location}: unsupported membership/retirement phase",
    )
    require(
        type(state.get("pre_vote_enabled")) is bool,
        f"{event.location}: invalid pre-vote flag",
    )
    facts = {
        "role": ROLES[role],
        "currentTerm": term(state.get("current_view"), event.location),
        "logLength": index(state.get("last_idx"), event.location),
        "commitIndex": index(state.get("commit_idx"), event.location),
        "membershipState": "active" if membership == "Active" else PHASES[phase],
        "preVoteEnabled": state["pre_vote_enabled"],
    }
    for raw, target in (
        ("retirement_idx", "retirementIndex"),
        ("retirement_committable_idx", "retirementCommittableIndex"),
        ("retired_committed_idx", "retiredCommittedIndex"),
    ):
        facts[target] = (
            None if state.get(raw) is None else index(state[raw], event.location)
        )
    if "committable_indices" in state:
        values = state["committable_indices"]
        require(
            isinstance(values, list), f"{event.location}: invalid committable_indices"
        )
        for value in values:
            natural(value, event.location)
        require(
            values == sorted(set(values)),
            f"{event.location}: unordered/duplicate committable indices",
        )
        facts["committableIndices"] = [index(value, event.location) for value in values]
    if "configurations" in event.message:
        configurations = event.message["configurations"]
        require(
            isinstance(configurations, list),
            f"{event.location}: invalid configurations",
        )
        projected = []
        previous = -1
        for value in configurations:
            names = configuration_value(value, event.location)
            require(
                value["idx"] > previous, f"{event.location}: unordered configurations"
            )
            previous = value["idx"]
            projected.append(
                {"index": index(value["idx"], event.location), "nodes": names}
            )
        facts["configurations"] = projected
    return facts


def packet(event: Event) -> dict[str, Any]:
    raw = event.message.get("packet")
    require(isinstance(raw, dict), f"{event.location}: missing packet")
    family = raw.get("msg")
    require(
        isinstance(family, str) and family in PACKETS,
        f"{event.location}: unsupported packet {family!r}",
    )
    require(
        set(raw) == PACKETS[family],
        f"{event.location}: missing/unknown {family} packet fields",
    )
    result = dict(raw)
    for key, value in raw.items():
        if key in INDEX_KEYS:
            result[key] = index(value, event.location)
        elif key in TERM_KEYS:
            result[key] = term(value, event.location)
    if "prev_idx" in raw:
        require(
            raw["prev_idx"] <= raw["idx"], f"{event.location}: reversed append batch"
        )
        require(
            type(raw["contains_new_view"]) is bool,
            f"{event.location}: invalid contains_new_view",
        )
    if "success" in raw:
        require(
            isinstance(raw["success"], str) and raw["success"] in {"OK", "FAIL"},
            f"{event.location}: unsupported response success",
        )
    if "vote_granted" in raw:
        require(
            type(raw["vote_granted"]) is bool, f"{event.location}: invalid vote_granted"
        )
    return result


def configuration(event: Event) -> list[str]:
    args = event.message.get("args")
    require(
        isinstance(args, dict) and set(args) == {"configuration"},
        f"{event.location}: invalid configuration args",
    )
    return configuration_value(args["configuration"], event.location)


def configuration_value(value: Any, location: str) -> list[str]:
    require(
        isinstance(value, dict) and set(value) == {"idx", "nodes", "rid"},
        f"{location}: invalid configuration",
    )
    natural(value["idx"], location)
    natural(value["rid"], f"{location}: configuration.rid")
    require(
        value["rid"] == value["idx"], f"{location}: configuration rid differs from idx"
    )
    nodes = value["nodes"]
    require(
        isinstance(nodes, dict) and bool(nodes),
        f"{location}: empty/invalid configuration nodes",
    )
    for name, address in nodes.items():
        node(name, location)
        require(
            address == {"address": ":"}, f"{location}: unsupported driver node metadata"
        )
    return sorted(nodes)


class Reducer:
    """Emit canonical instructions. No canonical state is simulated here."""

    def __init__(self, records: list[Record]):
        self.records = records
        self.events, self.modes = associate(records)
        self.instructions: list[dict[str, Any]] = []
        self.nominations: dict[int, Event] = {}
        pending: dict[tuple[str, int], list[Event]] = {}
        for event in self.events:
            if event.function == "step_down_and_nominate_successor":
                pending.setdefault(
                    (event.node, event.state["current_view"]), []
                ).append(event)
            elif event.function in {"recv_propose_request_vote", "drop_pending_to"}:
                packet(event)
                raw = event.message["packet"]
                if raw.get("msg") != "raft_propose_request_vote":
                    continue
                source = node(event.message.get("from_node_id"), event.location)
                candidates = pending.get((source, raw.get("term")), [])
                require(
                    len(candidates) == 1,
                    f"{event.location}: nomination packet has {len(candidates)} possible originating sends",
                )
                nomination = candidates.pop()
                self.nominations[nomination.record.line] = event
        unmatched = [event for events in pending.values() for event in events]
        require(
            not unmatched,
            f"{unmatched[0].location if unmatched else ''}: nomination has no recorded receive/drop destination",
        )
        self.drop_occurrences: dict[int, int] = {}
        self.correlate_packets()

    def correlate_packets(self) -> None:
        """Track recorded packet occurrences, not canonical protocol state."""
        queues: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for event in self.events:
            function = event.function
            if function in {
                "send_append_entries",
                "send_append_entries_response",
                "send_request_vote",
            }:
                packet(event)
                destination = node(event.message.get("to_node_id"), event.location)
                queues.setdefault((event.node, destination), []).append(
                    event.message["packet"]
                )
            elif function == "step_down_and_nominate_successor":
                evidence = self.nominations[event.record.line]
                destination = (
                    evidence.node
                    if evidence.function == "recv_propose_request_vote"
                    else evidence.message["to_node_id"]
                )
                queues.setdefault((event.node, destination), []).append(
                    {
                        "msg": "raft_propose_request_vote",
                        "term": event.state["current_view"],
                    }
                )
            elif function.startswith("recv_") or function == "drop_pending_to":
                packet(event)
                raw = event.message["packet"]
                source = node(event.message.get("from_node_id"), event.location)
                destination = (
                    event.node
                    if function.startswith("recv_")
                    else node(event.message.get("to_node_id"), event.location)
                )
                queue = queues.setdefault((source, destination), [])
                matches = [
                    occurrence
                    for occurrence, sent in enumerate(queue)
                    if all(raw.get(key) == value for key, value in sent.items())
                ]
                require(
                    bool(matches),
                    f"{event.location}: packet has no matching recorded send",
                )
                if function == "drop_pending_to":
                    require(
                        len(matches) == 1 or all(queue[i] == raw for i in matches),
                        f"{event.location}: dropped packet matches ambiguous unlogged vote responses",
                    )
                    self.drop_occurrences[event.record.line] = matches[0]
                    queue.pop(matches[0])
                else:
                    require(
                        matches[0] == 0,
                        f"{event.location}: receive reorders packets from one sender; canonical FIFO action cannot represent it",
                    )
                    queue.pop(0)
                    if function == "recv_request_vote":
                        family = raw["msg"]
                        require(
                            family in {"raft_request_vote", "raft_request_pre_vote"},
                            f"{event.location}: invalid vote family",
                        )
                        # C++ always sends one response here. Its grant bit is
                        # not logged; only correlate fields actually established.
                        queues.setdefault((destination, source), []).append(
                            {
                                "msg": family + "_response",
                                "term": max(raw["term"], event.state["current_view"]),
                            }
                        )

    def observe(
        self,
        event: Event,
        rule: str,
        fields: dict[str, Any] | None = None,
        **extra: Any,
    ) -> None:
        facts = state_facts(event) if fields is None else fields
        self.instructions.append(
            {
                "kind": "observation",
                "observation": "state",
                "node": event.node,
                "fields": {
                    key: value
                    for key, value in facts.items()
                    if key != "committableIndices"
                },
                "origin": [event.origin(rule)],
                **extra,
            }
        )
        for marker in facts.get("committableIndices", []):
            self.entry(event, marker, {"kind": "signature"}, rule="signature-marker")

    def callback(self, event: Event) -> None:
        facts = state_facts(event)
        selected = CALLBACK_FIELDS[event.function]
        origin = event.origin("tla-callback-stutter")
        checked = {}
        if event.function != "become_follower":
            require(
                facts["role"] == "follower",
                f"{event.location}: receive callback requires follower role",
            )
            checked["role"] = facts["role"]
        origin["checkedRawFields"] = checked
        origin["rawRecord"] = event.record.value
        origin["omittedTransientFields"] = {
            name: value
            for name, value in facts.items()
            if name not in selected and name not in checked
        }
        self.instructions.append(
            {
                "kind": "observation",
                "observation": "state",
                "node": event.node,
                "fields": {
                    name: value for name, value in facts.items() if name in selected
                },
                "origin": [origin],
            }
        )

    def entry(
        self,
        event: Event,
        entry_index: int,
        fields: dict[str, Any],
        rule: str = "callback-entry",
    ) -> None:
        self.instructions.append(
            {
                "kind": "observation",
                "observation": "entry",
                "node": event.node,
                "index": entry_index,
                "fields": fields,
                "origin": [event.origin(rule)],
            }
        )

    def action(
        self,
        event: Event,
        action: str,
        rule: str,
        group: list[Event] | None = None,
        **parameters: Any,
    ) -> None:
        if action in {"receive", "updateTerm"}:
            parameters["destination"] = event.node
        elif action in {
            "changeConfiguration",
            "appendEntries",
            "drop",
            "requestVote",
            "requestPreVote",
            "proposeVote",
            "advanceCommitIndexAndProposeVote",
        }:
            parameters["source"] = event.node
        else:
            parameters["node"] = event.node
        self.instructions.append(
            {
                "kind": "action",
                "action": action,
                "origin": [item.origin(rule) for item in (group or [event])],
                **parameters,
            }
        )

    def message(self, event: Event, rule: str, receiving: bool, **extra: Any) -> None:
        source = (
            node(event.message.get("from_node_id"), event.location)
            if receiving
            else event.node
        )
        destination = (
            event.node
            if receiving
            else node(event.message.get("to_node_id"), event.location)
        )
        self.instructions.append(
            {
                "kind": "observation",
                "observation": "message",
                "source": source,
                "destination": destination,
                "packet": packet(event),
                "origin": [event.origin(rule)],
                **extra,
            }
        )

    def peers(self, event: Event, rule: str) -> None:
        fields = {
            target: index(event.message[raw], event.location)
            for raw, target in (("sent_idx", "sentIndex"), ("match_idx", "matchIndex"))
            if raw in event.message
        }
        if fields:
            peer = event.message.get("to_node_id", event.message.get("from_node_id"))
            self.observe(event, rule, fields, peer=node(peer, event.location))

    def bootstrap(self) -> int:
        prelude = self.events[:5]
        require(
            [e.function for e in prelude]
            == [
                "become_leader",
                "replicate",
                "add_configuration",
                "replicate",
                "commit",
            ],
            f"{self.events[0].location}: expected exact five-event bootstrap",
        )
        leader = prelude[0].node
        for event, last in zip(prelude, [0, 0, 0, 1, 2]):
            require(
                event.node == leader
                and event.state["current_view"] == 2
                and event.state["last_idx"] == last
                and event.state["commit_idx"] == 0
                and event.state["leadership_state"] == "Leader"
                and event.state["membership_state"] == "Active",
                f"{event.location}: bootstrap state differs from audited prelude",
            )
        require(
            configuration(prelude[2]) == [leader],
            f"{prelude[2].location}: bootstrap is not singleton",
        )
        require(
            prelude[2].message["args"]["configuration"]["idx"] == 1,
            f"{prelude[2].location}: bootstrap configuration index",
        )
        for event, seqno, committable in (
            (prelude[1], 1, False),
            (prelude[3], 2, True),
        ):
            require(
                event.message.get("seqno") == seqno
                and event.message.get("view") == 2
                and event.message.get("globally_committable") is committable,
                f"{event.location}: bootstrap write differs from audited prelude",
            )
        require(
            prelude[4].message.get("args") == {"idx": 2},
            f"{prelude[4].location}: bootstrap commit target",
        )
        expected_committables = [[], [], [], [], [2]]
        for event, expected in zip(prelude, expected_committables):
            require(
                event.state.get("committable_indices") == expected,
                f"{event.location}: bootstrap committable indices",
            )
        for event in prelude[:3]:
            self.observe(event, "bootstrap")
        self.action(prelude[2], "initializeConfiguration", "bootstrap", prelude[1:3])
        self.observe(prelude[3], "bootstrap")
        self.action(prelude[3], "signCommittableMessages", "bootstrap")
        self.observe(prelude[4], "bootstrap")
        self.action(prelude[4], "advanceCommitIndex", "bootstrap")
        self.observe(prelude[4], "bootstrap", {"commitIndex": 2})
        self.leader = leader
        return 5

    def configuration_write(self, position: int) -> int:
        write, config = self.events[position : position + 2]
        require(
            "configurations" in config.message,
            f"{config.location}: missing configurations snapshot",
        )
        previous_nodes = {
            name
            for value in config.message["configurations"]
            for name in configuration_value(value, config.location)
        }
        added = set(configuration(config)) - previous_nodes - {write.node}
        callbacks = []
        last = position + 1
        seen = set()
        while last + 1 < len(self.events):
            callback = self.events[last + 1]
            if not (
                callback.function == "send_append_entries"
                and callback.command == write.command
                and callback.node == write.node
                and callback.state["last_idx"] == write.state["last_idx"]
            ):
                break
            destination = node(callback.message.get("to_node_id"), callback.location)
            raw = callback.message["packet"]
            old_last = write.state["last_idx"]
            require(
                destination in added
                and destination not in seen
                and raw["prev_idx"] == old_last
                and raw["idx"] == old_last
                and callback.message.get("sent_idx") == old_last + 1
                and callback.message.get("match_idx") == 0,
                f"{callback.location}: unsupported configuration callback heartbeat",
            )
            pre, post = {}, {}
            for key, value in state_facts(callback).items():
                if key in {
                    "membershipState",
                    "retirementIndex",
                    "retirementCommittableIndex",
                    "retiredCommittedIndex",
                }:
                    post[key] = value
                else:
                    pre[key] = value
            if pre:
                self.observe(callback, "configuration-callback-pre", pre)
            callbacks.append((callback, post))
            seen.add(destination)
            last += 1
        require(
            seen == added,
            f"{config.location}: missing new-peer configuration callback {sorted(added - seen)}",
        )
        self.action(
            write,
            "changeConfiguration",
            "configuration-pair",
            [write, config],
            configuration=configuration(config),
        )
        for callback, post in callbacks:
            if post:
                self.observe(callback, "configuration-callback-post", post)
            self.observe(
                callback,
                "configuration-callback-peer",
                {
                    "sentIndex": callback.message["sent_idx"] - 1,
                    "matchIndex": callback.message["match_idx"],
                },
                peer=callback.message["to_node_id"],
            )
            self.action(
                callback,
                "appendEntries",
                "configuration-callback-send",
                destination=callback.message["to_node_id"],
                batchEnd=packet(callback)["idx"],
            )
            self.message(callback, "send-post", receiving=False, selection="last")
        return last

    def nominee(self, event: Event) -> tuple[str, Event]:
        evidence = self.nominations[event.record.line]
        destination = (
            evidence.node
            if evidence.function == "recv_propose_request_vote"
            else node(evidence.message.get("to_node_id"), evidence.location)
        )
        return destination, evidence

    def terminal_commit(self, commit: Event, nomination: Event, target: int) -> None:
        """Nomination runs after compaction but before terminal role/phase assignment."""
        facts = state_facts(nomination)
        require(
            facts["role"] == "leader"
            and facts["membershipState"] == "retirementCompleted"
            and facts["commitIndex"] == target
            and facts["retiredCommittedIndex"] == target,
            f"{nomination.location}: unexpected terminal-retirement nomination boundary",
        )
        checked = {"role": facts["role"], "membershipState": facts["membershipState"]}
        post_fields = {"commitIndex", "retiredCommittedIndex", "committableIndices"}
        before = {
            key: value
            for key, value in facts.items()
            if key not in checked and key not in post_fields
        }
        after = {key: value for key, value in facts.items() if key in post_fields}
        origin = nomination.origin("terminal-nomination-pre")
        origin.update(rawRecord=nomination.record.value, checkedRawFields=checked)
        self.observe(nomination, "terminal-nomination-pre", before, origin=[origin])
        destination, evidence = self.nominee(nomination)
        self.action(
            commit,
            "advanceCommitIndexAndProposeVote",
            "terminal-commit",
            [commit, nomination, evidence],
            destination=destination,
        )
        origin = nomination.origin("terminal-nomination-post")
        origin.update(rawRecord=nomination.record.value, checkedRawFields=checked)
        self.observe(nomination, "terminal-nomination-post", after, origin=[origin])

    def run(self) -> dict[str, Any]:
        position = self.bootstrap()
        while position < len(self.events):
            event = self.events[position]
            following = (
                self.events[position + 1] if position + 1 < len(self.events) else None
            )
            function = event.function
            if function == "replicate":
                self.observe(event, "write-pre")
                require(
                    event.message.get("seqno") == event.state["last_idx"] + 1,
                    f"{event.location}: non-successor write",
                )
                require(
                    event.message.get("view") == event.state["current_view"],
                    f"{event.location}: write term mismatch",
                )
                require(
                    type(event.message.get("globally_committable")) is bool,
                    f"{event.location}: missing committable flag",
                )
                if following is not None and following.function == "add_configuration":
                    require(
                        following.node == event.node
                        and following.command == event.command
                        and following.state == event.state
                        and following.message["args"]["configuration"]["idx"]
                        == event.message["seqno"]
                        and event.message["globally_committable"] is False,
                        f"{event.location}: configuration write pair mismatch",
                    )
                    self.observe(following, "configuration-pair")
                    position = self.configuration_write(position)
                elif event.message["globally_committable"]:
                    self.action(event, "signCommittableMessages", "write-pre")
                elif event.command.value["cmd"].startswith("cleanup_nodes,"):
                    self.action(event, "appendRetiredCommitted", "write-pre")
                else:
                    self.action(
                        event,
                        "clientRequest",
                        "write-pre",
                        transaction=f"{event.record.file}:{event.record.line}",
                    )
            elif function == "send_append_entries":
                self.observe(event, "send-pre")
                self.peers(event, "send-pre")
                self.action(
                    event,
                    "appendEntries",
                    "atomic-append",
                    destination=node(event.message.get("to_node_id"), event.location),
                    batchEnd=packet(event)["idx"],
                )
                self.message(event, "send-post", receiving=False, selection="last")
            elif function == "drop_pending_to":
                self.observe(event, "drop")
                require(
                    event.message.get("from_node_id") == event.node,
                    f"{event.location}: drop sender mismatch",
                )
                occurrence = self.drop_occurrences[event.record.line]
                self.message(event, "drop", receiving=False, occurrence=occurrence)
                self.action(
                    event,
                    "drop",
                    "drop",
                    source=event.node,
                    destination=node(event.message.get("to_node_id"), event.location),
                    occurrence=occurrence,
                )
            elif function.startswith("recv_"):
                position = self.receive(position)
            elif function == "commit":
                require(
                    event.state["leadership_state"] == "Leader",
                    f"{event.location}: ungrouped follower commit",
                )
                self.observe(event, "commit-pre")
                args = event.message.get("args")
                require(
                    isinstance(args, dict) and set(args) == {"idx"},
                    f"{event.location}: invalid commit args",
                )
                target = index(args["idx"], event.location)
                if (
                    following is not None
                    and following.function == "step_down_and_nominate_successor"
                    and following.node == event.node
                    and following.command == event.command
                    and following.state.get("retired_committed_idx") is not None
                ):
                    self.terminal_commit(event, following, target)
                    position += 1
                else:
                    self.action(event, "advanceCommitIndex", "commit-pre")
                self.observe(
                    event,
                    "commit-post",
                    {"commitIndex": target},
                )
            elif function in {
                "become_candidate",
                "become_pre_vote_candidate",
                "become_follower",
                "become_leader",
            }:
                action = {
                    "become_candidate": (
                        "becomeCandidate"
                        if event.state["pre_vote_enabled"]
                        else "timeout"
                    ),
                    "become_pre_vote_candidate": "becomePreVoteCandidate",
                    "become_follower": "checkQuorum",
                    "become_leader": "becomeLeader",
                }[function]
                self.action(event, action, "role-post")
                self.observe(event, "role-post")
            elif function == "send_request_vote":
                self.observe(event, "send-pre")
                family = packet(event)["msg"]
                require(
                    family in {"raft_request_vote", "raft_request_pre_vote"},
                    f"{event.location}: wrong vote request packet",
                )
                self.action(
                    event,
                    (
                        "requestVote"
                        if family == "raft_request_vote"
                        else "requestPreVote"
                    ),
                    "send-pre",
                    destination=node(event.message.get("to_node_id"), event.location),
                )
                self.message(event, "send-post", receiving=False, selection="last")
            elif function == "step_down_and_nominate_successor":
                destination, evidence = self.nominee(event)
                self.observe(event, "nomination")
                self.action(
                    event,
                    "proposeVote",
                    "nomination",
                    [event, evidence],
                    destination=destination,
                )
            else:
                raise TraceError(f"{event.location}: ungrouped callback {function}")
            position += 1
        return {
            "schema": SCHEMA,
            "bootstrap": {
                "configuration": [self.leader],
                "leader": self.leader,
                "pre_vote_enabled": self.modes,
            },
            "instructions": self.instructions,
        }

    def receive(self, position: int) -> int:
        event = self.events[position]
        source = node(event.message.get("from_node_id"), event.location)
        families = {
            "recv_append_entries": {"raft_append_entries"},
            "recv_append_entries_response": {"raft_append_entries_response"},
            "recv_request_vote": {"raft_request_vote", "raft_request_pre_vote"},
            "recv_request_vote_response": {
                "raft_request_vote_response",
                "raft_request_pre_vote_response",
            },
            "recv_propose_request_vote": {"raft_propose_request_vote"},
        }
        require(
            packet(event)["msg"] in families[event.function],
            f"{event.location}: receive function/packet mismatch",
        )
        self.observe(event, "receive-pre")
        self.peers(event, "receive-pre")
        self.message(event, "receive-pre", receiving=True)
        last = position
        follower = None
        if last + 1 < len(self.events):
            candidate = self.events[last + 1]
            if (
                candidate.function == "become_follower"
                and candidate.node == event.node
                and candidate.command == event.command
            ):
                follower = candidate
                last += 1
        if follower is not None:
            require(
                follower.state["current_view"] == event.message["packet"]["term"],
                f"{follower.location}: follower term differs from packet",
            )
            if follower.state["current_view"] > event.state["current_view"]:
                self.action(
                    event,
                    "updateTerm",
                    "receive-term",
                    [event, follower],
                    source=source,
                )
            else:
                require(
                    event.function == "recv_append_entries",
                    f"{event.location}: unexplained same-term fallback",
                )
                self.action(
                    event,
                    "receive",
                    "receive-fallback",
                    [event, follower],
                    source=source,
                )
            self.callback(follower)
        helpers = []
        if event.function == "recv_append_entries":
            while last + 1 < len(self.events):
                helper = self.events[last + 1]
                if helper.function not in {
                    "execute_append_entries_sync",
                    "add_configuration",
                    "commit",
                    "send_append_entries_response",
                }:
                    break
                require(
                    helper.node == event.node and helper.command == event.command,
                    f"{helper.location}: interleaved receive callback",
                )
                helpers.append(helper)
                last += 1
                if helper.function == "send_append_entries_response":
                    break
        elif event.function == "recv_propose_request_vote" and last + 1 < len(
            self.events
        ):
            helper = self.events[last + 1]
            if (
                helper.function == "become_candidate"
                and helper.node == event.node
                and helper.command == event.command
            ):
                helpers.append(helper)
                last += 1
        self.action(
            event, "receive", "atomic-receive", [event, *helpers], source=source
        )
        for helper in helpers:
            if helper.function in {"send_append_entries_response", "become_candidate"}:
                self.observe(helper, "receive-post")
                if helper.function == "send_append_entries_response":
                    self.message(
                        helper, "response-post", receiving=False, selection="last"
                    )
                continue
            if helper.function == "execute_append_entries_sync":
                require(
                    helper.message.get("from_node_id") == source,
                    f"{helper.location}: execute source mismatch",
                )
            elif helper.function == "add_configuration":
                names = configuration(helper)
                self.entry(
                    helper,
                    helper.message["args"]["configuration"]["idx"],
                    {
                        "kind": "configuration",
                        "configuration": names,
                    },
                )
            elif helper.function == "commit":
                args = helper.message.get("args")
                require(
                    isinstance(args, dict) and set(args) == {"idx"},
                    f"{helper.location}: invalid commit args",
                )
                target = index(args["idx"], helper.location)
                self.entry(helper, target, {"kind": "signature", "committed": True})
            else:
                raise TraceError(
                    f"{helper.location}: unsupported receive helper {helper.function}"
                )
            self.callback(helper)
        return last


def reduce_trace(records: list[Record]) -> dict[str, Any]:
    return Reducer(records).run()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        result = reduce_trace(read_trace(args.trace))
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (TraceError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
