#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Deterministic, fail-closed reduction of recorded CCF Raft events."""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

from trace_io import Record, TraceError, read_trace

SCHEMA = "ccfraft-replay/v3"
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
    "send_request_vote_response": {"to_node_id", "packet"},
    "step_down_and_nominate_successor": {"configurations", "to_node_id"},
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


def require(condition: bool, message: str) -> None:
    """Report trace evidence that a rule or projection cannot handle."""
    if not condition:
        raise TraceError(message)


def natural(value: Any, location: str) -> int:
    """Read a non-negative trace coordinate, rejecting booleans as integers."""
    require(type(value) is int and value >= 0, f"{location}: expected natural number")
    return value


def node(value: Any, location: str) -> str:
    """Read a driver node ID without renaming it for replay."""
    require(isinstance(value, str) and bool(value), f"{location}: expected node string")
    return value


def index(value: Any, location: str) -> int:
    """Preserve physical ledger positions when translating to replay."""
    return natural(value, location)


def term(value: Any, location: str) -> int:
    """Preserve implementation term numbers when translating to replay."""
    return natural(value, location)


@dataclass(frozen=True)
class Event:
    """Pair a raw event with its driver command for rule matching and origins."""

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
        """Link an emitted instruction back to this event and its command."""
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
    """Attach commands and collect fixed per-node pre-vote settings.

    Preserve capture order; do not reconstruct protocol state or packet queues.
    """
    events = []
    command = None
    modes: dict[str, bool] = {}
    default_mode = True
    for record in records:
        row = record.value
        if "cmd" in row:
            parts = row["cmd"].split(",")
            prefix = parts[0]
            require(
                prefix in COMMANDS, f"{record.location}: unsupported command {prefix!r}"
            )
            # Creation commands declare modes for nodes with no Raft events yet.
            created = []
            if prefix == "pre_vote_enabled":
                default_mode = {"true": True, "false": False}[parts[1]]
            elif prefix in {"start_node", "create_new_node", "nodes"}:
                created = parts[1:]
            elif prefix in {"trust_node", "trust_nodes"}:
                created = parts[2:]
            elif prefix == "swap_node":
                created = parts[3:]
            elif prefix == "swap_nodes":
                mode = None
                for part in parts[2:]:
                    if part in {"in", "out"}:
                        mode = part
                    elif mode == "in":
                        created.append(part)
            modes.update((name, default_mode) for name in created)
            command = record
            continue
        # Keep the original command and record for grouping and diagnostics.
        require(command is not None, f"{record.location}: event before command")
        require(
            not (
                row.keys()
                - {"tag", "h_ts", "thread_id", "level", "file", "number", "msg"}
            ),
            f"{record.location}: unknown record fields",
        )
        message = row["msg"]
        # Reject extensions we would otherwise silently omit from observations.
        require(
            message["function"] in MESSAGE_FIELDS,
            f"{record.location}: unsupported function {message['function']!r}",
        )
        require(
            not (
                message.keys()
                - {"function", "state"}
                - MESSAGE_FIELDS[message["function"]]
            ),
            f"{record.location}: unknown message fields",
        )
        event = Event(record, command, message)
        if event.function == "step_down_and_nominate_successor":
            require(
                "to_node_id" in message,
                f"{event.location}: missing nomination destination; recapture with an updated raft_driver",
            )
        # Without a creation command, use the node's first snapshot.
        modes.setdefault(event.node, event.state["pre_vote_enabled"])
        events.append(event)
    require(bool(events), "trace contains commands but no events")
    return events, modes


def state_facts(event: Event) -> dict[str, Any]:
    """Project a recorded snapshot into Lean's observation properties.

    These are expected values for emit_observations, not computed model state.
    Rules choose which properties to exclude at their action boundary.
    """
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
    """Translate a recorded packet header for rules and message observations.

    Preserve coordinates without reconstructing payloads or searching queues.
    """
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
    """Read the incoming membership from an add_configuration callback."""
    args = event.message.get("args")
    require(
        isinstance(args, dict) and set(args) == {"configuration"},
        f"{event.location}: invalid configuration args",
    )
    return configuration_value(args["configuration"], event.location)


def configuration_value(value: Any, location: str) -> list[str]:
    """Extract sorted node IDs from a configuration argument or cached snapshot."""
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


class Instructions:
    """Output builders only; no event cursor or protocol state."""

    def __init__(self):
        self.instructions: list[dict[str, Any]] = []

    def emit_observations(
        self,
        event: Event,
        rule: str,
        properties: dict[str, Any] | None = None,
        *,
        exclusions: dict[str, str] | None = None,
        peer: str | None = None,
    ) -> None:
        """Emit properties for Lean to compare, recording reasons for exclusions.

        Use all state_facts by default. Emit committable markers as entry checks.
        """
        properties = state_facts(event) if properties is None else properties
        exclusions = {} if exclusions is None else exclusions
        require(
            not exclusions.keys() - properties.keys(),
            f"{event.location}: exclusions name unknown properties: "
            f"{sorted(exclusions.keys() - properties.keys())}",
        )
        require(
            all(
                isinstance(reason, str) and reason.strip()
                for reason in exclusions.values()
            ),
            f"{event.location}: every observation exclusion requires a reason",
        )
        origin = event.origin(rule)
        if exclusions:
            origin.update(
                rawRecord=event.record.value,
                omittedTransientFields={name: properties[name] for name in exclusions},
                omissionReasons=exclusions,
            )
        facts = {
            name: value for name, value in properties.items() if name not in exclusions
        }
        # C++'s committable cache is not a complete signature enumeration and
        # commit prunes it. Check positive log membership, not cache equality.
        fields = {
            name: value for name, value in facts.items() if name != "committableIndices"
        }
        require(
            bool(fields),
            f"{event.location}: {rule} has no state properties to observe",
        )
        observation = {
            "kind": "observation",
            "observation": "state",
            "node": event.node,
            "fields": fields,
            "origin": [origin],
        }
        if peer is not None:
            observation["peer"] = peer
        self.instructions.append(observation)
        for marker in facts.get("committableIndices", []):
            self.entry(event, marker, {"kind": "signature"}, rule="signature-marker")

    def entry(
        self,
        event: Event,
        entry_index: int,
        fields: dict[str, Any],
        rule: str = "callback-entry",
    ) -> None:
        """Observe selected fields of one physical log entry on the event's node."""
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
        """Append a rule-selected model action with origins for its source events."""
        self.instructions.append(
            {
                "kind": "action",
                "action": action,
                "origin": [item.origin(rule) for item in (group or [event])],
                **parameters,
            }
        )

    def message(self, event: Event, rule: str, receiving: bool, **extra: Any) -> None:
        """Observe a queued header using receive or send endpoint direction.

        Rules select the queue position through selection or occurrence.
        """
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
        """Observe sent_idx and match_idx as progress toward the remote peer."""
        fields = {
            target: index(event.message[raw], event.location)
            for raw, target in (("sent_idx", "sentIndex"), ("match_idx", "matchIndex"))
            if raw in event.message
        }
        if fields:
            peer = event.message.get("to_node_id", event.message.get("from_node_id"))
            self.emit_observations(event, rule, fields, peer=node(peer, event.location))


def reduce_trace(records: list[Record]) -> dict[str, Any]:
    """Translate ordered event prefixes into actions and observations for Lean."""
    source, modes = associate(records)
    events = deque(source)
    out = Instructions()
    leader = source[0].node

    def peek(count: int = 1) -> list[str]:
        return [event.function for event in islice(events, count)]

    def take(count: int = 1) -> list[Event]:
        require(
            len(events) >= count,
            f"{events[0].location if events else 'end of trace'}: incomplete event group",
        )
        return [events.popleft() for _ in range(count)]

    def same_context(first: Event, second: Event) -> bool:
        return first.node == second.node and first.command == second.command

    bootstrap = [
        "become_leader",
        "replicate",
        "add_configuration",
        "replicate",
        "commit",
    ]
    receive_families = {
        "recv_append_entries": {"raft_append_entries"},
        "recv_append_entries_response": {"raft_append_entries_response"},
        "recv_request_vote": {"raft_request_vote", "raft_request_pre_vote"},
        "recv_request_vote_response": {
            "raft_request_vote_response",
            "raft_request_pre_vote_response",
        },
        "recv_propose_request_vote": {"raft_propose_request_vote"},
    }
    append_callbacks = {
        "execute_append_entries_sync",
        "add_configuration",
        "commit",
        "send_append_entries_response",
    }
    retirement_fields = {
        "membershipState",
        "retirementIndex",
        "retirementCommittableIndex",
        "retiredCommittedIndex",
    }

    while events:
        if events[0].function == "replicate":
            write = events[0]
            require(
                write.message["seqno"] == write.state["last_idx"] + 1
                and write.message["view"] == write.state["current_view"],
                f"{write.location}: write coordinates differ from the recorded state",
            )
        if not out.instructions:
            require(
                peek(5) == bootstrap,
                f"{events[0].location}: expected exact five-event bootstrap",
            )
            prelude = take(5)
            for event, length, markers in zip(
                prelude, [0, 0, 0, 1, 2], [[], [], [], [], [2]]
            ):
                require(
                    event.node == leader
                    and event.state["current_view"] == 2
                    and event.state["last_idx"] == length
                    and event.state["commit_idx"] == 0
                    and event.state["leadership_state"] == "Leader"
                    and event.state["membership_state"] == "Active",
                    f"{event.location}: bootstrap state differs from audited prelude",
                )
                require(
                    event.state.get("committable_indices") == markers,
                    f"{event.location}: bootstrap committable indices",
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
                prelude[4].message["args"]["idx"] == 2,
                f"{prelude[4].location}: bootstrap commit target",
            )
            for event in prelude[:3]:
                out.emit_observations(event, "bootstrap")
            out.action(
                prelude[2],
                "initializeConfiguration",
                "bootstrap",
                prelude[1:3],
                node=leader,
            )
            out.emit_observations(prelude[3], "bootstrap")
            out.action(prelude[3], "signCommittableMessages", "bootstrap", node=leader)
            out.emit_observations(prelude[4], "bootstrap")
            out.action(prelude[4], "advanceCommitIndex", "bootstrap", node=leader)
            # The snapshot precedes commit; args.idx alone records its result.
            out.emit_observations(prelude[4], "bootstrap", {"commitIndex": 2})

        elif peek(2) == ["replicate", "add_configuration"]:
            write, config = take(2)
            require(
                same_context(write, config)
                and config.state == write.state
                and config.message["args"]["configuration"]["idx"]
                == write.message["seqno"]
                and write.message["globally_committable"] is False,
                f"{write.location}: configuration write pair mismatch",
            )
            out.emit_observations(write, "write-pre")
            out.emit_observations(config, "configuration-pair")
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
            require(
                peek(len(added)) == ["send_append_entries"] * len(added),
                f"{config.location}: missing new-peer configuration callback",
            )
            callbacks = take(len(added))
            require(
                sorted(node(c.message.get("to_node_id"), c.location) for c in callbacks)
                == sorted(added),
                f"{config.location}: new-peer configuration callback destinations differ",
            )
            for callback in callbacks:
                raw = callback.message["packet"]
                old_length = write.state["last_idx"]
                require(
                    same_context(write, callback)
                    and callback.state["last_idx"] == old_length
                    and raw["prev_idx"] == old_length
                    and raw["idx"] == old_length
                    and callback.message.get("sent_idx") == old_length + 1
                    and callback.message.get("match_idx") == 0,
                    f"{callback.location}: unsupported configuration callback heartbeat",
                )
                # Hooks have changed membership, but replicate has not yet
                # appended the configuration entry. Check both sides separately.
                out.emit_observations(
                    callback,
                    "configuration-callback-pre",
                    exclusions={
                        field: "The configuration hook already changed this property; observed after changeConfiguration."
                        for field in retirement_fields
                    },
                )
            out.action(
                write,
                "changeConfiguration",
                "configuration-pair",
                [write, config],
                source=write.node,
                configuration=configuration(config),
            )
            for callback in callbacks:
                facts = state_facts(callback)
                out.emit_observations(
                    callback,
                    "configuration-callback-post",
                    {
                        field: value
                        for field, value in facts.items()
                        if field in retirement_fields
                    },
                )
                # The new-peer constructor stores a next-index sentinel, one
                # past the canonical sent frontier. Ordinary sends do not.
                out.emit_observations(
                    callback,
                    "configuration-callback-peer",
                    {
                        "sentIndex": callback.message["sent_idx"] - 1,
                        "matchIndex": callback.message["match_idx"],
                    },
                    peer=callback.message["to_node_id"],
                )
                out.action(
                    callback,
                    "appendEntries",
                    "configuration-callback-send",
                    source=write.node,
                    destination=callback.message["to_node_id"],
                    batchEnd=packet(callback)["idx"],
                )
                out.message(callback, "send-post", receiving=False, selection="last")

        elif peek(1) == ["replicate"]:
            (event,) = take()
            out.emit_observations(event, "write-pre")
            if event.message["globally_committable"]:
                out.action(
                    event, "signCommittableMessages", "write-pre", node=event.node
                )
            elif event.command.value["cmd"].startswith("cleanup_nodes,"):
                out.action(
                    event, "appendRetiredCommitted", "write-pre", node=event.node
                )
            else:
                out.action(
                    event,
                    "clientRequest",
                    "write-pre",
                    node=event.node,
                    transaction=f"{event.record.file}:{event.record.line}",
                )

        elif peek(1) == ["send_append_entries"]:
            (event,) = take()
            out.emit_observations(event, "send-pre")
            out.peers(event, "send-pre")
            out.action(
                event,
                "appendEntries",
                "atomic-append",
                source=event.node,
                destination=node(event.message.get("to_node_id"), event.location),
                batchEnd=packet(event)["idx"],
            )
            out.message(event, "send-post", receiving=False, selection="last")

        elif peek(1) == ["drop_pending_to"]:
            (event,) = take()
            require(
                event.message.get("from_node_id") == event.node,
                f"{event.location}: drop sender mismatch",
            )
            out.emit_observations(event, "drop")
            out.message(event, "drop", receiving=False, occurrence=0)
            out.action(
                event,
                "drop",
                "drop",
                source=event.node,
                destination=node(event.message.get("to_node_id"), event.location),
                occurrence=0,
            )

        elif events[0].function in receive_families:
            (event,) = take()
            sender = node(event.message.get("from_node_id"), event.location)
            require(
                packet(event)["msg"] in receive_families[event.function],
                f"{event.location}: receive function/packet mismatch",
            )
            out.emit_observations(event, "receive-pre")
            out.peers(event, "receive-pre")
            out.message(event, "receive-pre", receiving=True)

            # A newer term, or a same-term AppendEntries at a candidate, makes
            # the receiver a follower. The model does this inside the receive.
            followers = []
            if peek() == ["become_follower"] and same_context(event, events[0]):
                followers = take()
                require(
                    followers[0].state["current_view"]
                    == event.message["packet"]["term"],
                    f"{followers[0].location}: follower term differs from packet",
                )
                require(
                    followers[0].state["current_view"] > event.state["current_view"]
                    or event.function == "recv_append_entries",
                    f"{event.location}: unexplained same-term fallback",
                )

            # Match the variable-length source callback run, not protocol state.
            # A response ends it; response-less receive paths are also valid.
            callbacks = []
            if event.function == "recv_append_entries":
                while events and events[0].function in append_callbacks:
                    (callback,) = take()
                    require(
                        same_context(event, callback),
                        f"{callback.location}: interleaved receive callback",
                    )
                    callbacks.append(callback)
                    if callback.function == "send_append_entries_response":
                        break
            elif event.function == "recv_request_vote" and peek() == [
                "send_request_vote_response"
            ]:
                (response,) = take()
                require(
                    same_context(event, response)
                    and response.message["to_node_id"] == sender
                    and packet(response)["msg"]
                    == event.message["packet"]["msg"] + "_response",
                    f"{response.location}: vote response does not match request",
                )
                callbacks = [response]
            elif (
                event.function == "recv_propose_request_vote"
                and peek() == ["become_candidate"]
                and same_context(event, events[0])
            ):
                callbacks = take()
            out.action(
                event,
                "receive",
                "atomic-receive",
                [event, *followers, *callbacks],
                source=sender,
                destination=event.node,
            )
            for follower in followers:
                facts = state_facts(follower)
                out.emit_observations(
                    follower,
                    "receive-follower-post",
                    facts,
                    exclusions={
                        name: "become_follower traces before the rest of the atomic "
                        "receive, which can change this property."
                        for name in facts
                        if name not in {"role", "currentTerm"}
                    },
                )
            for position, callback in enumerate(callbacks):
                if callback.function in {
                    "send_append_entries_response",
                    "send_request_vote_response",
                    "become_candidate",
                }:
                    out.emit_observations(callback, "receive-post")
                    if callback.function != "become_candidate":
                        out.message(
                            callback, "response-post", receiving=False, selection="last"
                        )
                    continue

                if callback.function == "execute_append_entries_sync":
                    require(
                        callback.message.get("from_node_id") == sender,
                        f"{callback.location}: execute source mismatch",
                    )
                elif callback.function == "add_configuration":
                    out.entry(
                        callback,
                        callback.message["args"]["configuration"]["idx"],
                        {
                            "kind": "configuration",
                            "configuration": configuration(callback),
                        },
                    )
                elif callback.function == "commit":
                    out.entry(
                        callback,
                        callback.message["args"]["idx"],
                        {"kind": "signature", "committed": True},
                    )

                facts = state_facts(callback)
                require(
                    facts["role"] == "follower",
                    f"{callback.location}: receive callback requires follower role",
                )
                # Include the current callback: it traces before its mutation.
                pending = {c.function for c in callbacks[position:]}
                exclusions = {
                    "membershipState": (
                        "Configuration hooks order retirement, signature application signs "
                        "it, and commit completes it, all within the atomic receive."
                    ),
                }
                if "execute_append_entries_sync" in pending:
                    exclusions["logLength"] = (
                        "execute_append_entries_sync traces before applying an entry; "
                        "remaining execute callbacks extend the log before receive ends."
                    )
                if "commit" in pending:
                    exclusions["role"] = (
                        "Checked as follower at the raw call site above; terminal retirement "
                        "during a pending commit can clear the final role."
                    )
                    exclusions["commitIndex"] = (
                        "commit traces before advancing commit_idx; remaining commit "
                        "callbacks can advance it again. Check the already-committed "
                        "signature below instead of equality with the final frontier."
                    )
                    if facts["commitIndex"] > 0:
                        out.entry(
                            callback,
                            facts["commitIndex"],
                            {"kind": "signature", "committed": True},
                            rule="callback-committed-prefix",
                        )
                # State rollback precedes the execute loop. A present retirement
                # index cannot be replaced by the remaining hooks or commits.
                for field, writer, reason in (
                    (
                        "retirementIndex",
                        "add_configuration",
                        "a pending configuration hook can order retirement",
                    ),
                    (
                        "retirementCommittableIndex",
                        "execute_append_entries_sync",
                        "a pending entry can be the signature that signs retirement",
                    ),
                    (
                        "retiredCommittedIndex",
                        "commit",
                        "a pending commit callback can finish retirement",
                    ),
                ):
                    if facts[field] is None and writer in pending:
                        exclusions[field] = (
                            f"Absent at this callback, but {reason} in the same packet. "
                            "Present indices are compared to the final state."
                        )
                if "configurations" in facts:
                    exclusions["configurations"] = (
                        "add_configuration traces before inserting its configuration; "
                        "commit traces before pruning old configurations. Check the "
                        "recorded entries below, not equality with the final active cache."
                    )
                    for config in facts["configurations"]:
                        out.entry(
                            callback,
                            config["index"],
                            {"kind": "configuration", "configuration": config["nodes"]},
                            rule="callback-configuration",
                        )
                out.emit_observations(
                    callback, "tla-callback-stutter", facts, exclusions=exclusions
                )

        elif peek(2) == [
            "commit",
            "step_down_and_nominate_successor",
        ] and same_context(events[0], events[1]):
            commit, nomination = take(2)
            require(
                commit.state["leadership_state"] == "Leader",
                f"{commit.location}: ungrouped follower commit",
            )
            out.emit_observations(commit, "commit-pre")
            target = commit.message["args"]["idx"]
            facts = state_facts(nomination)
            require(
                facts["role"] == "leader"
                and facts["membershipState"] == "retirementCompleted"
                and facts["commitIndex"] == target
                and facts["retiredCommittedIndex"] == target,
                f"{nomination.location}: unexpected terminal-retirement nomination boundary",
            )
            post_fields = {"commitIndex", "retiredCommittedIndex", "committableIndices"}
            # The nomination runs after compaction but before role/phase
            # assignment and before old configurations are discarded.
            out.emit_observations(
                nomination,
                "terminal-nomination-pre",
                facts,
                exclusions={
                    "role": "nominate_successor runs before become_retired clears leadership; the raw leader role is checked above.",
                    "membershipState": "nominate_successor runs before become_retired assigns the terminal phase; the raw completed phase is checked above.",
                    **{
                        field: "Observed after the combined action at terminal-nomination-post."
                        for field in post_fields
                        if field in facts
                    },
                },
            )
            out.action(
                commit,
                "advanceCommitIndexAndProposeVote",
                "terminal-commit",
                [commit, nomination],
                source=commit.node,
                destination=nomination.message["to_node_id"],
            )
            out.emit_observations(
                nomination,
                "terminal-nomination-post",
                {
                    field: value
                    for field, value in facts.items()
                    if field in post_fields
                },
            )
            out.emit_observations(commit, "commit-post", {"commitIndex": target})

        elif peek(1) == ["commit"]:
            (event,) = take()
            require(
                event.state["leadership_state"] == "Leader",
                f"{event.location}: ungrouped follower commit",
            )
            out.emit_observations(event, "commit-pre")
            out.action(event, "advanceCommitIndex", "commit-pre", node=event.node)
            out.emit_observations(
                event, "commit-post", {"commitIndex": event.message["args"]["idx"]}
            )

        elif events[0].function in {
            "become_candidate",
            "become_pre_vote_candidate",
            "become_follower",
            "become_leader",
        }:
            (event,) = take()
            action = {
                "become_candidate": (
                    "becomeCandidate" if event.state["pre_vote_enabled"] else "timeout"
                ),
                "become_pre_vote_candidate": "becomePreVoteCandidate",
                "become_follower": "checkQuorum",
                "become_leader": "becomeLeader",
            }[event.function]
            out.action(event, action, "role-post", node=event.node)
            out.emit_observations(event, "role-post")

        elif peek(1) == ["send_request_vote"]:
            (event,) = take()
            out.emit_observations(event, "send-pre")
            family = packet(event)["msg"]
            require(
                family in {"raft_request_vote", "raft_request_pre_vote"},
                f"{event.location}: wrong vote request packet",
            )
            out.action(
                event,
                "requestVote" if family == "raft_request_vote" else "requestPreVote",
                "send-pre",
                source=event.node,
                destination=node(event.message.get("to_node_id"), event.location),
            )
            out.message(event, "send-post", receiving=False, selection="last")

        elif peek(1) == ["step_down_and_nominate_successor"]:
            (event,) = take()
            out.emit_observations(event, "nomination")
            out.action(
                event,
                "proposeVote",
                "nomination",
                source=event.node,
                destination=event.message["to_node_id"],
            )

        else:
            event = events[0]
            raise TraceError(f"{event.location}: ungrouped callback {event.function}")

    return {
        "schema": SCHEMA,
        "bootstrap": {
            "configuration": [leader],
            "leader": leader,
            "pre_vote_enabled": modes,
        },
        "instructions": out.instructions,
    }


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
