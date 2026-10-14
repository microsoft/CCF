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

SCHEMA = "ccfraft-replay/v4"
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
        sources = group or [event]
        if action != "nominateSuccessor":
            # Nomination callbacks have their own explicit model action.
            sources = [
                item
                for item in sources
                if item.function != "step_down_and_nominate_successor"
            ]
        self.instructions.append(
            {
                "kind": "action",
                "action": action,
                "origin": [item.origin(rule) for item in sources],
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

    def message_propose(self, nomination: Event, rule: str) -> None:
        """Observe the nominated successor's queued proposal."""
        self.instructions.append(
            {
                "kind": "observation",
                "observation": "message",
                "source": nomination.node,
                "destination": node(
                    nomination.message["to_node_id"], nomination.location
                ),
                "packet": {
                    "msg": "raft_propose_request_vote",
                    "term": term(nomination.state["current_view"], nomination.location),
                },
                "origin": [nomination.origin(rule)],
                "selection": "last",
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

    def election_group(
        head: Event,
    ) -> tuple[list[Event], list[Event], list[Event]]:
        """Take the callbacks of one raft.h election entry after its head event.

        become_pre_vote_candidate and become_candidate vote for self before
        their request loops; a self-quorum promotes synchronously, so nested
        become_candidate/become_leader trace before any send_request_vote.
        """
        nested: list[Event] = []
        if (
            head.function == "become_pre_vote_candidate"
            and peek() == ["become_candidate"]
            and same_context(head, events[0])
        ):
            nested += take()
        if (
            (nested or [head])[-1].function == "become_candidate"
            and peek() == ["become_leader"]
            and same_context(head, events[0])
        ):
            nested += take()
        # A synchronous promotion commits when alone and heartbeats before the
        # candidate's own request loop continues.
        tail = (
            take_leader_tail(nested[-1])
            if nested and nested[-1].function == "become_leader"
            else []
        )
        family = (
            "raft_request_pre_vote"
            if head.function == "become_pre_vote_candidate" and not nested
            else "raft_request_vote"
        )
        sends: list[Event] = []
        while peek() == ["send_request_vote"] and same_context(head, events[0]):
            (send,) = take()
            require(
                packet(send)["msg"] == family,
                f"{send.location}: wrong vote request packet",
            )
            sends.append(send)
        others = sorted(
            {
                member
                for conf in head.message["configurations"]
                for member in configuration_value(conf, head.location)
            }
            - {head.node}
        )
        require(
            [node(s.message.get("to_node_id"), s.location) for s in sends] == others,
            f"{head.location}: vote requests differ from other active members",
        )
        require(
            not (nested and others),
            f"{head.location}: self-quorum promotion with other active members",
        )
        return nested, sends, tail

    def take_commit_tail(anchor: Event) -> list[Event]:
        """Take an internal leader commit, and its retirement nomination, that
        raft.h runs inside the operation which traced the anchor."""
        if not (peek() == ["commit"] and same_context(anchor, events[0])):
            return []
        (commit,) = take()
        require(
            commit.state["leadership_state"] == "Leader",
            f"{commit.location}: internal commit outside leadership",
        )
        if not (
            peek() == ["step_down_and_nominate_successor"]
            and same_context(commit, events[0])
        ):
            return [commit]
        (nomination,) = take()
        target = commit.message["args"]["idx"]
        facts = state_facts(nomination)
        require(
            facts["role"] == "leader"
            and facts["membershipState"] == "retirementCompleted"
            and facts["commitIndex"] == target
            and facts["retiredCommittedIndex"] == target,
            f"{nomination.location}: unexpected terminal-retirement nomination boundary",
        )
        return [commit, nomination]

    def emit_commit_tail(tail: list[Event]) -> None:
        """Observe the result of a commit tail after its enclosing action."""
        if not tail:
            return
        commit = tail[0]
        target = commit.message["args"]["idx"]
        facts = state_facts(commit)
        changed = {
            "commitIndex",
            "role",
            "configurations",
            *retirement_fields,
        }
        # commit traces before advancing; it can also prune configurations and
        # complete or finish retirement inside the same model step.
        out.emit_observations(
            commit,
            "commit-in-action",
            facts,
            exclusions={
                name: "commit traces before applying itself inside the same "
                "atomic model step; checked after the commit below."
                for name in changed
                if name in facts
            },
        )
        if len(tail) == 2:
            nomination = tail[1]
            nominated = state_facts(nomination)
            post_fields = {"commitIndex", "retiredCommittedIndex", "committableIndices"}
            # The nomination runs after compaction but before role/phase
            # assignment and before old configurations are discarded.
            out.emit_observations(
                nomination,
                "terminal-nomination-pre",
                nominated,
                exclusions={
                    "role": "nominate_successor runs before become_retired clears leadership; the raw leader role is checked when grouping.",
                    "membershipState": "nominate_successor runs before become_retired assigns the terminal phase; the raw completed phase is checked when grouping.",
                    **{
                        field: "Observed after the nomination at terminal-nomination-post."
                        for field in post_fields
                        if field in nominated
                    },
                    **(
                        {
                            "configurations": "become_retired later discards old configurations in the same step."
                        }
                        if "configurations" in nominated
                        else {}
                    ),
                },
            )
            out.action(
                nomination,
                "nominateSuccessor",
                "terminal-nomination",
                node=nomination.node,
                destination=node(nomination.message["to_node_id"], nomination.location),
            )
            out.message_propose(nomination, "terminal-nomination-message")
            out.emit_observations(
                nomination,
                "terminal-nomination-post",
                {
                    field: value
                    for field, value in nominated.items()
                    if field
                    in {"commitIndex", "retiredCommittedIndex", "committableIndices"}
                },
            )
        out.emit_observations(commit, "commit-post", {"commitIndex": target})

    def take_heartbeats(anchor: Event) -> list[Event]:
        """Take the empty AppendEntries raft.h sends inside become_leader."""
        heartbeats: list[Event] = []
        while peek() == ["send_append_entries"] and same_context(anchor, events[0]):
            raw = events[0].message["packet"]
            if not (raw["prev_idx"] == raw["idx"] == events[0].state["last_idx"]):
                break
            heartbeats += take()
        destinations = [
            node(h.message.get("to_node_id"), h.location) for h in heartbeats
        ]
        require(
            len(set(destinations)) == len(destinations),
            f"{anchor.location}: duplicate leadership heartbeat destination",
        )
        if "configurations" in anchor.message:
            active = {
                name
                for value in anchor.message["configurations"]
                for name in configuration_value(value, anchor.location)
            } - {anchor.node}
            require(
                active <= set(destinations),
                f"{anchor.location}: missing active-peer leadership heartbeat",
            )
        return heartbeats

    def take_leader_tail(leader_event: Event) -> list[Event]:
        """become_leader: internal commit when alone, then heartbeats to peers."""
        return [*take_commit_tail(leader_event), *take_heartbeats(leader_event)]

    def emit_leader_tail(tail: list[Event]) -> None:
        commits = [e for e in tail if e.function != "send_append_entries"]
        emit_commit_tail(commits)
        for heartbeat in tail[len(commits) :]:
            out.peers(heartbeat, "leader-heartbeat-pre")
            out.message(heartbeat, "send-post", receiving=False, selection="last")

    def emit_election(
        head: Event,
        nested: list[Event],
        sends: list[Event],
        tail: list[Event],
        rule: str,
    ):
        """Observe each role snapshot and each queued vote request of a group."""
        final = state_facts((nested or [head])[-1])
        for event in [head, *nested][:-1]:
            facts = state_facts(event)
            out.emit_observations(
                event,
                rule,
                facts,
                exclusions={
                    name: "a synchronous self-quorum promotion later in the "
                    "same atomic election step changes this property."
                    for name in facts
                    if facts[name] != final.get(name)
                },
            )
        last = (nested or [head])[-1]
        last_facts = state_facts(last)
        committing = any(e.function == "commit" for e in tail)
        out.emit_observations(
            last,
            rule,
            last_facts,
            exclusions={
                name: "become_leader traces before its internal commit in the "
                "same atomic step; checked after the commit."
                for name in {
                    "commitIndex",
                    "role",
                    "configurations",
                    *retirement_fields,
                }
                if committing and name in last_facts
            },
        )
        emit_leader_tail(tail)
        for send in sends:
            out.emit_observations(send, "send-post")
            out.message(send, "send-post", receiving=False, selection="last")

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
            # The initial leader log already holds the bootstrap configuration,
            # so the empty-log events before it are validated but not replayed.
            # The bootstrap signature is one append batch; the lone leader
            # commits it inside the same step.
            out.emit_observations(prelude[3], "bootstrap")
            out.action(
                prelude[3],
                "append",
                "bootstrap",
                [prelude[3], prelude[4]],
                node=leader,
                entries=[{"kind": "signature"}],
            )
            emit_commit_tail([prelude[4]])

        elif peek(1) == ["replicate"]:
            # Every driver replicate writes exactly one entry, so each raw
            # replicate is one append batch of one entry. Its configuration
            # hook, new-peer heartbeats and lone-leader commit run inside it.
            (write,) = take()
            config = None
            if peek() == ["add_configuration"] and same_context(write, events[0]):
                (config,) = take()
                require(
                    config.state == write.state
                    and config.message["args"]["configuration"]["idx"]
                    == write.message["seqno"]
                    and write.message["globally_committable"] is False,
                    f"{write.location}: configuration write pair mismatch",
                )
            command = write.command.value["cmd"]
            transaction = f"{write.record.file}:{write.record.line}"
            if write.message["globally_committable"]:
                require(
                    config is None,
                    f"{write.location}: signature carrying a configuration",
                )
                entry: dict[str, Any] = {"kind": "signature"}
            elif config is not None:
                entry = {
                    "kind": "transaction",
                    "transaction": transaction,
                    "effects": [
                        {
                            "kind": "configuration",
                            "configuration": configuration(config),
                        }
                    ],
                }
            elif command.startswith("cleanup_nodes,"):
                # The replicate event does not carry the retired node set; the
                # driver command records it after the term.
                retired = sorted(
                    node(name, write.location) for name in command.split(",")[2:]
                )
                require(bool(retired), f"{write.location}: empty retirement record")
                entry = {
                    "kind": "transaction",
                    "transaction": transaction,
                    "effects": [{"kind": "retiredCommitted", "nodes": retired}],
                }
            else:
                entry = {
                    "kind": "transaction",
                    "transaction": transaction,
                    "effects": [],
                }
            out.emit_observations(write, "write-pre")
            callbacks: list[Event] = []
            if config is not None:
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
                    sorted(
                        node(c.message.get("to_node_id"), c.location) for c in callbacks
                    )
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
                            field: "The configuration hook already changed this property; observed after the append."
                            for field in retirement_fields
                        },
                    )
            tail = take_commit_tail(write)
            out.action(
                write,
                "append",
                "atomic-append",
                [write, *([config] if config else []), *callbacks, *tail],
                node=write.node,
                entries=[entry],
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
                out.message(callback, "send-post", receiving=False, selection="last")
            emit_commit_tail(tail)

        elif peek(1) == ["send_append_entries"]:
            (event,) = take()
            raw = event.message["packet"]
            # The model derives prev from sentIndex; only the endpoint is input.
            require(
                raw["prev_idx"] == event.message.get("sent_idx"),
                f"{event.location}: send prev_idx differs from sent_idx",
            )
            out.emit_observations(event, "send-pre")
            out.peers(event, "send-pre")
            out.action(
                event,
                "sendEntries",
                "atomic-send",
                source=event.node,
                destination=node(event.message.get("to_node_id"), event.location),
                endIndex=packet(event)["idx"],
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
                event.function
                in {"recv_propose_request_vote", "recv_request_vote_response"}
                and peek() == ["become_candidate"]
                and same_context(event, events[0])
            ):
                # Accepted proposals and pre-vote quorums enter the next term
                # inside the receive, with the whole election entry.
                callbacks = take()
                election = election_group(callbacks[0])
                callbacks += [*election[0], *election[2], *election[1]]
            elif (
                event.function == "recv_request_vote_response"
                and peek() == ["become_leader"]
                and same_context(event, events[0])
            ):
                # add_vote_for_me promotes inside the receive on a vote quorum.
                callbacks = take()
                election = ([], [], take_leader_tail(callbacks[0]))
                callbacks += election[2]
            elif event.function == "recv_append_entries_response":
                # A current-term ACK updates match_idx, then commits inside
                # the receive.
                callbacks = take_commit_tail(event)
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
            if callbacks and callbacks[0].function in {
                "become_candidate",
                "become_leader",
            }:
                nested, sends, tail = election
                emit_election(callbacks[0], nested, sends, tail, "receive-post")
                callbacks = []
            elif callbacks and event.function == "recv_append_entries_response":
                emit_commit_tail(callbacks)
                callbacks = []
            for position, callback in enumerate(callbacks):
                if callback.function in {
                    "send_append_entries_response",
                    "send_request_vote_response",
                }:
                    out.emit_observations(callback, "receive-post")
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
                            "kind": "transaction",
                            "configurations": [configuration(callback)],
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
                            {
                                "kind": "transaction",
                                "configurations": [config["nodes"]],
                            },
                            rule="callback-configuration",
                        )
                out.emit_observations(
                    callback, "tla-callback-stutter", facts, exclusions=exclusions
                )

        elif events[0].function in {"become_candidate", "become_pre_vote_candidate"}:
            (event,) = take()
            require(
                event.state["pre_vote_enabled"]
                == (event.function == "become_pre_vote_candidate"),
                f"{event.location}: election entry differs from pre-vote mode",
            )
            nested, sends, tail = election_group(event)
            out.action(
                event,
                "timeout",
                "atomic-election",
                [event, *nested, *tail, *sends],
                node=event.node,
                timeout="election",
            )
            emit_election(event, nested, sends, tail, "role-post")

        elif events[0].function == "become_follower":
            (event,) = take()
            out.action(
                event, "timeout", "role-post", node=event.node, timeout="checkQuorum"
            )
            out.emit_observations(event, "role-post")

        elif peek(1) == ["step_down_and_nominate_successor"]:
            (event,) = take()
            require(
                event.command.value["cmd"].startswith("nominate_successor,"),
                f"{event.location}: nomination outside a nominate_successor command",
            )
            out.emit_observations(event, "nomination")
            # The model chooses the successor itself; check the emitted one.
            out.action(
                event,
                "nominateSuccessor",
                "nomination",
                node=event.node,
                destination=node(event.message["to_node_id"], event.location),
            )
            out.message_propose(event, "nomination-message")

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
