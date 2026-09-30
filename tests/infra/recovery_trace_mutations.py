# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Mutation testing for the disaster-recovery trace validator.

Run from the repository root:

  python3 tests/infra/recovery_trace_mutations.py \
    lean/disaster-recovery/.lake/build/bin/disaster-recovery-replay \
    lean/disaster-recovery/replay/fixtures

The fixtures are trace-only log excerpts for the quorum, failover, and
multiple-timeout recovery-decision-protocol scenarios. The harness checks:

- baseline replay of each unmodified scenario
- curated targeted mutants with explicit pass/fail expectations
- a systematic sweep that perturbs one field of sampled records

Unexpected outcomes fail the script. Sweep mutants may pass only when they
match a small explicit allowlist of harmless, currently indistinguishable
classes.

Most mutants are declarative: a `select` finds one record and an `edit`
changes it. A few need bespoke functions: inserting or deleting records,
swapping sequences between records, relabeling a TxID everywhere it appears,
deleting whole batches, changing CLI arguments, or transforming a whole log.
"""

from __future__ import annotations

import collections
import copy
import json
import os
import pathlib
import random
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

MARK = "RDP_TRACE "
PHASES = ["Gossiping", "Voting", "Opening", "Joining", "Open"]
HANDLERS = {"gossip_accepted", "vote_accepted", "iamopen_accepted", "timeout"}

Target = tuple[int, int, dict]


def dump(record: dict[str, Any], sort: bool = True) -> str:
    return json.dumps(record, separators=(",", ":"), sort_keys=sort)


def load_scenario(path: pathlib.Path) -> dict[str, Any]:
    metadata = json.loads((path / "scenario.json").read_text(encoding="utf-8"))
    logs = []
    for log_path in sorted(path.glob("*.out")):
        entries = []
        with log_path.open(encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                index = line.find(MARK)
                if index < 0:
                    entries.append({"raw": line})
                    continue
                body = line[index + len(MARK) :]
                newline = ""
                if body.endswith("\n"):
                    body = body[:-1]
                    newline = "\n"
                record = json.loads(body)
                assert dump(record) == body, (log_path, body)
                entries.append(
                    {"prefix": line[: index + len(MARK)], "rec": record, "nl": newline}
                )
        logs.append(entries)
    return {
        "name": path.name,
        "participants": metadata["participants"],
        "open_kind": metadata["open_kind"],
        "logs": logs,
        "order": list(range(len(logs))),
        "detail": [],
    }


def render(entry: dict[str, Any]) -> str:
    if entry.get("deleted"):
        return ""
    if "raw" in entry:
        return entry["raw"]
    body = entry.get("body", dump(entry["rec"], entry.get("sort", True)))
    return entry["prefix"] + body + entry["nl"]


def recs(state: dict[str, Any]):
    for file_index, log in enumerate(state["logs"]):
        for entry_index, item in enumerate(log):
            if "rec" in item and not item.get("deleted"):
                yield file_index, entry_index, item["rec"]


def seqsorted(state: dict[str, Any]):
    return sorted(recs(state), key=lambda item: (item[0], item[2]["sequence"]))


def is_final(state: dict[str, Any], record: dict[str, Any]) -> bool:
    if "caused_by" not in record:
        return True
    same = [
        row["sequence"]
        for _, _, row in recs(state)
        if row["node"] == record["node"] and row.get("caused_by") == record["caused_by"]
    ]
    return record["sequence"] == max(same)


def find(
    state: dict[str, Any], predicate, nth: int = 0, final_only: bool = True
) -> Target | None:
    candidates = [
        item
        for item in seqsorted(state)
        if predicate(item[2]) and (not final_only or is_final(state, item[2]))
    ]
    return candidates[nth] if len(candidates) > nth else None


def find_any(state: dict[str, Any], *predicates, nth: int = 0) -> Target | None:
    for predicate in predicates:
        target = find(state, predicate, nth=nth)
        if target:
            return target
    return None


def locs(state: dict[str, Any]) -> list[str]:
    return next(recs(state))[2]["expected_locations"]


def nodes(state: dict[str, Any]) -> list[str]:
    return sorted({record["node"] for _, _, record in recs(state)})


def other(
    state: dict[str, Any], current: str, pool: list[str] | None = None
) -> str | None:
    values = pool or locs(state)
    for value in values:
        if value != current:
            return value
    return None


def by_id(state: dict[str, Any], cause_id: str) -> Target | None:
    node, sequence = cause_id.split(":")
    for file_index, entry_index, record in recs(state):
        if record["node"] == node and record["sequence"] == int(sequence):
            return file_index, entry_index, record
    return None


def referenced(state: dict[str, Any]) -> set[str]:
    return {
        record["caused_by"] for _, _, record in recs(state) if "caused_by" in record
    }


def bump(txid: str, delta: int = 1) -> str:
    view, seqno = txid.split(".")
    return f"{view}.{int(seqno) + delta}"


def txkey(txid: str, name: str) -> tuple[int, int, str]:
    view, seqno = txid.split(".")
    return int(view), int(seqno), name


def note(state: dict[str, Any], record: dict[str, Any], text: str) -> None:
    state["detail"].append(
        f"node {record['node']} seq {record['sequence']} ({record['kind']}): {text}"
    )


def entry(state: dict[str, Any], file_index: int, entry_index: int) -> dict[str, Any]:
    return state["logs"][file_index][entry_index]


# --- Declarative single-record mutants ----------------------------------
#
# Each row below finds one record with `select` and changes it with `edit`.
# `edit` mutates the record (or, for a self-delete, the log entry) in place
# and returns a description; returning None means the mutation is not
# applicable, like a missing `select` match.

Select = Callable[[dict], Target | None]
Edit = Callable[[dict, Target], str | None]


def set_field(record: dict[str, Any], field: str, value: Any) -> str:
    old = record.get(field, "<absent>")
    record[field] = value
    return f"{field} {json.dumps(old)} -> {json.dumps(value)}"


def del_field(record: dict[str, Any], field: str) -> str:
    old = record.pop(field)
    return f"{field} {json.dumps(old)} removed"


# --- Predicate and edit factories for the common "one field" mutants -----

kind_is = lambda *kinds: (lambda r: r["kind"] in kinds)
has = lambda field: (lambda r: field in r)
flag = lambda field: (lambda r: r.get(field) is True)
setf = lambda field, value: (lambda s, r: set_field(r, field, value))
delf = lambda field: (lambda s, r: del_field(r, field))
bumpf = lambda field, delta: (lambda s, r: set_field(r, field, r[field] + delta))
flipf = lambda field, mapping: (lambda s, r: set_field(r, field, mapping[r[field]]))
relabel = lambda field: (lambda s, r: set_field(r, field, other(s, r[field])))
copyf = lambda dst, src: (lambda s, r: set_field(r, dst, r[src]))
dynf = lambda field, fn: (lambda s, r: set_field(r, field, fn(r)))


def self_delete(state: dict[str, Any], target: Target, text: str) -> str:
    entry(state, target[0], target[1])["deleted"] = True
    return text


def record_mutant(select: Select, edit: Edit) -> Callable[[dict], bool]:
    def mutant(state: dict[str, Any]) -> bool:
        target = select(state)
        if not target:
            return False
        description = edit(state, target)
        if description is None:
            return False
        note(state, target[2], description)
        return True

    return mutant


def simple(predicate, edit, nth: int = 0) -> Callable[[dict], bool]:
    """A mutant that finds one record by predicate and edits it in place."""
    return record_mutant(
        lambda s: find(s, predicate, nth=nth), lambda s, t: edit(s, t[2])
    )


def fallback(predicates, edit) -> Callable[[dict], bool]:
    """A mutant that edits the first record matched by any predicate, in order."""
    return record_mutant(lambda s: find_any(s, *predicates), lambda s, t: edit(s, t[2]))


def _to_voting(record: dict[str, Any]) -> bool:
    return (
        record["kind"] in HANDLERS
        and record["pre"] == "Gossiping"
        and record["post"] == "Voting"
        and "chosen" in record
    )


def _edit_open_without_quorum(state: dict[str, Any], record: dict[str, Any]) -> str:
    kept = (
        [record["source"]]
        if record.get("source") in record["votes"]
        else record["votes"][:1]
    )
    return set_field(record, "votes", kept) + " (still opens Quorum)"


def _edit_no_advance(state: dict[str, Any], record: dict[str, Any]) -> str:
    record["post"] = "Gossiping"
    return del_field(record, "chosen") + ", post -> Gossiping"


def _edit_premature_voting(state: dict[str, Any], record: dict[str, Any]) -> str:
    chosen = max(record["gossips"].items(), key=lambda item: txkey(item[1], item[0]))[0]
    set_field(record, "post", "Voting")
    return (
        set_field(record, "chosen", chosen) + f" with {len(record['gossips'])} gossips"
    )


def _edit_vote_to_non_chosen(state: dict[str, Any], record: dict[str, Any]) -> str:
    original = record["send"].split(":", 1)[1]
    return set_field(record, "send", f"vote:{other(state, original)}")


def _edit_timeout_phase_skip(state: dict[str, Any], record: dict[str, Any]) -> str:
    index = PHASES.index(record["post_timeout"])
    candidate = PHASES[min(index + 1, 2)]
    new = candidate if candidate != record["post_timeout"] else "Joining"
    return set_field(record, "post_timeout", new)


def _edit_failover_without_valid_timeout(
    state: dict[str, Any], record: dict[str, Any]
) -> str:
    new = "Gossiping" if record["pre_timeout"] != "Gossiping" else "Opening"
    return set_field(record, "pre_timeout", new)


def _edit_set_chain_off(state: dict[str, Any], record: dict[str, Any]) -> str:
    txid = record["gossips"][record["source"]]
    missing = [v for v in record["expected_locations"] if v not in record["gossips"]]
    dropped = next(v for v in record["gossips"] if v != record["source"])
    new = {k: v for k, v in record["gossips"].items() if k != dropped} | {
        missing[0]: txid
    }
    return set_field(record, "gossips", new) + " (a set off the chain)"


def _edit_truncated_json(state: dict[str, Any], target: Target) -> str:
    file_index, entry_index, record = target
    body = dump(record)
    entry(state, file_index, entry_index)["body"] = body[: len(body) // 2]
    return "JSON truncated"


def _select_participation_drop(state: dict[str, Any]) -> Target | None:
    return find(
        state, lambda r: r["kind"] == "committed" and r["node"] == nodes(state)[-1]
    )


def _select_retry_bad_version(state: dict[str, Any]) -> Target | None:
    first_send = find(state, lambda r: r["kind"] == "send", nth=0)
    if not first_send:
        return None
    first = first_send[2]["pre_version"]
    return find(state, lambda r: r["kind"] == "send" and r["pre_version"] != first)


def _select_delete_unreceived_send(state: dict[str, Any]) -> Target | None:
    refs = referenced(state)
    batches = collections.Counter(
        (record["node"], record["batch"])
        for _, _, record in recs(state)
        if record["kind"] == "send"
    )
    for target in seqsorted(state):
        record = target[2]
        if (
            record["kind"] == "send"
            and f"{record['node']}:{record['sequence']}" not in refs
            and batches[(record["node"], record["batch"])] > 1
        ):
            return target
    return None


def _edit_delete_unreceived_send(state: dict[str, Any], target: Target) -> str:
    record = target[2]
    count = sum(
        1
        for _, _, other_record in recs(state)
        if other_record["kind"] == "send"
        and other_record["node"] == record["node"]
        and other_record["batch"] == record["batch"]
    )
    return self_delete(
        state,
        target,
        f"deleted one unreceived send ({record['send']}) of a batch of {count}",
    )


def _multi_attempt(state: dict[str, Any]):
    groups = collections.defaultdict(list)
    for file_index, entry_index, record in recs(state):
        if "caused_by" in record:
            groups[(record["node"], record["caused_by"])].append(
                (file_index, entry_index, record)
            )
    for _, values in sorted(groups.items()):
        if len(values) > 1:
            values.sort(key=lambda item: item[2]["sequence"])
            return values
    return None


def _select_rolled_back(state: dict[str, Any]) -> Target | None:
    attempts = _multi_attempt(state)
    return attempts[0] if attempts else None


def _edit_rolled_back(state: dict[str, Any], target: Target) -> str:
    record = target[2]
    before = record["post"]
    record["post"] = "Opening" if record["post"] != "Opening" else "Voting"
    if record["post"] == "Opening":
        record["open_kind"] = "Quorum"
    return f"superseded attempt: post {before} -> {record['post']}"


def m_committed_version_within_newest_pair(state: dict[str, Any]) -> bool:
    """
    The committed record for the newest pair's writer must be higher than
    both versions of that pair, since the writer read that pair. Lowering it
    to a version still inside the pair must fail even though it stays above
    every earlier known committed version.
    """
    for node in nodes(state):
        handlers = [
            rec
            for _, _, rec in recs(state)
            if rec["node"] == node and rec["kind"] in HANDLERS
        ]
        committed = [
            (file_index, entry_index, rec)
            for file_index, entry_index, rec in recs(state)
            if rec["node"] == node and rec["kind"] == "committed"
        ]
        if not handlers or not committed:
            continue
        newest = max(
            max(rec["pre_version"], rec["pre_timeout_version"]) for rec in handlers
        )
        lowest = min(
            min(rec["pre_version"], rec["pre_timeout_version"])
            for rec in handlers
            if max(rec["pre_version"], rec["pre_timeout_version"]) == newest
        )
        if newest - lowest < 2:
            continue
        target = max(committed, key=lambda item: item[2]["sequence"])
        if target[2]["version"] <= newest:
            continue
        new_version = (lowest + newest) // 2
        if new_version <= lowest or new_version >= newest:
            continue
        note(
            state,
            target[2],
            f"version {target[2]['version']} -> {new_version} (inside the newest pair {(lowest, newest)})",
        )
        target[2]["version"] = new_version
        return True
    return False


# --- Bespoke mutants: cross-record edits, insertions, deletions, whole-log
# transforms and CLI argument changes -------------------------------------


def m_txid_lie_send_only(state: dict[str, Any]) -> bool:
    target = find(
        state,
        lambda record: record["kind"] == "gossip_accepted"
        and record["source"] != record["node"]
        and by_id(state, record["caused_by"]) is not None,
    )
    if not target:
        target = find(
            state,
            lambda record: record["kind"] == "gossip_accepted"
            and by_id(state, record["caused_by"]) is not None,
        )
    if not target:
        return False
    send = by_id(state, target[2]["caused_by"])[2]
    note(
        state,
        send,
        f"send txid {send['txid']} -> {bump(send['txid'])} (receiver unchanged)",
    )
    send["txid"] = bump(send["txid"])
    return True


def _set_txid_everywhere(state: dict[str, Any], name: str, new: str) -> None:
    for _, _, record in recs(state):
        if record["kind"] == "send" and record["node"] == name and "txid" in record:
            record["txid"] = new
        if record["kind"] == "gossip_accepted" and record.get("source") == name:
            record["txid"] = new
        if name in record.get("gossips", {}):
            record["gossips"][name] = new


def _txids(state: dict[str, Any]) -> dict[str, str]:
    txids = {}
    for _, _, record in recs(state):
        if record["kind"] == "send" and "txid" in record:
            txids[record["node"]] = record["txid"]
    return txids


def m_txid_raise_consistent(state: dict[str, Any]) -> bool:
    chosen = {record["chosen"] for _, _, record in recs(state) if "chosen" in record}
    txids = _txids(state)
    candidates = [name for name in txids if name not in chosen]
    if not candidates or not chosen:
        return False
    name = candidates[0]
    top = max(txkey(value, node) for node, value in txids.items())
    new = f"{top[0]}.{top[1] + 77}"
    state["detail"].append(
        f"node {name} recovered TxID {txids[name]} -> {new} in every send, receive and gossips map"
    )
    _set_txid_everywhere(state, name, new)
    return True


def m_txid_lower_consistent(state: dict[str, Any]) -> bool:
    chosen = {record["chosen"] for _, _, record in recs(state) if "chosen" in record}
    txids = _txids(state)
    candidates = [
        name
        for name in txids
        if name not in chosen and int(txids[name].split(".")[1]) > 0
    ]
    if not candidates or not chosen:
        return False
    name = candidates[0]
    new = bump(txids[name], -1)
    state["detail"].append(
        f"node {name} recovered TxID {txids[name]} -> {new} in every send, receive and gossips map"
    )
    _set_txid_everywhere(state, name, new)
    return True


def m_caused_by_other_kind(state: dict[str, Any]) -> bool:
    target = find(state, lambda record: record["kind"] == "vote_accepted")
    if not target:
        return False
    record = target[2]
    source = record["caused_by"].split(":")[0]
    gossip = find(
        state,
        lambda row: row["kind"] == "send"
        and row["node"] == source
        and row["send"].startswith("gossip:"),
        final_only=False,
    )
    if not gossip:
        return False
    new = f"{source}:{gossip[2]['sequence']}"
    note(state, record, f"caused_by {record['caused_by']} -> {new} (a gossip send)")
    record["caused_by"] = new
    return True


def m_drop_received_send(state: dict[str, Any]) -> bool:
    target = find(
        state,
        lambda record: record["kind"] == "gossip_accepted"
        and by_id(state, record["caused_by"]) is not None,
    )
    if not target:
        return False
    file_index, entry_index, send = by_id(state, target[2]["caused_by"])
    note(
        state,
        send,
        f"send record deleted (received by node {target[2]['node']} seq {target[2]['sequence']})",
    )
    entry(state, file_index, entry_index)["deleted"] = True
    return True


def m_receive_before_send(state: dict[str, Any]) -> bool:
    target = find(
        state,
        lambda record: record["kind"] == "gossip_accepted"
        and record["caused_by"].split(":")[0] == record["node"]
        and by_id(state, record["caused_by"]) is not None,
    )
    if not target:
        return False
    record = target[2]
    send = by_id(state, record["caused_by"])[2]
    receive_sequence, send_sequence = record["sequence"], send["sequence"]
    note(
        state,
        record,
        f"swapped sequence with its own send {record['node']}:{send_sequence}, so the receive comes first",
    )
    record["sequence"], send["sequence"] = send_sequence, receive_sequence
    record["caused_by"] = f"{record['node']}:{receive_sequence}"
    return True


def m_redirect_to_identical_copy(state: dict[str, Any]) -> bool:
    refs = referenced(state)
    for _, _, record in seqsorted(state):
        if (
            record["kind"] != "gossip_accepted"
            or record["source"] == record["node"]
            or not is_final(state, record)
        ):
            continue
        send = by_id(state, record["caused_by"])
        if not send:
            continue
        send_record = send[2]
        for _, _, copy_record in seqsorted(state):
            if (
                copy_record["kind"] == "send"
                and copy_record["node"] == send_record["node"]
                and copy_record["send"] == send_record["send"]
                and copy_record.get("txid") == send_record.get("txid")
                and copy_record["sequence"] < send_record["sequence"]
                and f"{copy_record['node']}:{copy_record['sequence']}" not in refs
            ):
                new = f"{copy_record['node']}:{copy_record['sequence']}"
                note(
                    state,
                    record,
                    f"caused_by {record['caused_by']} -> {new} (an identical, unreceived copy)",
                )
                record["caused_by"] = new
                return True
    return False


def m_extra_final_attempt(state: dict[str, Any]) -> bool:
    target = find(state, lambda record: "open_kind" in record and "caused_by" in record)
    if not target:
        return False
    file_index, entry_index, record = target
    node_max = max(
        row["sequence"] for _, _, row in recs(state) if row["node"] == record["node"]
    )
    duplicate = copy.deepcopy(record)
    duplicate["sequence"] = node_max + 1
    duplicate["post"] = duplicate["pre"]
    duplicate.pop("open_kind")
    current = entry(state, file_index, entry_index)
    state["logs"][file_index].append(
        {"prefix": current["prefix"], "rec": duplicate, "nl": "\n"}
    )
    note(
        state,
        record,
        f"added a later attempt {record['node']}:{duplicate['sequence']} of {record['caused_by']} that does not open",
    )
    return True


def m_failed_to_trace_line(state: dict[str, Any]) -> bool:
    log = state["logs"][0]
    log.insert(
        len(log) // 2,
        {
            "raw": "2026-09-30T07:50:00.000000Z 1   [fail ] de/recovery_decision_protocol.cpp:60 | Failed to trace recovery-decision-protocol send: injected\n"
        },
    )
    state["detail"].append(
        "inserted a 'Failed to trace recovery-decision-protocol' line into the first log"
    )
    return True


def _delete_unreceived_batch(state: dict[str, Any], tail: bool) -> bool:
    refs = referenced(state)
    groups = collections.defaultdict(list)
    per_node_max = collections.defaultdict(int)
    for file_index, entry_index, record in recs(state):
        if record["kind"] == "send":
            groups[(record["node"], record["batch"])].append(
                (file_index, entry_index, record)
            )
        per_node_max[record["node"]] = max(
            per_node_max[record["node"]], record["sequence"]
        )
    for (node, batch), rows in sorted(
        groups.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        if not all(
            f"{record['node']}:{record['sequence']}" not in refs
            for _, _, record in rows
        ):
            continue
        highest = max(record["sequence"] for _, _, record in rows)
        is_tail = highest == per_node_max[node]
        if is_tail != tail:
            continue
        for file_index, entry_index, _ in rows:
            entry(state, file_index, entry_index)["deleted"] = True
        label = "tail" if tail else "middle"
        state["detail"].append(
            f"node {node}: deleted all {len(rows)} sends of {label} batch {batch}, none received"
        )
        return True
    return False


def m_delete_middle_unreceived_batch(state: dict[str, Any]) -> bool:
    return _delete_unreceived_batch(state, tail=False)


def m_delete_tail_unreceived_batch(state: dict[str, Any]) -> bool:
    return _delete_unreceived_batch(state, tail=True)


def m_truncate_opener_after_voting(state: dict[str, Any]) -> bool:
    target = find(state, lambda record: "open_kind" in record)
    if not target:
        return False
    opener = target[2]["node"]
    committed = find(
        state,
        lambda record: record["kind"] == "committed"
        and record["node"] == opener
        and record["post"] == "Voting",
    )
    if not committed:
        return False
    cut = committed[2]["sequence"]
    deleted = 0
    for file_index, entry_index, record in recs(state):
        if record["node"] == opener and record["sequence"] > cut:
            entry(state, file_index, entry_index)["deleted"] = True
            deleted += 1
    state["detail"].append(
        f"node {opener}: deleted its {deleted} records after committing Voting"
    )
    return True


def m_wrong_open_kind_arg(state: dict[str, Any]) -> bool:
    state["open_kind"] = "FAILOVER" if state["open_kind"] == "QUORUM" else "QUORUM"
    state["detail"].append(f"--open-kind {state['open_kind']}")
    return True


def m_wrong_participants_arg(state: dict[str, Any]) -> bool:
    state["participants"] = (
        state["participants"] - 1 if state["participants"] > 1 else 2
    )
    state["detail"].append(f"--participants {state['participants']}")
    return True


def m_missing_log_file(state: dict[str, Any]) -> bool:
    if len(state["order"]) < 2:
        return False
    dropped = state["order"].pop()
    state["detail"].append(f"log {dropped} not passed, --participants unchanged")
    return True


def m_shuffle_trace_lines(state: dict[str, Any]) -> bool:
    rng = random.Random(8282)
    for log in state["logs"]:
        indices = [index for index, item in enumerate(log) if "rec" in item]
        values = [log[index] for index in indices]
        rng.shuffle(values)
        for index, value in zip(indices, values):
            log[index] = value
    state["detail"].append("shuffled the order of trace lines within each log")
    return True


def m_strip_non_trace_lines(state: dict[str, Any]) -> bool:
    for log in state["logs"]:
        log[:] = [item for item in log if "rec" in item]
    state["detail"].append("removed every non-trace line")
    return True


def m_reverse_key_order(state: dict[str, Any]) -> bool:
    for log in state["logs"]:
        for item in log:
            if "rec" in item:
                item["body"] = json.dumps(
                    dict(sorted(item["rec"].items(), reverse=True)),
                    separators=(",", ":"),
                )
    state["detail"].append("reversed the JSON key order of every record")
    return True


def m_log_order_permuted(state: dict[str, Any]) -> bool:
    if len(state["order"]) < 2:
        return False
    state["order"].reverse()
    state["detail"].append("logs passed in reverse order")
    return True


_OPEN_KINDS = {"Quorum": "Failover", "Failover": "Quorum"}

MUTANTS = [
    (
        "decision/open_kind_flip/FAIL",
        simple(has("open_kind"), flipf("open_kind", _OPEN_KINDS)),
    ),
    (
        "decision/open_without_quorum/FAIL",
        simple(
            lambda r: r.get("open_kind") == "Quorum" and len(r.get("votes", [])) > 1,
            _edit_open_without_quorum,
        ),
    ),
    ("decision/chosen_not_max/FAIL", simple(_to_voting, relabel("chosen"))),
    ("decision/skip_to_opening/FAIL", simple(_to_voting, setf("post", "Opening"))),
    ("decision/no_advance_on_full_gossips/FAIL", simple(_to_voting, _edit_no_advance)),
    (
        "decision/premature_voting/FAIL",
        simple(
            lambda r: r["kind"] == "gossip_accepted"
            and r["pre"] == r["post"] == "Gossiping"
            and len(r["gossips"]) < len(r["expected_locations"]),
            _edit_premature_voting,
        ),
    ),
    ("decision/drop_restart/FAIL", simple(flag("restart"), delf("restart"))),
    (
        "decision/add_restart/FAIL",
        simple(kind_is("gossip_accepted"), setf("restart", True)),
    ),
    (
        "decision/vote_to_non_chosen/FAIL",
        simple(
            lambda r: r["kind"] == "send" and r["send"].startswith("vote:"),
            _edit_vote_to_non_chosen,
        ),
    ),
    (
        "decision/timeout_phase_skip/FAIL",
        simple(
            lambda r: r["kind"] == "timeout" and r["post_timeout"] != r["pre_timeout"],
            _edit_timeout_phase_skip,
        ),
    ),
    (
        "decision/timeout_no_advance/FAIL",
        simple(
            lambda r: r["kind"] == "timeout" and r["post_timeout"] != r["pre_timeout"],
            copyf("post_timeout", "pre_timeout"),
        ),
    ),
    (
        "decision/failover_without_valid_timeout/FAIL",
        simple(
            lambda r: r.get("open_kind") == "Failover",
            _edit_failover_without_valid_timeout,
        ),
    ),
    ("decision/txid_lie_send_only/FAIL", m_txid_lie_send_only),
    ("decision/txid_raise_consistent/FAIL", m_txid_raise_consistent),
    ("decision/txid_lower_consistent/PASS", m_txid_lower_consistent),
    (
        "causality/dangling_caused_by/FAIL",
        simple(
            kind_is("gossip_accepted"),
            dynf("caused_by", lambda r: f"{r['source']}:99999"),
        ),
    ),
    ("causality/caused_by_other_kind/FAIL", m_caused_by_other_kind),
    (
        "causality/source_mismatch/FAIL",
        fallback(
            [
                lambda r: r["kind"] == "gossip_accepted" and r["source"] != r["node"],
                kind_is("gossip_accepted"),
            ],
            relabel("source"),
        ),
    ),
    ("causality/drop_received_send/FAIL", m_drop_received_send),
    ("causality/receive_before_send/FAIL", m_receive_before_send),
    (
        "causality/timeout_dangling/FAIL",
        simple(
            lambda r: r["kind"] == "timeout" and "caused_by" in r,
            dynf("caused_by", lambda r: f"{r['node']}:99999"),
        ),
    ),
    (
        "commit-order/participation_drop/FAIL",
        record_mutant(
            _select_participation_drop,
            lambda s, t: self_delete(s, t, "first committed record deleted"),
        ),
    ),
    (
        "commit-order/participation_version/FAIL",
        simple(kind_is("committed"), bumpf("version", 1)),
    ),
    (
        "commit-order/segment_bad_pre_version/FAIL",
        simple(kind_is("gossip_accepted"), bumpf("pre_version", 100), nth=1),
    ),
    (
        "commit-order/committed_version_shift/FAIL",
        simple(
            lambda r: r["kind"] == "committed" and r["post"] != "Gossiping",
            bumpf("version", 1),
        ),
    ),
    (
        "commit-order/committed_version_within_newest_pair/FAIL",
        m_committed_version_within_newest_pair,
    ),
    (
        "commit-order/committed_phase_lie/FAIL",
        simple(
            lambda r: r["kind"] == "committed" and r["post"] == "Voting",
            setf("post", "Opening"),
        ),
    ),
    (
        "commit-order/set_chain_off/FAIL",
        simple(
            lambda r: r["kind"] == "gossip_accepted"
            and r["post"] == "Gossiping"
            and 1 < len(r["gossips"]) < len(r["expected_locations"]),
            _edit_set_chain_off,
        ),
    ),
    (
        "commit-order/retry_bad_version/FAIL",
        record_mutant(
            _select_retry_bad_version,
            lambda s, t: set_field(t[2], "pre_version", t[2]["pre_version"] + 100),
        ),
    ),
    (
        "commit-order/rolled_back_mutation/FAIL",
        record_mutant(_select_rolled_back, _edit_rolled_back),
    ),
    ("commit-order/extra_final_attempt/FAIL", m_extra_final_attempt),
    ("commit-order/failed_to_trace_line/FAIL", m_failed_to_trace_line),
    (
        "format/truncated_json/FAIL",
        record_mutant(
            lambda s: find(s, kind_is("gossip_accepted")), _edit_truncated_json
        ),
    ),
    ("format/missing_pre/FAIL", simple(kind_is(*HANDLERS), delf("pre"))),
    ("format/unknown_kind/FAIL", simple(kind_is("send"), setf("kind", "bogus"))),
    (
        "format/expected_locations_changed/FAIL",
        simple(
            kind_is("gossip_accepted"),
            dynf("expected_locations", lambda r: r["expected_locations"][:-1]),
        ),
    ),
    ("format/node_misattributed/FAIL", simple(kind_is(*HANDLERS), relabel("node"))),
    (
        "format/duplicate_sequence/FAIL",
        simple(kind_is("send"), bumpf("sequence", -1), nth=1),
    ),
    (
        "format/delete_unreceived_send/FAIL",
        record_mutant(_select_delete_unreceived_send, _edit_delete_unreceived_send),
    ),
    ("format/delete_middle_unreceived_batch/FAIL", m_delete_middle_unreceived_batch),
    ("format/delete_tail_unreceived_batch/PASS", m_delete_tail_unreceived_batch),
    ("format/truncate_opener_after_voting/FAIL", m_truncate_opener_after_voting),
    ("args/wrong_open_kind_arg/FAIL", m_wrong_open_kind_arg),
    ("args/wrong_participants_arg/FAIL", m_wrong_participants_arg),
    ("args/missing_log_file/FAIL", m_missing_log_file),
    ("benign/shuffle_trace_lines/PASS", m_shuffle_trace_lines),
    ("benign/strip_non_trace_lines/PASS", m_strip_non_trace_lines),
    ("benign/reverse_key_order/PASS", m_reverse_key_order),
    ("benign/log_order_permuted/PASS", m_log_order_permuted),
    ("benign/identical_unreceived_copy/PASS", m_redirect_to_identical_copy),
]


# --- Systematic sweep: perturb one field of each sampled record ----------

KIND_SWAP = {
    "gossip_accepted": "vote_accepted",
    "vote_accepted": "gossip_accepted",
    "iamopen_accepted": "vote_accepted",
    "timeout": "vote_accepted",
    "send": "timeout_request",
    "timeout_request": "send",
    "committed": "timeout_request",
}


def perturb(state: dict[str, Any], record: dict[str, Any], field: str) -> str | None:
    value = record[field]
    if field in ("pre", "post", "pre_timeout", "post_timeout"):
        record[field] = PHASES[(PHASES.index(value) + 1) % len(PHASES)]
    elif field in ("version", "pre_version", "pre_timeout_version", "batch"):
        record[field] = value + 1
    elif field == "sequence":
        record[field] = value + 1000
    elif field == "caused_by":
        node, sequence = value.split(":")
        record[field] = f"{node}:{int(sequence) + 1}"
    elif field in ("source", "node", "chosen"):
        record[field] = other(state, value)
    elif field == "txid":
        record[field] = bump(value)
    elif field == "gossips":
        if len(value) > 1:
            value.pop(min(value))
        else:
            key = next(iter(value))
            value[key] = bump(value[key])
    elif field == "votes":
        if len(value) > 1:
            record[field] = value[1:]
        else:
            record[field] = sorted(set(value) | {other(state, value[0])})
    elif field == "open_kind":
        record[field] = "Failover" if value == "Quorum" else "Quorum"
    elif field == "restart":
        del record[field]
    elif field == "send":
        message, target = value.split(":", 1)
        record[field] = f"{message}:{other(state, target)}"
    elif field == "expected_locations":
        record[field] = value[:-1]
    elif field == "kind":
        record[field] = KIND_SWAP[value]
    else:
        return None
    old = "..." if field == "gossips" else json.dumps(value)
    new = json.dumps(record.get(field, "<removed>"))
    return f"{field}: {old} -> {new}"


def sweep_specs(base: dict[str, Any]):
    by_kind = collections.defaultdict(list)
    for file_index, entry_index, record in seqsorted(base):
        if is_final(base, record):
            by_kind[record["kind"]].append((file_index, entry_index))
    for kind, rows in sorted(by_kind.items()):
        for position in sorted({0, len(rows) // 2, len(rows) - 1}):
            file_index, entry_index = rows[position]
            for field in sorted(base["logs"][file_index][entry_index]["rec"]):
                yield kind, field, position, file_index, entry_index


ALLOW_SWEEP = [
    {
        "name": "latest-commit-version",
        "pattern": re.compile(r"^committed\.version#7$"),
        "scenarios": {"quorum"},
        "reason": "The newest committed sm_state version has no later reader, so the trace alone does not constrain its exact number.",
    },
    {
        "name": "unread-timeout-version",
        "pattern": re.compile(r"^timeout\.pre_timeout_version#[12]$"),
        "scenarios": {"quorum"},
        "reason": "The mutated timeout_sm_state version is read only by that one execution, so no other record can distinguish it.",
    },
]


def allow_sweep(result: dict[str, Any]) -> tuple[str, str] | None:
    for entry in ALLOW_SWEEP:
        if result["scenario"] in entry["scenarios"] and entry["pattern"].match(
            result["name"]
        ):
            return entry["name"], entry["reason"]
    return None


def classify(returncode: int, output: str) -> str:
    if returncode == 0:
        return "PASS"
    if returncode == 2:
        return "USAGE"
    if "timed out waiting for a complete recovery trace" in output:
        return "FAIL:incomplete"
    if "reduction failed:" in output:
        return "FAIL:invalid"
    if "replay failed:" in output:
        return "FAIL:replay"
    if "scenario failed" in output:
        return "FAIL:scenario"
    return f"OTHER(rc={returncode})"


def run_mutant(
    mutant_id: str,
    state: dict[str, Any],
    replayer: pathlib.Path,
    work_dir: pathlib.Path,
) -> tuple[str, str]:
    case_dir = work_dir / mutant_id.replace("/", "__")
    case_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for index in state["order"]:
        path = case_dir / f"{index}.out"
        path.write_text(
            "".join(render(item) for item in state["logs"][index]), encoding="utf-8"
        )
        files.append(str(path))
    command = [
        str(replayer),
        "--participants",
        str(state["participants"]),
        "--open-kind",
        state["open_kind"],
        "--wait-ms",
        "0",
        *files,
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=90, check=False
        )
        output = (completed.stdout + completed.stderr).strip()
        return classify(completed.returncode, output), output
    except subprocess.TimeoutExpired:
        return "OTHER(rc=-1)", "harness timeout"


def build_jobs(scenarios: dict[str, Any]):
    jobs = []
    for name, base in scenarios.items():
        jobs.append(("baseline", name, "baseline", "PASS", copy.deepcopy(base)))
        for spec, fn in MUTANTS:
            group, mutant_name, expected = spec.split("/")
            state = copy.deepcopy(base)
            if fn(state):
                jobs.append((group, name, mutant_name, expected, state))
        for kind, field, position, file_index, entry_index in sweep_specs(base):
            state = copy.deepcopy(base)
            record = state["logs"][file_index][entry_index]["rec"]
            ident = f"node {record['node']} seq {record['sequence']} ({kind})"
            change = perturb(state, record, field)
            if change is None:
                continue
            state["detail"].append(f"{ident}: {change}")
            jobs.append(("sweep", name, f"{kind}.{field}#{position}", "?", state))
    return jobs


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} REPLAYER FIXTURES_DIR", file=sys.stderr)
        return 2
    replayer = pathlib.Path(sys.argv[1])
    fixtures_dir = pathlib.Path(sys.argv[2])

    scenarios = {
        path.name: load_scenario(path)
        for path in sorted(fixtures_dir.iterdir())
        if path.is_dir() and (path / "scenario.json").exists()
    }
    if not scenarios:
        raise SystemExit(f"no scenarios found under {fixtures_dir}")

    jobs = build_jobs(scenarios)

    with tempfile.TemporaryDirectory() as work_dir_name:
        work_dir = pathlib.Path(work_dir_name)

        def work(job):
            group, scenario, mutant_name, expected, state = job
            outcome, output = run_mutant(
                f"{scenario}/{group}/{mutant_name}", state, replayer, work_dir
            )
            result = {
                "group": group,
                "scenario": scenario,
                "name": mutant_name,
                "expected": expected,
                "outcome": outcome,
                "detail": "; ".join(state["detail"]),
                "message": output.splitlines()[-1][:300] if output else "",
            }
            allowed = (
                allow_sweep(result) if group == "sweep" and outcome == "PASS" else None
            )
            if allowed is not None:
                result["allowlist"] = {"name": allowed[0], "reason": allowed[1]}
            return result

        with ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as executor:
            results = list(executor.map(work, jobs))

    unexpected = []
    for result in results:
        if result["group"] == "sweep":
            if result["outcome"] == "PASS" and "allowlist" not in result:
                unexpected.append(result)
            continue
        expected = result["expected"]
        if (
            expected == "PASS"
            and result["outcome"] != "PASS"
            or expected == "FAIL"
            and result["outcome"] == "PASS"
        ):
            unexpected.append(result)

    curated = [
        row
        for row in results
        if row["group"] != "sweep" and row["expected"] in {"PASS", "FAIL"}
    ]
    curated_ok = sum(
        (row["expected"] == "PASS" and row["outcome"] == "PASS")
        or (row["expected"] == "FAIL" and row["outcome"] != "PASS")
        for row in curated
    )
    sweep = [row for row in results if row["group"] == "sweep"]
    sweep_caught = sum(row["outcome"] != "PASS" for row in sweep)
    sweep_allowed = [row for row in sweep if row.get("allowlist")]

    print(f"Curated mutants: {curated_ok}/{len(curated)} matched expectation")
    print(
        f"Sweep mutants: {sweep_caught}/{len(sweep)} caught, {len(sweep_allowed)} allowlisted harmless pass(es)"
    )
    if sweep_allowed:
        print("Allowlisted sweep classes:")
        seen = set()
        for row in sweep_allowed:
            key = (row["allowlist"]["name"], row["allowlist"]["reason"])
            if key in seen:
                continue
            seen.add(key)
            print(f"- {key[0]}: {key[1]}")

    if unexpected:
        print("Unexpected mutation outcomes:", file=sys.stderr)
        for row in unexpected:
            expected = row["expected"]
            print(
                f"- {row['scenario']} {row['group']} {row['name']}: expected {expected}, got {row['outcome']}\n"
                f"  detail: {row['detail']}\n"
                f"  message: {row['message']}",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
