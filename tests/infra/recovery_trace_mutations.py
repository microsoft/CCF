# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Mutation testing for the disaster-recovery trace validator.

Run: python3 tests/infra/recovery_trace_mutations.py REPLAYER FIXTURES_DIR

The fixtures are trace-only log excerpts for the quorum, failover, and
multiple-timeout recovery-decision-protocol scenarios. The harness checks
baseline replay, curated mutants grouped by kind with explicit pass/fail
expectations, and a systematic sweep that perturbs one field of sampled
records. Unexpected outcomes fail the script; sweep mutants may pass only
when they match a small explicit allowlist of harmless, currently
indistinguishable classes.
"""

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
from concurrent.futures import ThreadPoolExecutor
from typing import Any, NamedTuple

MARK = "RDP_TRACE "
PHASES = ["Gossiping", "Voting", "Opening", "Joining", "Open"]
HANDLERS = {"gossip_accepted", "vote_accepted", "iamopen_accepted", "timeout"}
PASS, FAIL = "PASS", "FAIL"
FAILED_TO_TRACE_LINE = (
    "2026-09-30T07:50:00.000000Z 1   [fail ] de/recovery_decision_protocol.cpp:60"
    " | Failed to trace recovery-decision-protocol send: injected\n"
)


def dump(record: dict, sort: bool = True) -> str:
    return json.dumps(record, separators=(",", ":"), sort_keys=sort)


def load_scenario(path: pathlib.Path) -> dict:
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
                    body, newline = body[:-1], "\n"
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
    }


def render(item: dict) -> str:
    if item.get("deleted"):
        return ""
    if "raw" in item:
        return item["raw"]
    body = item.get("body", dump(item["rec"], item.get("sort", True)))
    return item["prefix"] + body + item["nl"]


def recs(state: dict):
    for file_index, log in enumerate(state["logs"]):
        for entry_index, item in enumerate(log):
            if "rec" in item and not item.get("deleted"):
                yield file_index, entry_index, item["rec"]


def seqsorted(state: dict):
    return sorted(recs(state), key=lambda item: (item[0], item[2]["sequence"]))


def is_final(state: dict, record: dict) -> bool:
    if "caused_by" not in record:
        return True
    same = [
        row["sequence"]
        for _, _, row in recs(state)
        if row["node"] == record["node"] and row.get("caused_by") == record["caused_by"]
    ]
    return record["sequence"] == max(same)


def find(state: dict, predicate, nth: int = 0, final_only: bool = True):
    candidates = [
        item
        for item in seqsorted(state)
        if predicate(item[2]) and (not final_only or is_final(state, item[2]))
    ]
    return candidates[nth] if len(candidates) > nth else None


def locs(state: dict) -> list:
    return next(recs(state))[2]["expected_locations"]


def nodes(state: dict) -> list:
    return sorted({record["node"] for _, _, record in recs(state)})


def other(state: dict, current: str, pool=None):
    for value in pool or locs(state):
        if value != current:
            return value
    return None


def by_id(state: dict, cause_id: str):
    node, sequence = cause_id.split(":")
    for file_index, entry_index, record in recs(state):
        if record["node"] == node and record["sequence"] == int(sequence):
            return file_index, entry_index, record
    return None


def referenced(state: dict) -> set:
    return {
        record["caused_by"] for _, _, record in recs(state) if "caused_by" in record
    }


def bump(txid: str, delta: int = 1) -> str:
    view, seqno = txid.split(".")
    return f"{view}.{int(seqno) + delta}"


def txkey(txid: str, name: str) -> tuple:
    view, seqno = txid.split(".")
    return int(view), int(seqno), name


def set_field(record: dict, field: str, value: Any) -> None:
    record[field] = value


def del_field(record: dict, field: str) -> None:
    del record[field]


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
dyns = lambda field, fn: (lambda s, r: set_field(r, field, fn(s, r)))


def combine(*edits):
    def edit(s, r):
        for e in edits:
            e(s, r)

    return edit


def one(*args, nth: int = 0):
    """A mutant applying `edit` (the last arg) to the first record matched
    by any of the preceding predicates, tried in order."""
    *predicates, edit = args

    def mutant(state: dict) -> bool:
        for predicate in predicates:
            target = find(state, predicate, nth=nth)
            if target:
                edit(state, target[2])
                return True
        return False

    return mutant


_to_voting = lambda record: (
    record["kind"] in HANDLERS
    and record["pre"] == "Gossiping"
    and record["post"] == "Voting"
    and "chosen" in record
)


def _capped_next_phase(current: str) -> str:
    candidate = PHASES[min(PHASES.index(current) + 1, 2)]
    return candidate if candidate != current else "Joining"


def _set_chain_off(record: dict) -> dict:
    txid = record["gossips"][record["source"]]
    missing = [v for v in record["expected_locations"] if v not in record["gossips"]]
    dropped = next(v for v in record["gossips"] if v != record["source"])
    return {k: v for k, v in record["gossips"].items() if k != dropped} | {
        missing[0]: txid
    }


def _truncated_json(state: dict) -> bool:
    target = find(state, kind_is("gossip_accepted"))
    if not target:
        return False
    file_index, entry_index, record = target
    body = dump(record)
    state["logs"][file_index][entry_index]["body"] = body[: len(body) // 2]
    return True


def _participation_drop(state: dict) -> bool:
    target = find(
        state, lambda r: r["kind"] == "committed" and r["node"] == nodes(state)[-1]
    )
    if not target:
        return False
    file_index, entry_index, _ = target
    state["logs"][file_index][entry_index]["deleted"] = True
    return True


def _retry_bad_version(state: dict) -> bool:
    first = find(state, lambda r: r["kind"] == "send")
    if not first:
        return False
    target = find(
        state,
        lambda r: r["kind"] == "send" and r["pre_version"] != first[2]["pre_version"],
    )
    if not target:
        return False
    target[2]["pre_version"] += 100
    return True


def _rolled_back_mutation(state: dict) -> bool:
    groups = collections.defaultdict(list)
    for _, _, record in recs(state):
        if "caused_by" in record:
            groups[(record["node"], record["caused_by"])].append(record)
    for key in sorted(groups):
        attempts = groups[key]
        if len(attempts) < 2:
            continue
        record = min(attempts, key=lambda r: r["sequence"])
        record["post"] = "Opening" if record["post"] != "Opening" else "Voting"
        if record["post"] == "Opening":
            record["open_kind"] = "Quorum"
        return True
    return False


def _delete_unreceived_send(state: dict) -> bool:
    refs = referenced(state)
    batches = collections.Counter(
        (r["node"], r["batch"]) for _, _, r in recs(state) if r["kind"] == "send"
    )
    for file_index, entry_index, record in seqsorted(state):
        if (
            record["kind"] == "send"
            and f"{record['node']}:{record['sequence']}" not in refs
            and batches[(record["node"], record["batch"])] > 1
        ):
            state["logs"][file_index][entry_index]["deleted"] = True
            return True
    return False


def _delete_unreceived_batch(state: dict, tail: bool) -> bool:
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
    for (node, batch), rows in sorted(groups.items()):
        if any(f"{r['node']}:{r['sequence']}" in refs for _, _, r in rows):
            continue
        highest = max(r["sequence"] for _, _, r in rows)
        if (highest == per_node_max[node]) != tail:
            continue
        for file_index, entry_index, _ in rows:
            state["logs"][file_index][entry_index]["deleted"] = True
        return True
    return False


def m_txid_lie_send_only(state: dict) -> bool:
    def has_send(r):
        return (
            r["kind"] == "gossip_accepted" and by_id(state, r["caused_by"]) is not None
        )

    target = find(state, lambda r: has_send(r) and r["source"] != r["node"]) or find(
        state, has_send
    )
    if not target:
        return False
    send = by_id(state, target[2]["caused_by"])[2]
    send["txid"] = bump(send["txid"])
    return True


def _txid_consistent(state: dict, raise_it: bool) -> bool:
    chosen = {r["chosen"] for _, _, r in recs(state) if "chosen" in r}
    txids = {
        r["node"]: r["txid"]
        for _, _, r in recs(state)
        if r["kind"] == "send" and "txid" in r
    }
    candidates = [
        n
        for n in txids
        if n not in chosen and (raise_it or int(txids[n].split(".")[1]) > 0)
    ]
    if not candidates or not chosen:
        return False
    name = candidates[0]
    if raise_it:
        top = max(txkey(v, n) for n, v in txids.items())
        new = f"{top[0]}.{top[1] + 77}"
    else:
        new = bump(txids[name], -1)
    for _, _, record in recs(state):
        if record["kind"] == "send" and record["node"] == name and "txid" in record:
            record["txid"] = new
        if record["kind"] == "gossip_accepted" and record.get("source") == name:
            record["txid"] = new
        if name in record.get("gossips", {}):
            record["gossips"][name] = new
    return True


def m_caused_by_other_kind(state: dict) -> bool:
    target = find(state, lambda r: r["kind"] == "vote_accepted")
    if not target:
        return False
    record = target[2]
    source = record["caused_by"].split(":")[0]
    gossip = find(
        state,
        lambda r: r["kind"] == "send"
        and r["node"] == source
        and r["send"].startswith("gossip:"),
        final_only=False,
    )
    if not gossip:
        return False
    record["caused_by"] = f"{source}:{gossip[2]['sequence']}"
    return True


def m_drop_received_send(state: dict) -> bool:
    target = find(
        state,
        lambda r: r["kind"] == "gossip_accepted"
        and by_id(state, r["caused_by"]) is not None,
    )
    if not target:
        return False
    file_index, entry_index, _ = by_id(state, target[2]["caused_by"])
    state["logs"][file_index][entry_index]["deleted"] = True
    return True


def m_receive_before_send(state: dict) -> bool:
    target = find(
        state,
        lambda r: r["kind"] == "gossip_accepted"
        and r["caused_by"].split(":")[0] == r["node"]
        and by_id(state, r["caused_by"]) is not None,
    )
    if not target:
        return False
    record = target[2]
    send = by_id(state, record["caused_by"])[2]
    record["sequence"], send["sequence"] = send["sequence"], record["sequence"]
    record["caused_by"] = f"{record['node']}:{record['sequence']}"
    return True


def m_redirect_to_identical_copy(state: dict) -> bool:
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
                record["caused_by"] = f"{copy_record['node']}:{copy_record['sequence']}"
                return True
    return False


def m_extra_final_attempt(state: dict) -> bool:
    target = find(state, lambda r: "open_kind" in r and "caused_by" in r)
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
    prefix = state["logs"][file_index][entry_index]["prefix"]
    state["logs"][file_index].append({"prefix": prefix, "rec": duplicate, "nl": "\n"})
    return True


def m_failed_to_trace_line(state: dict) -> bool:
    log = state["logs"][0]
    log.insert(len(log) // 2, {"raw": FAILED_TO_TRACE_LINE})
    return True


def m_truncate_opener_after_voting(state: dict) -> bool:
    target = find(state, lambda r: "open_kind" in r)
    if not target:
        return False
    opener = target[2]["node"]
    committed = find(
        state,
        lambda r: r["kind"] == "committed"
        and r["node"] == opener
        and r["post"] == "Voting",
    )
    if not committed:
        return False
    cut = committed[2]["sequence"]
    for file_index, entry_index, record in recs(state):
        if record["node"] == opener and record["sequence"] > cut:
            state["logs"][file_index][entry_index]["deleted"] = True
    return True


def m_wrong_open_kind_arg(state: dict) -> bool:
    state["open_kind"] = "FAILOVER" if state["open_kind"] == "QUORUM" else "QUORUM"
    return True


def m_wrong_participants_arg(state: dict) -> bool:
    state["participants"] = (
        state["participants"] - 1 if state["participants"] > 1 else 2
    )
    return True


def m_missing_log_file(state: dict) -> bool:
    if len(state["order"]) < 2:
        return False
    state["order"].pop()
    return True


def m_shuffle_trace_lines(state: dict) -> bool:
    rng = random.Random(8282)
    for log in state["logs"]:
        indices = [i for i, item in enumerate(log) if "rec" in item]
        values = [log[i] for i in indices]
        rng.shuffle(values)
        for i, value in zip(indices, values):
            log[i] = value
    return True


def m_strip_non_trace_lines(state: dict) -> bool:
    for log in state["logs"]:
        log[:] = [item for item in log if "rec" in item]
    return True


def m_reverse_key_order(state: dict) -> bool:
    for log in state["logs"]:
        for item in log:
            if "rec" in item:
                item["body"] = json.dumps(
                    dict(sorted(item["rec"].items(), reverse=True)),
                    separators=(",", ":"),
                )
    return True


def m_log_order_permuted(state: dict) -> bool:
    if len(state["order"]) < 2:
        return False
    state["order"].reverse()
    return True


def m_committed_version_within_newest_pair(state: dict) -> bool:
    # The newest pair's writer's committed version must exceed both of that
    # pair's versions; a version still inside the pair must fail even though
    # it is above every earlier known committed version.
    for node in nodes(state):
        handlers = [
            r for _, _, r in recs(state) if r["node"] == node and r["kind"] in HANDLERS
        ]
        committed = [
            (fi, ei, r)
            for fi, ei, r in recs(state)
            if r["node"] == node and r["kind"] == "committed"
        ]
        if not handlers or not committed:
            continue
        newest = max(max(r["pre_version"], r["pre_timeout_version"]) for r in handlers)
        lowest = min(
            min(r["pre_version"], r["pre_timeout_version"])
            for r in handlers
            if max(r["pre_version"], r["pre_timeout_version"]) == newest
        )
        if newest - lowest < 2:
            continue
        target = max(committed, key=lambda item: item[2]["sequence"])[2]
        if target["version"] <= newest:
            continue
        new_version = (lowest + newest) // 2
        if lowest < new_version < newest:
            target["version"] = new_version
            return True
    return False


OPEN_KIND_FLIP = {"Quorum": "Failover", "Failover": "Quorum"}


_votes_over_quorum = (
    lambda r: r.get("open_kind") == "Quorum" and len(r.get("votes", [])) > 1
)
_trim_votes = lambda s, r: set_field(
    r, "votes", [r["source"]] if r.get("source") in r["votes"] else r["votes"][:1]
)


_no_advance = combine(setf("post", "Gossiping"), delf("chosen"))


_premature_pred = lambda r: (
    r["kind"] == "gossip_accepted"
    and r["pre"] == r["post"] == "Gossiping"
    and len(r["gossips"]) < len(r["expected_locations"])
)


def _premature_edit(s, r):
    chosen = max(r["gossips"].items(), key=lambda i: txkey(i[1], i[0]))[0]
    combine(setf("post", "Voting"), setf("chosen", chosen))(s, r)


_is_vote_send = lambda r: r["kind"] == "send" and r["send"].startswith("vote:")
_vote_to_non_chosen = dyns(
    "send", lambda s, r: f"vote:{other(s, r['send'].split(':', 1)[1])}"
)
_timeout_changed = (
    lambda r: r["kind"] == "timeout" and r["post_timeout"] != r["pre_timeout"]
)
_phase_skip = dynf("post_timeout", lambda r: _capped_next_phase(r["post_timeout"]))
_is_failover = lambda r: r.get("open_kind") == "Failover"
_pretimeout_edit = dynf(
    "pre_timeout",
    lambda r: "Gossiping" if r["pre_timeout"] != "Gossiping" else "Opening",
)
_no_advance_timeout = copyf("post_timeout", "pre_timeout")

DECISION = [
    ("open_kind_flip", FAIL, one(has("open_kind"), flipf("open_kind", OPEN_KIND_FLIP))),
    ("open_without_quorum", FAIL, one(_votes_over_quorum, _trim_votes)),
    ("chosen_not_max", FAIL, one(_to_voting, relabel("chosen"))),
    ("skip_to_opening", FAIL, one(_to_voting, setf("post", "Opening"))),
    ("no_advance_on_full_gossips", FAIL, one(_to_voting, _no_advance)),
    ("premature_voting", FAIL, one(_premature_pred, _premature_edit)),
    ("drop_restart", FAIL, one(flag("restart"), delf("restart"))),
    ("add_restart", FAIL, one(kind_is("gossip_accepted"), setf("restart", True))),
    ("vote_to_non_chosen", FAIL, one(_is_vote_send, _vote_to_non_chosen)),
    ("timeout_phase_skip", FAIL, one(_timeout_changed, _phase_skip)),
    ("timeout_no_advance", FAIL, one(_timeout_changed, _no_advance_timeout)),
    ("failover_without_valid_timeout", FAIL, one(_is_failover, _pretimeout_edit)),
    ("txid_lie_send_only", FAIL, m_txid_lie_send_only),
    ("txid_raise_consistent", FAIL, lambda s: _txid_consistent(s, True)),
    ("txid_lower_consistent", PASS, lambda s: _txid_consistent(s, False)),
]

_dangling_gossip = dynf("caused_by", lambda r: f"{r['source']}:99999")
_source_ne_node = lambda r: r["kind"] == "gossip_accepted" and r["source"] != r["node"]
_timeout_has_cause = lambda r: r["kind"] == "timeout" and "caused_by" in r
_dangling_timeout = dynf("caused_by", lambda r: f"{r['node']}:99999")
_source_mismatch = one(_source_ne_node, kind_is("gossip_accepted"), relabel("source"))

CAUSALITY = [
    ("dangling_caused_by", FAIL, one(kind_is("gossip_accepted"), _dangling_gossip)),
    ("caused_by_other_kind", FAIL, m_caused_by_other_kind),
    ("source_mismatch", FAIL, _source_mismatch),
    ("drop_received_send", FAIL, m_drop_received_send),
    ("receive_before_send", FAIL, m_receive_before_send),
    ("timeout_dangling", FAIL, one(_timeout_has_cause, _dangling_timeout)),
]

_committed_shift_pred = lambda r: r["kind"] == "committed" and r["post"] != "Gossiping"
_committed_voting = lambda r: r["kind"] == "committed" and r["post"] == "Voting"
_committed_version_bound = m_committed_version_within_newest_pair
_segment_bad_pre_version = one(
    kind_is("gossip_accepted"), bumpf("pre_version", 100), nth=1
)
_set_chain_off_pred = lambda r: (
    r["kind"] == "gossip_accepted"
    and r["post"] == "Gossiping"
    and 1 < len(r["gossips"]) < len(r["expected_locations"])
)

COMMIT_ORDER = [
    ("participation_drop", FAIL, _participation_drop),
    ("participation_version", FAIL, one(kind_is("committed"), bumpf("version", 1))),
    ("segment_bad_pre_version", FAIL, _segment_bad_pre_version),
    ("committed_version_shift", FAIL, one(_committed_shift_pred, bumpf("version", 1))),
    ("committed_version_within_newest_pair", FAIL, _committed_version_bound),
    ("committed_phase_lie", FAIL, one(_committed_voting, setf("post", "Opening"))),
    ("set_chain_off", FAIL, one(_set_chain_off_pred, dynf("gossips", _set_chain_off))),
    ("retry_bad_version", FAIL, _retry_bad_version),
    ("rolled_back_mutation", FAIL, _rolled_back_mutation),
    ("extra_final_attempt", FAIL, m_extra_final_attempt),
    ("failed_to_trace_line", FAIL, m_failed_to_trace_line),
]

_shrink_expected_locations = dynf(
    "expected_locations", lambda r: r["expected_locations"][:-1]
)
_expected_locations_changed = one(
    kind_is("gossip_accepted"), _shrink_expected_locations
)
_delete_middle_batch = lambda s: _delete_unreceived_batch(s, False)
_delete_tail_batch = lambda s: _delete_unreceived_batch(s, True)

FORMAT = [
    ("truncated_json", FAIL, _truncated_json),
    ("missing_pre", FAIL, one(kind_is(*HANDLERS), delf("pre"))),
    ("unknown_kind", FAIL, one(kind_is("send"), setf("kind", "bogus"))),
    ("expected_locations_changed", FAIL, _expected_locations_changed),
    ("node_misattributed", FAIL, one(kind_is(*HANDLERS), relabel("node"))),
    ("duplicate_sequence", FAIL, one(kind_is("send"), bumpf("sequence", -1), nth=1)),
    ("delete_unreceived_send", FAIL, _delete_unreceived_send),
    ("delete_middle_unreceived_batch", FAIL, _delete_middle_batch),
    ("delete_tail_unreceived_batch", PASS, _delete_tail_batch),
    ("truncate_opener_after_voting", FAIL, m_truncate_opener_after_voting),
]

ARGS = [
    ("wrong_open_kind_arg", FAIL, m_wrong_open_kind_arg),
    ("wrong_participants_arg", FAIL, m_wrong_participants_arg),
    ("missing_log_file", FAIL, m_missing_log_file),
]

BENIGN = [
    ("shuffle_trace_lines", PASS, m_shuffle_trace_lines),
    ("strip_non_trace_lines", PASS, m_strip_non_trace_lines),
    ("reverse_key_order", PASS, m_reverse_key_order),
    ("log_order_permuted", PASS, m_log_order_permuted),
    ("identical_unreceived_copy", PASS, m_redirect_to_identical_copy),
]

GROUPS = {
    "decision": DECISION,
    "causality": CAUSALITY,
    "commit-order": COMMIT_ORDER,
    "format": FORMAT,
    "args": ARGS,
    "benign": BENIGN,
}


KIND_SWAP = {
    "gossip_accepted": "vote_accepted",
    "vote_accepted": "gossip_accepted",
    "iamopen_accepted": "vote_accepted",
    "timeout": "vote_accepted",
    "send": "timeout_request",
    "timeout_request": "send",
    "committed": "timeout_request",
}


def perturb(state: dict, record: dict, field: str) -> bool:
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
        record[field] = (
            value[1:]
            if len(value) > 1
            else sorted(set(value) | {other(state, value[0])})
        )
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
        return False
    return True


def sweep_specs(base: dict):
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


class Result(NamedTuple):
    group: str
    scenario: str
    name: str
    expected: str
    outcome: str
    message: str
    state: dict


def describe(base: dict, mutated: dict) -> str:
    """A human-readable diff between a scenario and one of its mutants."""
    changes = []
    for key in ("participants", "open_kind", "order"):
        if base[key] != mutated[key]:
            changes.append(f"{key} {base[key]} -> {mutated[key]}")
    before = {(fi, ei): r for fi, ei, r in recs(base)}
    after = {(fi, ei): r for fi, ei, r in recs(mutated)}
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old is None:
            changes.append(f"inserted {new['node']}:{new['sequence']} ({new['kind']})")
        elif new is None:
            changes.append(f"deleted {old['node']}:{old['sequence']} ({old['kind']})")
        else:
            for field in sorted(set(old) | set(new)):
                if old.get(field) != new.get(field):
                    changes.append(
                        f"{old['node']}:{old['sequence']} {field}: {old.get(field)} -> {new.get(field)}"
                    )
    return "; ".join(changes) or "(no change)"


def allow_sweep(result: Result):
    for entry in ALLOW_SWEEP:
        if result.scenario in entry["scenarios"] and entry["pattern"].match(
            result.name
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
    mutant_id: str, state: dict, replayer: pathlib.Path, work_dir: pathlib.Path
):
    case_dir = work_dir / mutant_id.replace("/", "__")
    case_dir.mkdir(parents=True, exist_ok=True)
    files = [case_dir / f"{index}.out" for index in state["order"]]
    for path, index in zip(files, state["order"]):
        path.write_text(
            "".join(render(item) for item in state["logs"][index]), encoding="utf-8"
        )
    command = [
        str(replayer),
        "--participants",
        str(state["participants"]),
        "--open-kind",
        state["open_kind"],
        "--wait-ms",
        "0",
        *(str(f) for f in files),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=90, check=False
        )
        output = (completed.stdout + completed.stderr).strip()
        return classify(completed.returncode, output), output
    except subprocess.TimeoutExpired:
        return "OTHER(rc=-1)", "harness timeout"


def build_jobs(scenarios: dict):
    for name, base in scenarios.items():
        yield "baseline", name, "baseline", PASS, copy.deepcopy(base)
        for group, rows in GROUPS.items():
            for mutant_name, expected, fn in rows:
                state = copy.deepcopy(base)
                if fn(state):
                    yield group, name, mutant_name, expected, state
        for kind, field, position, file_index, entry_index in sweep_specs(base):
            state = copy.deepcopy(base)
            record = state["logs"][file_index][entry_index]["rec"]
            if perturb(state, record, field):
                yield "sweep", name, f"{kind}.{field}#{position}", "?", state


_bad = lambda row: (
    (row.outcome == "PASS" and not allow_sweep(row))
    if row.group == "sweep"
    else (row.expected == PASS) != (row.outcome == "PASS")
)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} REPLAYER FIXTURES_DIR", file=sys.stderr)
        return 2
    replayer, fixtures_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    scenarios = {
        p.name: load_scenario(p)
        for p in sorted(fixtures_dir.iterdir())
        if p.is_dir() and (p / "scenario.json").exists()
    }
    if not scenarios:
        raise SystemExit(f"no scenarios found under {fixtures_dir}")

    with tempfile.TemporaryDirectory() as work_dir:

        def run(job) -> Result:
            group, scenario, name, expected, state = job
            outcome, output = run_mutant(
                f"{scenario}/{group}/{name}", state, replayer, pathlib.Path(work_dir)
            )
            message = output.splitlines()[-1][:300] if output else ""
            return Result(group, scenario, name, expected, outcome, message, state)

        with ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as executor:
            results = list(executor.map(run, build_jobs(scenarios)))

    curated = [r for r in results if r.group != "sweep"]
    sweep = [r for r in results if r.group == "sweep"]
    allowed = {allow_sweep(r) for r in sweep if r.outcome == "PASS" and allow_sweep(r)}
    allowed_count = sum(1 for r in sweep if r.outcome == "PASS" and allow_sweep(r))
    print(
        f"Curated mutants: {sum(not _bad(r) for r in curated)}/{len(curated)} matched expectation"
    )
    print(
        f"Sweep mutants: {sum(r.outcome != 'PASS' for r in sweep)}/{len(sweep)} caught, "
        f"{allowed_count} allowlisted harmless pass(es)"
    )
    for name, reason in sorted(allowed):
        print(f"- {name}: {reason}")

    unexpected = [r for r in results if _bad(r)]
    for r in unexpected:
        print(
            f"- {r.scenario} {r.group} {r.name}: expected {r.expected}, got {r.outcome}\n"
            f"  changes: {describe(scenarios[r.scenario], r.state)}\n  message: {r.message}",
            file=sys.stderr,
        )
    return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
