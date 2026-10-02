# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Mutation testing for the disaster-recovery trace validator.

Run: python3 tests/infra/recovery_trace_mutations.py REPLAYER FIXTURES_DIR

The fixtures are trace-only log excerpts for the quorum, failover, and
multiple-timeout recovery-decision-protocol scenarios. The harness checks
baseline replay, curated mutants grouped by kind with explicit pass/fail
expectations, and a systematic sweep that perturbs one field of sampled
records, every one of which must fail. Commit order is covered by targeted
mutants rather than by sweeping `version` and `wrote`.
"""

import collections
import copy
import itertools
import json
import os
import pathlib
import random
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


def find(state: dict, predicate, nth: int = 0):
    candidates = [item for item in seqsorted(state) if predicate(item[2])]
    return candidates[nth] if len(candidates) > nth else None


def locs(state: dict) -> list:
    return next(r for _, _, r in recs(state) if r["kind"] == "start")[
        "expected_locations"
    ]


def nodes(state: dict) -> list:
    return sorted({record["node"] for _, _, record in recs(state)})


def other(state: dict, current: str, pool=None):
    for value in pool or locs(state):
        if value != current:
            return value
    return None


def envelope(record: dict) -> tuple:
    """The (source, target, message) of a send or receive record."""
    if record["kind"] == "send":
        return record["node"], record["target"], record["message"], record.get("txid")
    message = record["kind"].removesuffix("_accepted")
    return record["source"], record["node"], message, record.get("txid")


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


def _set_chain_off(state: dict, record: dict) -> dict:
    txid = record["gossips"][record["source"]]
    missing = [v for v in locs(state) if v not in record["gossips"]]
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


def _start_drop(state: dict) -> bool:
    target = find(
        state, lambda r: r["kind"] == "start" and r["node"] == nodes(state)[-1]
    )
    if not target:
        return False
    file_index, entry_index, _ = target
    state["logs"][file_index][entry_index]["deleted"] = True
    return True


def _start_twice(state: dict) -> bool:
    target = find(state, kind_is("start"))
    if not target:
        return False
    file_index, entry_index, record = target
    duplicate = copy.deepcopy(record)
    duplicate["sequence"] = 1 + max(
        r["sequence"] for _, _, r in recs(state) if r["node"] == record["node"]
    )
    prefix = state["logs"][file_index][entry_index]["prefix"]
    state["logs"][file_index].append({"prefix": prefix, "rec": duplicate, "nl": "\n"})
    return True


def _writes(state: dict, node: str) -> list:
    return sorted(
        (r for _, _, r in recs(state) if r["node"] == node and r.get("wrote")),
        key=lambda r: r["version"],
    )


def _swap_gossip_writes(state: dict) -> bool:
    for node in nodes(state):
        writes = _writes(state, node)
        for first, second in itertools.pairwise(writes):
            if first["kind"] == second["kind"] == "gossip_accepted" and len(
                first["gossips"]
            ) != len(second["gossips"]):
                first["version"], second["version"] = (
                    second["version"],
                    first["version"],
                )
                return True
    return False


def _duplicate_write_version(state: dict) -> bool:
    for node in nodes(state):
        writes = _writes(state, node)
        if len(writes) > 1:
            writes[1]["version"] = writes[0]["version"]
            return True
    return False


def _read_only_before_its_write(state: dict) -> bool:
    for _, _, record in seqsorted(state):
        if record["kind"] != "gossip_accepted" or record.get("wrote") is not False:
            continue
        written = {r["version"]: r for r in _writes(state, record["node"])}
        writer = written.get(record["version"])
        if writer and writer["kind"] == "gossip_accepted":
            record["version"] -= 1
            return True
    return False


def _unwrite_read_version(state: dict) -> bool:
    read = {
        (r["node"], r["pre_version"]) for _, _, r in recs(state) if r["kind"] == "send"
    }
    for _, _, record in seqsorted(state):
        if record.get("wrote") and (record["node"], record["version"]) in read:
            record["wrote"] = False
            return True
    return False


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


def _retry_after_end(state: dict) -> bool:
    """Moves a node's last retry to read the write that took it to Joining or
    Open, where the model disables retries."""
    for node in nodes(state):
        records = [r for _, _, r in seqsorted(state) if r["node"] == node]
        ended = [
            r
            for r in records
            if r["kind"] in HANDLERS and r["wrote"] and r["post"] in ("Joining", "Open")
        ]
        sends = [r for r in records if r["kind"] == "send"]
        if not ended or not sends:
            continue
        batch = [r for r in sends if r["batch"] == sends[-1]["batch"]]
        if batch[0]["pre_version"] < ended[0]["version"]:
            for record in batch:
                record["pre_version"] = ended[0]["version"]
            return True
    return False


def _delete_send_from_batch(state: dict) -> bool:
    batches = collections.Counter(
        (r["node"], r["batch"]) for _, _, r in recs(state) if r["kind"] == "send"
    )
    for file_index, entry_index, record in seqsorted(state):
        if record["kind"] == "send" and batches[(record["node"], record["batch"])] > 1:
            state["logs"][file_index][entry_index]["deleted"] = True
            return True
    return False


def _delete_batch(state: dict, tail: bool) -> bool:
    """Deletes a retry's sends, from the middle of a node's log or from its end.
    A tail batch is only deleted if every receive still has a send to take."""
    sends = collections.Counter(
        envelope(r) for _, _, r in recs(state) if r["kind"] == "send"
    )
    receives = collections.Counter(
        envelope(r) for _, _, r in recs(state) if "source" in r
    )
    groups = collections.defaultdict(list)
    last = collections.defaultdict(int)
    for file_index, entry_index, record in recs(state):
        if record["kind"] == "send":
            groups[(record["node"], record["batch"])].append(
                (file_index, entry_index, record)
            )
        last[record["node"]] = max(last[record["node"]], record["sequence"])
    for (node, _), rows in sorted(groups.items()):
        if (max(r["sequence"] for _, _, r in rows) == last[node]) != tail:
            continue
        if tail and any(
            sends[envelope(r)] <= receives[envelope(r)] for _, _, r in rows
        ):
            continue
        for file_index, entry_index, _ in rows:
            state["logs"][file_index][entry_index]["deleted"] = True
        return True
    return False


def m_txid_lie_send_only(state: dict) -> bool:
    target = find(state, lambda r: r["kind"] == "send" and "txid" in r, nth=1)
    if not target:
        return False
    target[2]["txid"] = bump(target[2]["txid"])
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


def m_receive_before_send(state: dict) -> bool:
    # A node's receive of its own vote, moved before the retry that first sent it
    for _, _, record in seqsorted(state):
        if record["kind"] != "vote_accepted" or record["source"] != record["node"]:
            continue
        own_votes = [
            r
            for _, _, r in seqsorted(state)
            if r["kind"] == "send"
            and r["node"] == record["node"]
            and r["message"] == "vote"
            and r["target"] == record["node"]
        ]
        if own_votes:
            record["version"] = own_votes[0]["pre_version"] - 1
            record["wrote"] = False
            return True
    return False


def m_extra_final_attempt(state: dict) -> bool:
    target = find(state, lambda r: "open_kind" in r and "source" in r)
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
    voting = find(
        state,
        lambda r: r["node"] == opener
        and r["kind"] in HANDLERS
        and r["pre"] == "Gossiping"
        and r["post"] == "Voting",
    )
    if not voting:
        return False
    cut = voting[2]["sequence"]
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


OPEN_KIND_FLIP = {"Quorum": "Failover", "Failover": "Quorum"}


_votes_over_quorum = (
    lambda r: r.get("open_kind") == "Quorum" and len(r.get("votes", [])) > 1
)
_trim_votes = lambda s, r: set_field(
    r, "votes", [r["source"]] if r.get("source") in r["votes"] else r["votes"][:1]
)


_no_advance = combine(setf("post", "Gossiping"), delf("chosen"))


_premature_pred = lambda r: (
    r["kind"] == "gossip_accepted" and r["pre"] == r["post"] == "Gossiping"
)


def _premature_edit(s, r):
    chosen = max(r["gossips"].items(), key=lambda i: txkey(i[1], i[0]))[0]
    combine(setf("post", "Voting"), setf("chosen", chosen))(s, r)


_is_vote_send = lambda r: r["kind"] == "send" and r["message"] == "vote"
_timeout_changed = (
    lambda r: r["kind"] == "timeout" and r["post_timeout"] != r["pre_timeout"]
)
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
    ("add_restart", FAIL, one(kind_is("gossip_accepted"), setf("restart", True))),
    ("vote_to_non_chosen", FAIL, one(_is_vote_send, relabel("target"))),
    ("timeout_no_advance", FAIL, one(_timeout_changed, _no_advance_timeout)),
    ("failover_without_valid_timeout", FAIL, one(_is_failover, _pretimeout_edit)),
    ("txid_lie_send_only", FAIL, m_txid_lie_send_only),
    ("txid_raise_consistent", FAIL, lambda s: _txid_consistent(s, True)),
    ("txid_lower_consistent", PASS, lambda s: _txid_consistent(s, False)),
]

_source_ne_node = lambda r: r["kind"] == "gossip_accepted" and r["source"] != r["node"]
_source_mismatch = one(_source_ne_node, kind_is("gossip_accepted"), relabel("source"))

CAUSALITY = [
    ("source_mismatch", FAIL, _source_mismatch),
    ("receive_before_send", FAIL, m_receive_before_send),
]

_set_chain_off_pred = lambda r: (
    r["kind"] == "gossip_accepted"
    and r["post"] == "Gossiping"
    and len(r["gossips"]) > 1
)

COMMIT_ORDER = [
    ("start_drop", FAIL, _start_drop),
    ("start_version", FAIL, one(kind_is("start"), bumpf("version", 1))),
    ("start_twice", FAIL, _start_twice),
    ("swap_gossip_writes", FAIL, _swap_gossip_writes),
    ("duplicate_write_version", FAIL, _duplicate_write_version),
    ("read_only_before_its_write", FAIL, _read_only_before_its_write),
    ("unwrite_read_version", FAIL, _unwrite_read_version),
    ("set_chain_off", FAIL, one(_set_chain_off_pred, dyns("gossips", _set_chain_off))),
    ("retry_bad_version", FAIL, _retry_bad_version),
    ("retry_after_end", FAIL, _retry_after_end),
    ("extra_final_attempt", FAIL, m_extra_final_attempt),
    ("failed_to_trace_line", FAIL, m_failed_to_trace_line),
]

_delete_middle_batch = lambda s: _delete_batch(s, False)
_delete_tail_batch = lambda s: _delete_batch(s, True)

FORMAT = [
    ("truncated_json", FAIL, _truncated_json),
    ("missing_pre", FAIL, one(kind_is(*HANDLERS), delf("pre"))),
    ("unknown_kind", FAIL, one(kind_is("send"), setf("kind", "bogus"))),
    ("duplicate_sequence", FAIL, one(kind_is("send"), bumpf("sequence", -1), nth=1)),
    ("delete_send_from_batch", FAIL, _delete_send_from_batch),
    ("delete_middle_batch", FAIL, _delete_middle_batch),
    ("delete_tail_batch", PASS, _delete_tail_batch),
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
    "send": "start",
    "start": "send",
}


def perturb(state: dict, record: dict, field: str) -> bool:
    value = record[field]
    if field in ("pre", "post", "pre_timeout", "post_timeout"):
        record[field] = PHASES[(PHASES.index(value) + 1) % len(PHASES)]
    elif field in ("pre_version", "batch"):
        record[field] = value + 1
    elif field == "sequence":
        record[field] = value + 1000
    elif field in ("source", "node", "chosen", "target"):
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
    elif field == "message":
        record[field] = {"gossip": "vote", "vote": "iamopen", "iamopen": "gossip"}[
            value
        ]
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
        by_kind[record["kind"]].append((file_index, entry_index))
    for kind, rows in sorted(by_kind.items()):
        for position in sorted({0, len(rows) // 2, len(rows) - 1}):
            file_index, entry_index = rows[position]
            for field in sorted(base["logs"][file_index][entry_index]["rec"]):
                yield kind, field, position, file_index, entry_index


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


def _bad(row: Result) -> bool:
    if row.group == "sweep":
        return row.outcome == "PASS"
    return (row.expected == PASS) != (row.outcome == "PASS")


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
    print(
        f"Curated mutants: {sum(not _bad(r) for r in curated)}/{len(curated)} matched expectation"
    )
    print(
        f"Sweep mutants: {sum(r.outcome != 'PASS' for r in sweep)}/{len(sweep)} caught"
    )

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
