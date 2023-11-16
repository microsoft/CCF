# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
import rich

"""
TODO

Add status on responses (votes and append entries)
"""

LEADERSHIP_STATUS = {
    "None": ":beginner:",
    "Leader": ":crown:",
    "Follower": ":guard:",
    "Candidate": ":person_raising_hand:",
}

FUNCTIONS = {
    "add_configuration": "Cfg",
    "replicate": "Rpl",
    "send_append_entries": "SAe",
    "recv_append_entries": "RAe",
    "execute_append_entries_sync": "EAe",
    "send_append_entries_response": "SAeR",
    "recv_append_entries_response": "RAeR",
    "send_request_vote": "SRv",
    "recv_request_vote": "RRv",
    "recv_request_vote_response": "RRvR",
    "recv_propose_request_vote": "RPRv",
    "become_candidate": "BCan",
    "become_leader": "BLea",
    "become_follower": "BFol",
    "commit": "Cmt",
    None: "",
}

OK = {"Y": ":white_check_mark:", "N": ":x:", " ": "  "}


def digits(value):
    return len(str(value))


def diffed_key(old, new, key, suffix, size):
    if old is None or old[key] == new[key]:
        return f"{new[key]:>{size}}{suffix}"
    color = "bright_white on red"
    return f"[{color}]{new[key]:>{size}}{suffix}[/{color}]"


def render_state(state, func, old_state, ok, cfg):
    if state is None:
        return " "
    ls = LEADERSHIP_STATUS[state["leadership_state"]]
    nid = state["node_id"]
    v = diffed_key(old_state, state, "current_view", "v", cfg.view)
    i = diffed_key(old_state, state, "last_idx", "i", cfg.index)
    c = diffed_key(old_state, state, "commit_idx", "c", cfg.commit)
    f = FUNCTIONS[func]
    opc = "bold bright_white on red" if func else "normal"
    return f"[{opc}]{nid:>{cfg.nodes}}{ls}{f:<4} [/{opc}]{OK[ok]} {v} {i} {c}"


class DigitsCfg:
    nodes = 0
    view = 0
    index = 0
    commit = 0


def table(lines):
    entries = [json.loads(line) for line in lines]
    nodes = []
    max_view = 0
    max_index = 0
    max_commit = 0
    for entry in entries:
        node_id = entry["msg"]["state"]["node_id"]
        if node_id not in nodes:
            nodes.append(node_id)
        max_view = max(max_view, entry["msg"]["state"]["current_view"])
        max_index = max(max_index, entry["msg"]["state"]["last_idx"])
        max_commit = max(max_commit, entry["msg"]["state"]["commit_idx"])
    dcfg = DigitsCfg()
    dcfg.nodes = max(nodes, key=len)
    dcfg.view = digits(max_view)
    dcfg.index = digits(max_index)
    dcfg.commit = digits(max_commit)
    node_to_state = {}
    rows = []
    for entry in entries:
        node_id = entry["msg"]["state"]["node_id"]
        old_state = node_to_state.get(node_id)
        node_to_state[node_id] = entry["msg"]["state"]
        ok = " "
        if "packet" in entry["msg"]:
            if "success" in entry["msg"]["packet"]:
                ok = "Y" if entry["msg"]["packet"]["success"] == "OK" else "N"
            if "vote_granted" in entry["msg"]["packet"]:
                ok = "Y" if entry["msg"]["packet"]["vote_granted"] else "N"
        states = [
            (
                node_to_state.get(node),
                entry["msg"]["function"] if node == node_id else None,
                old_state if node == node_id else None,
                ok if node == node_id else " ",
            )
            for node in nodes
        ]
        rows.append("     ".join(render_state(*state, dcfg) for state in states))
    return rows


if __name__ == "__main__":
    with open(sys.argv[1]) as tf:
        for line in table(tf.readlines()):
            rich.print(line)
