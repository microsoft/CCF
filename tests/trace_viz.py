# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
import rich

LEADERSHIP_STATUS = {
    "None": ":beginner:",
    "Leader": ":crown:",
    "Follower": ":guard:",
    "Candidate": ":person_raising_hand:",
}

MEMBERSHIP_STATUS = {"Active": "A", "Retired": "R"}

RETIREMENT_PHASE = {"Ordered": "o", "Signed": "s", "Completed": "c", None: " "}

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
    "bootstrap": "Boot",
    "drop_pending_to": "Drop",
    None: "",
}

TAG = {"Y": ":white_check_mark:", "N": ":x:", " ": "  ", "S": ":pencil:"}


def digits(value):
    return len(str(value))


def diffed_key(old, new, key, suffix, size, sub=lambda x: x):
    if old is None or old[key] == new[key]:
        return f"{sub(new[key]):>{size}}{suffix}"
    color = "bright_white on red"
    return f"[{color}]{sub(new[key]):>{size}}{suffix}[/{color}]"


def diffed_opt_key(old, new, key, suffix, size, sub=lambda x: x):
    if old is None or old.get(key) == new.get(key):
        return f"{sub(new.get(key)):>{size}}{suffix}"
    color = "bright_white on red"
    return f"[{color}]{sub(new.get(key)):>{size}}{suffix}[/{color}]"


def render_state(state, func, old_state, tag, cfg):
    if state is None:
        return " "
    ls = LEADERSHIP_STATUS[state["leadership_state"]]
    ms = diffed_key(old_state, state, "membership_state", "", 1, MEMBERSHIP_STATUS.get)
    rp = diffed_opt_key(
        old_state, state, "retirement_phase", "", 1, RETIREMENT_PHASE.get
    )
    nid = state["node_id"]
    v = diffed_key(old_state, state, "current_view", "", cfg.view)
    i = diffed_key(old_state, state, "last_idx", "", cfg.index)
    c = diffed_key(old_state, state, "commit_idx", "", cfg.commit)
    f = FUNCTIONS[func]
    opc = "bold bright_white on red" if func else "normal"
    return (
        f"[{opc}]{nid:>{cfg.nodes}}{ls}{f:<4} [/{opc}]{TAG[tag]} {ms}{rp} {v}.{i} {c}"
    )


class DigitsCfg:
    nodes = 0
    view = 0
    index = 0
    commit = 0
    ts = 0


def table(lines):
    entries = [json.loads(line) for line in lines]
    nodes = []
    max_view = 0
    max_index = 0
    max_commit = 0
    max_ts = 0
    for entry in entries:
        try:
            node_id = entry["msg"]["state"]["node_id"]
            if node_id not in nodes:
                nodes.append(node_id)
            max_view = max(max_view, entry["msg"]["state"]["current_view"])
            max_index = max(max_index, entry["msg"]["state"]["last_idx"])
            max_commit = max(max_commit, entry["msg"]["state"]["commit_idx"])
            max_ts = max(max_ts, int(entry["h_ts"]))
        except:
            print(f"Boom on: {entry}")
            raise
    dcfg = DigitsCfg()
    dcfg.nodes = len(max(nodes, key=len))
    dcfg.view = digits(max_view)
    dcfg.index = digits(max_index)
    dcfg.commit = digits(max_commit)
    dcfg.ts = digits(max_ts)
    node_to_state = {}
    rows = []
    for entry in entries:
        node_id = entry["msg"]["state"]["node_id"]
        old_state = node_to_state.get(node_id)
        node_to_state[node_id] = entry["msg"]["state"]
        tag = " "
        if "packet" in entry["msg"]:
            if "success" in entry["msg"]["packet"]:
                tag = "Y" if entry["msg"]["packet"]["success"] == "OK" else "N"
            if "vote_granted" in entry["msg"]["packet"]:
                tag = "Y" if entry["msg"]["packet"]["vote_granted"] else "N"
        if entry["msg"].get("globally_committable"):
            tag = "S"
        # Display commit index changes on the Cmt line itself
        if "args" in entry["msg"] and "commit_idx" in entry["msg"]["args"]:
            entry["msg"]["state"]["commit_idx"] = entry["msg"]["args"]["commit_idx"]
        states = [
            (
                node_to_state.get(node),
                entry["msg"]["function"] if node == node_id else None,
                old_state if node == node_id else None,
                tag if node == node_id else " ",
            )
            for node in nodes
        ]
        rows.append(
            f"[{entry['h_ts']:>{dcfg.ts}}] "
            + "     ".join(render_state(*state, dcfg) for state in states if state[0])
            + "   "
            + entry["cmd"]
        )
    return rows


if __name__ == "__main__":
    with open(sys.argv[1]) as tf:
        for line in table(tf.readlines()):
            rich.print(line)
