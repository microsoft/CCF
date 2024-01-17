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

FUNCTIONS = {
    "SIMChangeConfigurationInt": "Cfg",
    "ClientRequest": "Rpl",
    "AppendEntries": "SAe",
    "RcvAppendEntriesRequest": "RAe",
    "execute_append_entries_sync": "EAe",
    "send_append_entries_response": "SAeR",
    "RcvAppendEntriesResponse": "RAeR",
    "RequestVote": "SRv",
    "RcvRequestVoteRequest": "RRv",
    "RcvRequestVoteResponse": "RRvR",
    "recv_propose_request_vote": "RPRv",
    "become_candidate": "BCan",
    "BecomeLeader": "BLea",
    "become_follower": "BFol",
    "AdvanceCommitIndex": "Cmt",
    "bootstrap": "Boot",
    None: "",
    "SignCommittableMessages": "Rpl",
    "SIMTimeout": "Tmou",
    "RcvUpdateTerm": "UTrm",
    "SIMCheckQuorum": "ChkQ",
}

TAG = {"Y": ":white_check_mark:", "N": ":x:", " ": "  ", "S": ":pencil:"}


def digits(value):
    return len(str(value))


def diffed_key(old, new, key, suffix, size):
    if old is None or old[key] == new[key]:
        return f"{new[key]:>{size}}{suffix}"
    color = "bright_white on red"
    return f"[{color}]{new[key]:>{size}}{suffix}[/{color}]"


def render_state(state, func, old_state, tag, cfg):
    if state is None:
        return " "
    ls = LEADERSHIP_STATUS[state["leadership_state"]]
    nid = state["node_id"]
    v = diffed_key(old_state, state, "current_view", "", cfg.view)
    i = diffed_key(old_state, state, "last_idx", "", cfg.index)
    c = diffed_key(old_state, state, "commit_idx", "", cfg.commit)
    f = FUNCTIONS[func]
    opc = "bold bright_white on red" if func else "normal"
    return f"[{opc}]{nid:>{cfg.nodes}}{ls}{f:<4} [/{opc}]{TAG[tag]} {v}.{i} {c}"


class DigitsCfg:
    nodes = 0
    view = 0
    index = 0
    commit = 0
    ts = 0


def extract_node_state(global_state, node_id):
    return {
        "node_id": node_id,
        "leadership_state": global_state["leadershipState"][node_id],
        "current_view": global_state["currentTerm"][node_id],
        "last_idx": len(global_state["log"][node_id]),
        "commit_idx": global_state["commitIndex"][node_id],
    }


LOG = {
    "Reconfiguration": ":recycle:",
    "Signature": ":pencil:",
    "Entry": ":page_facing_up:",
}


def render_log(log, dcfg):
    term = 2
    chars = []
    for entry in log:
        if entry["term"] != term:
            term = entry["term"]
            chars.append(f" {term:>{dcfg.view}}")
        chars.append(LOG[entry["contentType"]])
    return "".join(chars)


def table(entries):
    nodes = []
    max_view = 0
    max_index = 0
    max_commit = 0
    max_ts = 0
    rows = []
    for pre, action, post in entries:
        node_id = action["context"]["i"]
        if node_id not in nodes:
            nodes.append(node_id)
        max_view = max(max_view, post[1]["currentTerm"][node_id])
        max_index = max(max_index, len(post[1]["log"][node_id]))
        max_commit = max(max_commit, post[1]["commitIndex"][node_id])
        max_ts += 1
    dcfg = DigitsCfg()
    dcfg.nodes = len(max(nodes, key=len))
    dcfg.view = digits(max_view)
    dcfg.index = digits(max_index)
    dcfg.commit = digits(max_commit)
    dcfg.ts = digits(max_ts)
    ts = 0
    for pre, action, post in entries:
        ts += 1
        node_id = action["context"]["i"]
        # TODO: need success, vote granted to be extracted from pre or post state
        tag = " "
        if action["name"] == "SignCommittableMessages":
            tag = "S"
        states = [
            (
                extract_node_state(post[1], node),
                action["name"] if node == node_id else None,
                extract_node_state(pre[1], node) if node == node_id else None,
                tag if node == node_id else " ",
            )
            for node in sorted(nodes)
        ]
        rows.append(
            f"[{ts:>{dcfg.ts}}] "
            + "     ".join(render_state(*state, dcfg) for state in states)
            + f"     {render_log(post[1]['log'][node_id], dcfg)}"
        )
    return rows


if __name__ == "__main__":
    with open(sys.argv[1]) as tf:
        for line in table(json.load(tf)["action"]):
            rich.print(line)
