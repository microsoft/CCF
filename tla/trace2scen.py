# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
import os

def comment(action):
    return f"# {action['name']} {action['location']['module']}:{action['location']['beginLine']}"

def term(ctx, pre):
    return str(pre["currentTerm"][ctx['i']])

def new_config(ctx, post):
    return sorted(post["configurations"][ctx["i"]].items())[-1][1]

MAP = {
    "ClientRequest": lambda ctx, pre, post: ["replicate", term(ctx, pre), "42"],
    "MCClientRequest": lambda ctx, pre, post: ["replicate", term(ctx, pre), "42"],
    "CheckQuorum": lambda ctx, pre, post: ["periodic_one", ctx['i'], "110"],
    "Timeout": lambda ctx, pre, post: ["periodic_one",  ctx['i'], "110"],
    "MCTimeout": lambda ctx, pre, post: ["periodic_one",  ctx['i'], "110"],
    "RequestVote": lambda _, __, ___: ["# Noop"],
    "AppendEntries": lambda _, __, ___: ["dispatch_all"],
    "BecomeLeader": lambda _, __, ___: ["# Noop"],
    "SignCommittableMessages": lambda ctx, pre, post: ["emit_signature", term(ctx, pre)],
    "MCSignCommittableMessages": lambda ctx, pre, post: ["emit_signature", term(ctx, pre)],
    "ChangeConfiguration": lambda ctx, pre, post: ["replicate_new_configuration", term(ctx, pre), *new_config(ctx, post)],
    "AdvanceCommitIndex": lambda _, __, ___: ["# Noop"],
    "HandleRequestVoteRequest": lambda _, __, ___: ["dispatch_all"],
    "HandleRequestVoteResponse": lambda _, __, ___: ["# Noop"],
    "RejectAppendEntriesRequest": lambda _, __, ___: ["# Noop"],
    "ReturnToFollowerState": lambda _, __, ___: ["# Noop"],
    "AppendEntriesAlreadyDone": lambda _, __, ___: ["# Noop"],
}

def post_commit(post):
    return [["assert_commit_idx", node, str(idx)] for node, idx in post["commitIndex"].items()]

def post_state(post):
    entries = []
    for node, state in post["state"].items():
        if state == "Leader":
            entries.append(["assert_is_primary", node])
        elif state == "Follower":
            entries.append(["assert_is_backup", node])
        elif state == "Candidate":
            entries.append(["assert_is_candidate", node])
    return entries

def step_to_action(pre_state, action, post_state):
    return os.linesep.join([
        comment(action),
        ','.join(MAP[action['name']](action['context'], pre_state[1], post_state[1]))])

def asserts(pre_state, action, post_state, assert_gen):
    return os.linesep.join([','.join(assertion) for assertion in assert_gen(post_state[1])])

if __name__ == "__main__":
    with open(sys.argv[1]) as trace:
        steps = json.load(trace)["action"]
        initial_state = steps[0][0][1]
        initial_node, = [node for node, log in initial_state["log"].items() if log]
        print(f"start_node,{initial_node}")
        print(f"emit_signature,2")
        for step in steps:
            print(step_to_action(*step))
            print(asserts(*step, post_state))
        print(asserts(*steps[-1], post_commit))