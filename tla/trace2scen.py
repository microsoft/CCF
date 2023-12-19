# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
import os

def comment(action):
    return f"# {action['name']} {action['location']['module']}:{action['location']['beginLine']}"

def term(ctx, pre):
    return str(pre["currentTerm"][ctx['i']])

MAP = {
    "ClientRequest": lambda ctx, pre: ["replicate", term(ctx, pre), "42"],
    "MCClientRequest": lambda ctx, pre: ["replicate", term(ctx, pre), "42"],
    "CheckQuorum": lambda ctx, pre: ["periodic_one", ctx['i'], "110"],
    "Timeout": lambda ctx, pre: ["periodic_one",  ctx['i'], "110"],
    "MCTimeout": lambda ctx, pre: ["periodic_one",  ctx['i'], "110"],
    "RequestVote": lambda _, __: ["# Noop"],
    "AppendEntries": lambda _, __: ["dispatch_all"],
    "BecomeLeader": lambda _, __: ["# Noop"],
    "SignCommittableMessages": lambda ctx, pre: ["emit_signature", term(ctx, pre)],
    "MCSignCommittableMessages": lambda ctx, pre: ["emit_signature", term(ctx, pre)],
    "ChangeConfigurationInt": lambda ctx, pre: ["replicate_new_configuration", term(ctx, pre), *ctx['newConfiguration']],
    "MCChangeConfigurationInt": lambda ctx, pre: ["replicate_new_configuration", term(ctx, pre), *ctx['newConfiguration']],
    "ChangeConfiguration": lambda _, __: ["# Noop"],
    "AdvanceCommitIndex": lambda _, __: ["# Noop"],
    "HandleRequestVoteRequest": lambda _, __: ["dispatch_all"],
    "HandleRequestVoteResponse": lambda _, __: ["# Noop"],
    "RejectAppendEntriesRequest": lambda _, __: ["# Noop"],
    "ReturnToFollowerState": lambda _, __: ["# Noop"],
    "AppendEntriesAlreadyDone": lambda _, __: ["# Noop"],
}

def step_to_action(pre_state, action, post_state):
    return os.linesep.join([
        comment(action),
        ','.join(MAP[action['name']](action['context'], pre_state[1]))])

if __name__ == "__main__":
    with open(sys.argv[1]) as trace:
        steps = json.load(trace)["action"]
        initial_state = steps[0][0][1]
        initial_node, = [node for node, log in initial_state["log"].items() if log]
        print(f"start_node,{initial_node}")
        print(f"emit_signature,2")
        for step in steps:
            print(step_to_action(*step))