# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
import os

def comment(action):
    return f"# {action['name']} {action['location']['module']}:{action['location']['beginLine']}"

MAP = {
    "ClientRequest": lambda ctx: ["replicate", ctx['i'], "42"],
    "MCClientRequest": lambda ctx: ["replicate", ctx['i'], "42"],
    "CheckQuorum": lambda ctx: ["periodic_one", ctx['i'], "110"],
    "Timeout": lambda ctx: ["periodic_one",  ctx['i'], "110"],
    "MCTimeout": lambda ctx: ["periodic_one",  ctx['i'], "110"],
    "RequestVote": lambda _: ["# Noop"],
    "AppendEntries": lambda _: ["dispatch_all"],
    "BecomeLeader": lambda _: ["# Noop"],
    "SignCommittableMessages": lambda ctx: ["emit_signature", ctx['i']],
    "MCSignCommittableMessages": lambda ctx: ["emit_signature", ctx['i']],
    "ChangeConfigurationInt": lambda ctx: ["replicate_new_configuration", ctx['i'], *ctx['newConfiguration']],
    "MCChangeConfigurationInt": lambda ctx: ["replicate_new_configuration", ctx['i'], *ctx['newConfiguration']],
    "ChangeConfiguration": lambda _: ["# Noop"],
    "AdvanceCommitIndex": lambda _: ["# Noop"],
    "HandleRequestVoteRequest": lambda _: ["dispatch_all"],
    "HandleRequestVoteResponse": lambda _: ["# Noop"],
    "RejectAppendEntriesRequest": lambda _: ["# Noop"],
    "ReturnToFollowerState": lambda _: ["# Noop"],
    "AppendEntriesAlreadyDone": lambda _: ["# Noop"],
}

def step_to_action(pre_state, action, post_state):
    return os.linesep.join([
        comment(action),
        ','.join(MAP[action['name']](action['context']))])

if __name__ == "__main__":
    with open(sys.argv[1]) as trace:
        steps = json.load(trace)["action"]
        initial_state = steps[0][0][1]
        initial_node, = [node for node, log in initial_state["log"].items() if log]
        print(f"start_node,{initial_node}")
        print(f"emit_signature,2")
        for step in steps:
            print(step_to_action(*step))