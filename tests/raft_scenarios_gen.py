# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
from random import randrange, choice, choices
from itertools import combinations, count


def fully_connected_scenario(nodes, steps):
    index = count(start=1)
    step_def = {
        0: lambda: "dispatch_all",
        # Most of the time, advance by a small periodic amount. Occasionally time out long enough to trigger an election
        1: lambda: "periodic_all,{}".format(
            choices([randrange(20), randrange(100, 500)], weights=[10, 1])[0]
        ),
        2: lambda: "replicate,latest,{}".format(f"hello {next(index)}"),
    }

    # Define the nodes
    lines = ["nodes,{}".format(",".join(str(n) for n in range(nodes)))]

    for first, second in combinations(range(nodes), 2):
        lines.append("connect,{},{}".format(first, second))

    # Get past the initial election
    lines.append("periodic_one,0,110")
    lines.append("dispatch_all")
    lines.append("periodic_all,30")
    lines.append("dispatch_all")
    lines.append("state_all")
    for _ in range(steps):
        lines.append(step_def[choice(list(step_def.keys()))]())

    lines.append("state_all")

    # Allow the network to reconcile, and assert it reaches a stable state

    # It is likely this scenario has resulted in a lot of elections and very little commit advancement.
    # To reach a stable state, we need to give each node a chance to win an election and share their state.
    # In a real network, we expect this to arise from the randomised election timeouts, and it is sufficient
    # for one of a quorum of nodes to win and share their state. This exhaustive approach ensures convergence,
    # even in the pessimal case.
    for node in range(nodes):
        lines.append(f"periodic_one,{node},100")
        lines.append("dispatch_all")
        lines.append("replicate,latest,CommitConfirmer")
        lines.append("periodic_all,10")
        lines.append("dispatch_all")
        lines.append("periodic_all,10")
        lines.append("dispatch_all")
        lines.append("state_all")

    lines.append("assert_state_sync")

    return "\n".join(lines)


def generate_scenarios(tgt_dir="."):
    NODES = 3
    SCENARIOS = 3
    STEPS = 25

    scenario_paths = []
    for scen_index in range(SCENARIOS):
        with open(
            os.path.join(tgt_dir, "scenario-{}".format(scen_index)),
            "w",
            encoding="utf-8",
        ) as scen:
            scen.write(fully_connected_scenario(NODES, STEPS) + "\n")
            scenario_paths.append(os.path.realpath(scen.name))

    return scenario_paths


if __name__ == "__main__":
    tgt_dir = sys.argv[1]
    generate_scenarios(tgt_dir)
