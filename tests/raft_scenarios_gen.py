# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
from random import randrange, choice
from itertools import combinations, count


def fully_connected_scenario(nodes, steps):
    index = count(start=1)
    step_def = {
        0: lambda: "dispatch_all",
        1: lambda: "periodic_all,{}".format(randrange(500)),
        2: lambda: "replicate,0,{},{}".format(next(index), "hello"),
    }

    lines = ["nodes,{}".format(nodes)]
    for first, second in combinations(range(nodes), 2):
        lines.append("connect,{},{}".format(first, second))
    # Get past the initial election
    lines.append("periodic_all,110")
    lines.append("dispatch_all")
    for _ in range(steps):
        lines.append(step_def[choice(list(step_def.keys()))]())

    return "\n".join(lines)


def generate_scenarios(tgt_dir):
    NODES = 3
    SCENARIOS = 3
    STEPS = 25

    for scen_index in range(SCENARIOS):
        with open(os.path.join(tgt_dir, "scenario-{}".format(scen_index)), "w") as scen:
            scen.write(fully_connected_scenario(NODES, STEPS) + "\n")


if __name__ == "__main__":
    tgt_dir = sys.argv[1]
    generate_scenarios(tgt_dir)
