#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import pathlib
import re
import shutil
import subprocess
import sys


HEADER = """---- MODULE RaftSeeds ----
EXTENDS ccfraft

CONSTANTS
    PV_PreVoteDisabled, PV_PreVoteCapable, PV_PreVoteEnabled,
    L_Follower, L_PreVoteCandidate, L_Candidate, L_Leader, L_None,
    R_Active, R_RetirementOrdered, R_RetirementSigned, R_RetirementCompleted, R_RetiredCommitted,
    M_RequestVoteRequest, M_RequestVoteResponse, M_AppendEntriesRequest, M_AppendEntriesResponse, M_ProposeVoteRequest,
    N_OrderedNoDup, N_Ordered, N_ReorderedNoDup, N_Reordered,
    T_Entry, T_Signature, T_Reconfiguration, T_Retired

VARIABLE seedId

"""


def run(*args):
    subprocess.run(args, check=True)


def extract_seed(module):
    text = module.read_text(encoding="utf-8")
    servers = re.search(r"^SeedServers == (?P<servers>.*)$", text, re.MULTILINE)
    seed_init = re.search(r"^SeedInit ==\n(?P<body>.*)^====$", text, re.MULTILINE | re.DOTALL)
    if servers is None or seed_init is None:
        raise ValueError(f"{module} is not a generated Raft seed module")
    return servers.group("servers"), seed_init.group("body").rstrip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("traces", nargs="+", type=pathlib.Path)
    args = parser.parse_args()

    work_dir = args.output.parent / f".{args.output.name}.tmp"
    shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True)

    servers = set()
    branches = []
    tlc = pathlib.Path(__file__).with_name("tlc.py")
    spec = pathlib.Path("consensus") / "Traceccfraft.tla"

    for trace in args.traces:
        seed_dir = work_dir / trace.stem
        run(
            sys.executable,
            str(tlc),
            "--workers",
            "1",
            "tv",
            "--disable-dfs",
            "--ccf-raft-trace",
            str(trace),
            "--seed-output-dir",
            str(seed_dir),
            str(spec),
        )
        seed_servers, seed_body = extract_seed(seed_dir / "RaftSeeds.tla")
        servers.update(re.findall(r'"[^"]+"', seed_servers))
        branches.append(seed_body)

    rendered_servers = "{" + ", ".join(sorted(servers)) + "}"
    rendered = []
    for branch in branches:
        lines = [line.strip() for line in branch.splitlines()]
        rendered.append("    \\/ " + lines[0])
        rendered.extend("       " + line for line in lines[1:])
    rendered_branches = "\n".join(rendered)
    args.output.write_text(
        f"{HEADER}SeedServers == {rendered_servers}\n\nSeedInit ==\n{rendered_branches}\n====\n",
        encoding="utf-8",
    )
    shutil.rmtree(work_dir)


if __name__ == "__main__":
    main()
