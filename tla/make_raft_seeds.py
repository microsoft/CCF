#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import pathlib
import re
import shutil
import subprocess
import sys


def extract_seed(module):
    text = module.read_text(encoding="utf-8")
    seed = re.search(
        r"(?P<prefix>.*^SeedServers == )(?P<servers>.*)\n\nSeedInit ==\n(?P<body>.*)^====$",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if seed is None:
        raise ValueError(f"{module} is not a generated Raft seed module")
    return seed.group("prefix"), seed.group("servers"), seed.group("body").rstrip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--module",
        default=None,
        help="Generated TLA module name, defaults to the output file stem",
    )
    parser.add_argument("traces", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    module_name = args.module or args.output.stem

    work_dir = args.output.parent / f".{args.output.name}.tmp"
    shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True)

    seed_servers = None
    branches = []
    module_prefix = None
    tlc = pathlib.Path(__file__).with_name("tlc.py")
    spec = pathlib.Path("consensus") / "Traceccfraft.tla"

    for trace in sorted(args.traces):
        seed_dir = work_dir / trace.stem
        subprocess.run(
            (
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
            ),
            check=True,
        )
        seed_module = seed_dir / "RaftSeeds.tla"
        if not seed_module.exists():
            continue

        seed_prefix, trace_servers, seed_body = extract_seed(seed_module)
        seed_prefix = seed_prefix.replace(
            "---- MODULE RaftSeeds ----", f"---- MODULE {module_name} ----", 1
        )
        if module_prefix is None:
            module_prefix = seed_prefix
        elif module_prefix != seed_prefix:
            raise ValueError("Seed modules use different headers")

        if seed_servers is None:
            seed_servers = trace_servers
        elif seed_servers != trace_servers:
            raise ValueError(
                f"{trace} has SeedServers {trace_servers}, expected {seed_servers}"
            )
        branches.append(seed_body)

    if not branches or seed_servers is None or module_prefix is None:
        raise ValueError("No seed markers found in the provided traces")

    rendered = []
    for branch in branches:
        lines = [line.strip() for line in branch.splitlines()]
        rendered.append("    \\/ " + lines[0])
        rendered.extend("       " + line for line in lines[1:])
    rendered_branches = "\n".join(rendered)
    args.output.write_text(
        f"{module_prefix}{seed_servers}\n\nSeedInit ==\n{rendered_branches}\n====\n",
        encoding="utf-8",
    )
    shutil.rmtree(work_dir)


if __name__ == "__main__":
    main()
