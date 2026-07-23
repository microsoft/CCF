# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import pathlib
import shutil
import subprocess
import sys


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raft-driver", required=True)
    parser.add_argument("--tla-dir", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()

    output_dir = args.output_dir
    shutil.rmtree(output_dir, ignore_errors=True)
    seed_export_dir = output_dir / "export"
    run(
        sys.executable,
        str(pathlib.Path(__file__).with_name("raft_seed_export_test.py")),
        "--raft-driver",
        args.raft_driver,
        "--tla-dir",
        str(args.tla_dir),
        "--output-dir",
        str(seed_export_dir),
    )

    seed_src = seed_export_dir / "seeds" / "RaftSeed_marked_startup_after_signature.tla"
    seed_dst = args.tla_dir / "consensus" / "RaftSeeds.tla"
    shutil.copyfile(seed_src, seed_dst)
    try:
        run(
            str(args.tla_dir / "tlc.py"),
            "sim",
            "--depth",
            "5",
            "--max-seconds",
            "10",
            "consensus/SeededSIMccfraft.tla",
            cwd=args.tla_dir,
        )
    finally:
        seed_dst.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
