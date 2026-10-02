#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Builds the runs that the recovery trace viewer shows.

Runs disaster-recovery-replay with --dump on each replay fixture, on other
directories of node logs with a scenario.json (--logs), and on mutants of the
fixtures from tests/infra/recovery_trace_mutations.py (--mutant, named
SCENARIO/GROUP/NAME as in its report), and writes the dumps and an index of
them to data/. It fails if the replayer writes no dump, or one whose outcome
disagrees with the replayer's exit code.
"""

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

VIEWER = pathlib.Path(__file__).resolve().parent
REPLAY = VIEWER.parent
sys.path.insert(0, str(REPLAY.parents[2] / "tests" / "infra"))

import recovery_trace_mutations as mutations

# One mutant per way a replay can stop: a state check, an outputs check, a
# disabled action, the scenario, records that no commit order explains, and a
# log that does not parse.
DEFAULT_MUTANTS = [
    "quorum/decision/chosen_not_max",
    "quorum/decision/txid_lie_send_only",
    "multiple-timeout/commit-order/retry_after_end",
    "quorum/args/wrong_open_kind_arg",
    "quorum/causality/receive_before_send",
    "quorum/format/truncated_json",
]


def replay(run: dict, directory: pathlib.Path, names: list[str]) -> dict:
    """Replays the named logs in `directory`, and returns the run with its dump."""
    dump = VIEWER / "data" / f"{run['id']}.json"
    # Ids name dumps in data/, which starts empty and ends with index.json.
    if dump.exists() or dump.name == "index.json":
        raise SystemExit(
            f"run id {run['id']} is taken: rename the --logs directory,"
            " or drop the repeated --mutant"
        )
    command = [REPLAY / ".lake/build/bin/disaster-recovery-replay"]
    command += ["--participants", str(run["participants"])]
    command += ["--open-kind", run["openKind"], "--wait-ms", "0", "--dump", dump]
    done = subprocess.run(
        command + names, cwd=directory, capture_output=True, text=True, check=False
    )
    output = (done.stdout + done.stderr).strip()
    ok = dump.exists() and json.loads(dump.read_text())["outcome"]["ok"]
    if not dump.exists() or ok != (done.returncode == 0):
        raise SystemExit(f"{run['id']}: no dump, or one the exit code disagrees with")
    print(f"{run['id']}: {output.splitlines()[-1] if output else 'no output'}")
    return run | {"dump": dump.name, "exitCode": done.returncode, "output": output}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutant", action="append", help="default: one per way")
    parser.add_argument("--logs", action="append", type=pathlib.Path, default=[])
    args = parser.parse_args()
    (VIEWER / "data").mkdir(exist_ok=True)
    for old in (VIEWER / "data").glob("*.json"):
        old.unlink()
    fixtures = REPLAY / "fixtures"
    runs = []
    scenarios = sorted(p for p in fixtures.iterdir() if (p / "scenario.json").exists())
    for directory in scenarios + [p.resolve() for p in args.logs]:
        scenario = json.loads((directory / "scenario.json").read_text())
        run = {"id": directory.name, "title": directory.name}
        run |= {"participants": scenario["participants"]}
        run |= {"openKind": scenario["open_kind"]}
        logs = sorted(p.name for p in directory.glob("*.out"))
        runs.append(replay(run, directory, logs))
    for ident in args.mutant or DEFAULT_MUTANTS:
        scenario, group, name = ident.split("/", 2)
        base = mutations.load_scenario(fixtures / scenario)
        jobs = mutations.build_jobs({scenario: base})
        found = [(e, s) for g, _, n, e, s in jobs if (g, n) == (group, name)]
        if not found:
            raise SystemExit(f"unknown or inapplicable mutant {ident}")
        expected, state = found[0]
        names = [p.name for p in sorted((fixtures / scenario).glob("*.out"))]
        run = {"id": ident.replace("/", "--").replace("#", "-"), "title": ident}
        run |= {"base": scenario, "expected": expected}
        run |= {"change": mutations.describe(base, state)}
        run |= {"participants": state["participants"], "openKind": state["open_kind"]}
        with tempfile.TemporaryDirectory() as work:
            for index in state["order"]:
                text = "".join(mutations.render(item) for item in state["logs"][index])
                (pathlib.Path(work) / names[index]).write_text(text, encoding="utf-8")
            runs.append(
                replay(run, pathlib.Path(work), [names[i] for i in state["order"]])
            )
    (VIEWER / "data" / "index.json").write_text(json.dumps(runs, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
