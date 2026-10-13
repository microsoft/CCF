#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Builds the runs that the recovery trace viewer shows.

Runs disaster-recovery-replay with --dump on each scenario's recorded traces in
fixtures/, on other directories of node logs with a scenario.json (--logs), and
on the invalid and valid traces stored as diffs against the recorded ones
(--trace SCENARIO/invalid/NAME or SCENARIO/valid/NAME, for
fixtures/SCENARIO/invalid/NAME.diff or fixtures/SCENARIO/valid/NAME.diff),
which it applies as check-fixtures.sh does. It writes the dumps and an index of
them to data/, and fails if the replayer writes no dump, or one whose outcome
disagrees with the replayer's exit code.
"""

import argparse
import json
import pathlib
import shutil
import subprocess
import tempfile

VIEWER = pathlib.Path(__file__).resolve().parent
REPLAYER = VIEWER.parent

DEFAULT_TRACES = [
    # A state check fails: node 0 records choosing itself where the model chooses 2
    "quorum/invalid/decision.chosen_not_max",
    # An outputs check fails: node 0 records gossiping TxID 2.22, not the model's 2.21
    "quorum/invalid/decision.txid_lie_send_only",
    # An action is disabled: node 0 retries once open, which the model does not allow
    "multiple-timeout/invalid/commit-order.retry_after_end",
    # The scenario fails: 3 nodes open or join, but scenario.json expects 2 participants
    "quorum/invalid/args.wrong_participants_arg",
    # Records that no commit order explains: node 2 receives its vote before sending it
    "quorum/invalid/causality.receive_before_send",
    # A log that does not parse: one of node 0's records is cut short
    "quorum/invalid/format.truncated_json",
]


def describe(diff: str) -> str:
    """How a stored trace differs from the recorded one, in short: the changed
    fields of each edited record or scenario.json member, and each deleted or
    inserted line."""

    def parse(line: str) -> dict | None:
        text = line.removeprefix("RDP_TRACE ").rstrip(",")
        try:
            value = json.loads(text if text.startswith("{") else "{" + text + "}")
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    def name(line: str) -> str:
        record = parse(line) or {}
        if "sequence" in record:
            return f"{record.get('node')}:{record['sequence']} ({record.get('kind')})"
        text = line.removeprefix("RDP_TRACE ").strip()
        return text[:40] + ("..." if len(text) > 40 else "")

    changes = []
    for hunk in diff.split("\n@@")[1:]:
        lines = hunk.splitlines()[1:]
        old = [line[1:] for line in lines if line[:1] == "-" and line[:4] != "--- "]
        new = [line[1:] for line in lines if line[:1] == "+" and line[:4] != "+++ "]
        for i in range(max(len(old), len(new))):
            if i >= len(new):
                changes.append(f"deleted {name(old[i])}")
            elif i >= len(old):
                changes.append(f"inserted {name(new[i])}")
            elif (a := parse(old[i])) and (b := parse(new[i])):
                where = f"{a.get('node')}:{a['sequence']} " if "sequence" in a else ""
                changes += [
                    f"{where}{key}: {a.get(key)} -> {b.get(key)}"
                    for key in sorted(a | b)
                    if a.get(key) != b.get(key)
                ]
            else:
                changes.append(f"{name(old[i])} -> {name(new[i])}")
    if len(changes) > 4:
        changes[4:] = [f"and {len(changes) - 4} more"]
    return "; ".join(changes)


def replay(run: dict, directory: pathlib.Path) -> dict:
    """Replays the logs in `directory` as its scenario.json says, and returns the
    run with its dump."""
    scenario = json.loads((directory / "scenario.json").read_text())
    run |= {"participants": scenario["participants"]}
    dump = VIEWER / "data" / f"{run['id']}.json"
    # Ids name dumps in data/, which starts empty and ends with index.json.
    if dump.exists() or dump.name == "index.json":
        raise SystemExit(
            f"run id {run['id']} is taken: rename the --logs directory,"
            " or drop the repeated --trace"
        )
    command = [REPLAYER / ".lake/build/bin/disaster-recovery-replay"]
    command += ["--participants", str(run["participants"])]
    command += ["--wait-ms", "0", "--dump", dump]
    names = sorted(p.name for p in directory.glob("*.out"))
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
    parser.add_argument("--trace", action="append", help="default: one per way")
    parser.add_argument("--logs", action="append", type=pathlib.Path, default=[])
    args = parser.parse_args()
    (VIEWER / "data").mkdir(exist_ok=True)
    for old in (VIEWER / "data").glob("*.json"):
        old.unlink()
    fixtures = REPLAYER / "fixtures"
    runs = []
    scenarios = sorted(p for p in fixtures.iterdir() if (p / "scenario.json").exists())
    for directory in scenarios + [p.resolve() for p in args.logs]:
        runs.append(replay({"id": directory.name, "title": directory.name}, directory))
    # The stored traces, by their paths under fixtures/ without .diff.
    stored = {
        path.relative_to(fixtures).with_suffix("").as_posix(): path
        for validity in ["invalid", "valid"]
        for path in fixtures.glob(f"*/{validity}/*.diff")
    }
    for ident in args.trace or DEFAULT_TRACES:
        diff = stored.get(ident)
        if diff is None:
            raise SystemExit(
                f"unknown trace {ident}: no fixtures/{ident}.diff under invalid/ or valid/"
            )
        scenario = diff.parent.parent.name
        run = {"id": ident.replace("/", "--"), "title": ident, "base": scenario}
        run |= {
            "valid": diff.parent.name == "valid",
            "change": describe(diff.read_text()),
        }
        with tempfile.TemporaryDirectory() as work:
            # The recorded traces with the diff applied, as check-fixtures.sh makes them.
            base = fixtures / scenario
            for path in [base / "scenario.json", *base.glob("*.out")]:
                shutil.copy(path, work)
            subprocess.run(
                ["git", "-C", work, "apply", "--unidiff-zero", diff], check=True
            )
            runs.append(replay(run, pathlib.Path(work)))
    (VIEWER / "data" / "index.json").write_text(json.dumps(runs, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
