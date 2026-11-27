#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture virtual recovery-decision-protocol traces and replay them in Lean."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

TRACE_CASES = {
    "Recovery trace quorum open complete": "quorum_open_complete",
    "Recovery trace voting zero votes timeout failover": (
        "voting_zero_votes_timeout_failover"
    ),
    "Recovery trace protocol rejections": "protocol_rejections",
}

REQUIRED_SCENARIO_EVENTS = {
    "quorum_open_complete": {
        "start",
        "send:gossip",
        "send:vote",
        "send:iamopen",
        "gossip_accepted",
        "vote_accepted",
        "iamopen_accepted",
        "open_kind:Quorum",
        "restart:true",
        "transition:Opening->Open",
        "timeout:Open->Open",
    },
    "voting_zero_votes_timeout_failover": {
        "start",
        "send:gossip",
        "send:vote",
        "send:iamopen",
        "gossip_accepted",
        "vote_accepted",
        "iamopen_accepted",
        "open_kind:Failover",
        "restart:true",
        "timeout:Voting_zero_votes_noop",
        "transition:Opening->Open",
        "timeout:Open->Open",
    },
    "protocol_rejections": {
        "start",
        "send:gossip",
        "send:vote",
        "send:iamopen",
        "gossip_accepted",
        "vote_accepted",
        "iamopen_accepted",
        "open_kind:Quorum",
        "restart:true",
        "transition:Opening->Open",
        "timeout:Open->Open",
    },
}

MARKER = "RDP_TRACE "


def check_case_list(binary: Path) -> None:
    """Verify every 'Recovery trace *' test case is covered by TRACE_CASES."""
    listing = subprocess.run(
        [
            str(binary),
            "--list-test-cases",
            "--test-case=Recovery trace *",
            "--case-sensitive=true",
            "--reporters=xml",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    listed = {
        case.get("name") for case in ElementTree.fromstring(listing).iter("TestCase")
    }
    expected = set(TRACE_CASES)
    if listed != expected:
        raise RuntimeError(
            f"Recovery trace test cases {sorted(listed)} do not match "
            f"the runner's {sorted(expected)}"
        )


def collect_events(logs: list[Path]) -> set[str]:
    """Summarize the protocol transitions observed in a scenario's RDP_TRACE logs."""
    observed: set[str] = set()
    for path in logs:
        for line in path.read_text(encoding="utf-8").splitlines():
            _, marker, body = line.partition(MARKER)
            if not marker:
                continue
            record = json.loads(body)
            kind = record["kind"]
            if kind == "send":
                observed.add(f"send:{record['message']}")
            else:
                observed.add(kind)
            if "open_kind" in record:
                observed.add(f"open_kind:{record['open_kind']}")
            if record.get("restart") is True:
                observed.add("restart:true")
            if kind == "timeout":
                pre = record["pre"]
                post = record["post"]
                pre_t = record["pre_timeout"]
                post_t = record["post_timeout"]
                if pre == "Opening" and post == "Open":
                    observed.add("transition:Opening->Open")
                if pre == "Open" and post == "Open":
                    observed.add("timeout:Open->Open")
                if (
                    pre == "Voting"
                    and post == "Voting"
                    and pre_t == "Voting"
                    and post_t == "Voting"
                ):
                    observed.add("timeout:Voting_zero_votes_noop")
    return observed


def run_capture(binary: Path, output_dir: Path, timeout: int) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["CCF_RECOVERY_TRACE"] = "1"
    env["CCF_RDP_TRACE_OUTPUT_DIR"] = str(output_dir)

    result = subprocess.run(
        [
            str(binary),
            "--test-case=Recovery trace *",
            "--case-sensitive=true",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Trace capture failed with exit code {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )


def validate_scenario(
    scenario_dir: Path,
    scenario_name: str,
    checker: Path | None,
    schema_script: Path | None,
    timeout: int,
) -> None:
    meta_path = scenario_dir / "scenario.json"
    if not meta_path.is_file():
        raise RuntimeError(f"Missing scenario metadata: {meta_path}")
    participants = int(
        json.loads(meta_path.read_text(encoding="utf-8"))["participants"]
    )
    logs = sorted(scenario_dir.glob("*.out"))
    if len(logs) != participants:
        raise RuntimeError(
            f"Scenario {scenario_name}: expected {participants} node logs, "
            f"found {len(logs)}"
        )

    observed = collect_events(logs)
    missing = REQUIRED_SCENARIO_EVENTS[scenario_name] - observed
    if missing:
        raise RuntimeError(
            f"Scenario {scenario_name} is missing required trace events: "
            f"{sorted(missing)}"
        )

    if schema_script is not None:
        schema_res = subprocess.run(
            [sys.executable, str(schema_script), *(str(p) for p in logs)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if schema_res.returncode != 0:
            raise RuntimeError(
                f"Schema validation failed for {scenario_name}:\n"
                f"{schema_res.stdout}{schema_res.stderr}"
            )
        print(f"[schema] {scenario_name}: {schema_res.stdout.strip()}")

    if checker is not None:
        replay_res = subprocess.run(
            [
                str(checker),
                "--wait-ms",
                "0",
                "--participants",
                str(participants),
                *(str(p) for p in logs),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if replay_res.returncode != 0:
            raise RuntimeError(
                f"Lean replay failed for {scenario_name}:\n"
                f"{replay_res.stdout}{replay_res.stderr}"
            )
        print(f"[replay] {scenario_name}: {replay_res.stdout.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        required=True,
        type=Path,
        help="Path to recovery_decision_protocol_test binary",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Directory where per-scenario RDP_TRACE logs are written",
    )
    parser.add_argument(
        "--checker",
        type=Path,
        default=None,
        help="Path to disaster-recovery-replay executable",
    )
    parser.add_argument(
        "--schema-script",
        type=Path,
        default=None,
        help="Optional path to lean/disaster-recovery/replayer/check-schema.py",
    )
    parser.add_argument(
        "--capture-only",
        action="store_true",
        help="Capture and check required events without invoking --checker",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds for each subprocess",
    )
    args = parser.parse_args()

    if not args.capture_only and args.checker is None:
        parser.error("--checker is required unless --capture-only is set")

    check_case_list(args.binary)
    run_capture(args.binary, args.output, args.timeout)

    for scenario_name in sorted(TRACE_CASES.values()):
        validate_scenario(
            args.output / scenario_name,
            scenario_name,
            None if args.capture_only else args.checker,
            args.schema_script,
            args.timeout,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
