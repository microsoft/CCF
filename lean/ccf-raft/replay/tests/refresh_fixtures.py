# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Refresh positive fixtures from actual native event captures."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(SOURCE / "tests"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_fixture(name, original, start, stop, output):
    selected = original.read_bytes().splitlines(keepends=True)[start:stop]
    if not selected or any(
        json.loads(line).get("tag") != "ccf.raft_trace" for line in selected
    ):
        raise ValueError(f"{original}: expected current ccf.raft_trace envelopes")
    destination = output / name
    destination.write_bytes(b"".join(selected))
    return {
        "fixture": name,
        "fixture_sha256": sha256(destination),
        "capture": str(original.resolve()),
        "capture_sha256": sha256(original),
        "first_line": start + 1,
        "last_line": start + len(selected),
    }


def main():
    from raft_trace_capture import capture

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=True)
    scenario = args.evidence / "events.scenario"
    scenario.write_text(
        "start_node,0\n"
        "emit_signature,2\n"
        "trust_node,2,1\n"
        "emit_signature,2\n"
        "dispatch_all\n"
        "periodic_one,0,10\n"
        "drop_pending_to,0,1\n"
        "periodic_one,0,10\n"
        "dispatch_single,0,1\n"
        "state_all\n",
        encoding="utf-8",
    )
    raw = args.evidence / "events.stdout"
    capture(args.driver, scenario, raw)
    lines = raw.read_bytes().splitlines(keepends=True)
    records = [json.loads(line) for line in lines]

    def command(name):
        return next(
            index
            for index, record in enumerate(records)
            if record["msg"].get("cmd") == name
        )

    trust = command("trust_node,2,1")
    dispatch = command("dispatch_all")
    periodic = command("periodic_one,0,10")
    end = command("state_all")
    fixtures = [
        ("bootstrap.ndjson", raw, 0, trust),
        ("configuration_callback.ndjson", raw, trust, dispatch),
        ("missing_prefix_response.ndjson", raw, dispatch, periodic),
        ("drop_resend.ndjson", raw, 0, end),
    ]
    for name, scenario_name in (
        ("startup.ndjson", "startup"),
        ("vote_responses.ndjson", "pre_vote"),
        ("retire_follower.stdout", "retire_one"),
        ("self_quorum.stdout", "reconfig_0_1"),
        ("nominate_successor.stdout", "nominate_successor"),
    ):
        fixtures.append((name, args.captures / f"{scenario_name}.stdout", 0, None))
    origins = [
        copy_fixture(name, original, start, stop, args.output)
        for name, original, start, stop in fixtures
    ]
    report = {
        "driver_sha256": sha256(args.driver),
        "scenario_sha256": sha256(scenario),
        "origins": origins,
    }
    (args.evidence / "fixture-origins.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
