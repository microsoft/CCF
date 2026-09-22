# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from contextlib import contextmanager
from heapq import merge

from raft_scenarios_gen import generate_scenarios
from raft_trace import as_log_lines, check_connection_timeout, run_driver

import msgpack


@contextmanager
def block(fd, title, level, lang=None, lines=None):
    fd.write(level * "#" + " " + title + "\n\n")
    fd.write("```" + (lang or "") + "\n")
    for line in lines or []:
        fd.write(line + "\n")
    yield
    fd.write("\n```\n\n")


def write_error_report(errors=None):
    if errors:
        errors = [(error[0], error[1].replace("\n", " <br> ")) for error in errors]
        scenario_len = max(len("Scenario"), *(len(error[0]) for error in errors))
        stderr_len = max(len("stderr"), *(len(error[1]) for error in errors))
        print("???+ error \n")
        fmt_s = f"   | {{:<{scenario_len}}} | {{:<{stderr_len}}} |\n"
        print(fmt_s.format("Scenario", "stderr"))
        print(fmt_s.format("-" * scenario_len, "-" * stderr_len))
        for error in errors:
            print(fmt_s.format(error[0], error[1]))
    else:
        print("??? success \n")


def preprocess_for_trace_validation(log):
    """
    For each node, remove the last "replicate" or "execute_append_entries_sync"
    preceding an "add_configuration" entry. For the first node, check the initial
    expected sequence of "become_leader", "add_configuration", "replicate" (committable),
    followed by "commit", and replace it with a "bootstrap" entry.
    """
    # Scenarios without commands produce no trace records.
    if not log:
        return log
    log_by_node = defaultdict(list)
    initial_node = None
    last_cmd = ""
    for line in log:
        entry = json.loads(line)
        if "cmd" in entry and len(entry["cmd"]) > 0:
            last_cmd = entry["cmd"]
            continue
        node = entry["msg"]["state"]["node_id"]
        entry["cmd"] = last_cmd
        entry["cmd_prefix"] = entry["cmd"].split(",")[0]
        if initial_node is None:
            initial_node = node
        if entry["msg"]["function"] == "add_configuration":
            removed = log_by_node[node].pop()
            assert removed["msg"]["function"] in (
                "replicate",
                "execute_append_entries_sync",
            ), removed
            entry["cmd"] = entry["cmd"] or removed["cmd"]
        log_by_node[node].append(entry)

        # Collapse propose_vote->become_candidate to just propose_vote
        if len(log_by_node[node]) >= 2 and [
            e["msg"]["function"] for e in log_by_node[node][-2:]
        ] == ["recv_propose_request_vote", "become_candidate"]:
            bc = log_by_node[node].pop()
            pr = log_by_node[node].pop()
            assert bc["cmd"] == pr["cmd"], f"Command mismatch between {pr} and {bc}"
            log_by_node[node].append(pr)

    def head():
        return log_by_node[initial_node].pop(0)

    assert head()["msg"]["function"] == "become_leader"
    assert head()["msg"]["function"] == "add_configuration"
    signature = head()
    assert signature["msg"]["function"] == "replicate", signature
    assert signature["msg"]["globally_committable"], signature
    commit = head()
    assert commit["msg"]["function"] == "commit", commit
    assert commit["msg"]["idx"] == 2, commit
    # Commit becomes bootstrap, the entry point into the trace validation
    commit["msg"]["function"] = "bootstrap"
    log_by_node[initial_node].insert(0, commit)
    return [
        json.dumps(e)
        for e in merge(*log_by_node.values(), key=lambda e: int(e["h_ts"]))
    ]


def noop(log):
    return log


def flatten_legacy_trace(message):
    """Adapt baseline-driver payloads from before commit/configuration flattening."""
    if "args" not in message:
        return message
    function = message.get("function")
    if function not in ("commit", "add_configuration"):
        return message
    flattened = {}
    for key, value in message.items():
        if key == "args":
            flattened.update(value if function == "commit" else value["configuration"])
        else:
            flattened[key] = value
    return flattened


def separate_log_lines(text, preprocess):
    mermaid = []
    log = []
    for line in text.split(os.linesep):
        if line.startswith("<RaftDriver>"):
            mermaid.append(line[len("<RaftDriver>") :])
        elif '"raft_trace"' in line:
            log.append(line)
    return (
        os.linesep.join(mermaid) + os.linesep,
        os.linesep.join(preprocess(log)) + os.linesep,
    )


def expand_files(files):
    all_files = []
    for path in files:
        if os.path.isdir(path):
            for dirpath, _, filenames in os.walk(path):
                for name in filenames:
                    all_files.append(os.path.join(dirpath, name))
        else:
            all_files.append(path)
    return all_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("driver", type=str, help="Path to raft_driver binary")
    parser.add_argument("--gen-scenarios", action="store_true")
    parser.add_argument(
        "--raft-tracing",
        action="store_true",
        help="Capture Raft traces from the driver through a local TCP collector",
    )
    parser.add_argument(
        "--compare-driver",
        help="Compare ordered trace payloads, flattening legacy baseline arguments",
    )
    parser.add_argument("files", nargs="*", type=str, help="Path to scenario files")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output directory",
        default=os.path.join("consensus"),
    )

    args = parser.parse_args()
    if args.compare_driver and not args.raft_tracing:
        parser.error("--compare-driver requires --raft-tracing")

    err_list = []
    test_result = True

    files = expand_files(args.files)

    if args.gen_scenarios:
        files += generate_scenarios()

    ostream = sys.stdout

    if args.raft_tracing and files:
        check_connection_timeout(args.driver, files[0])

    # Create consensus-specific output directory
    os.makedirs(args.output, exist_ok=True)

    for scenario in files:
        ostream.write(f"## {os.path.basename(scenario)}\n\n")
        with block(ostream, "steps", 3), open(scenario, "r", encoding="utf-8") as scen:
            ostream.write(scen.read())
        records = []
        if args.raft_tracing:
            proc, records = run_driver(args.driver, scenario)
            if args.compare_driver:
                baseline, baseline_records = run_driver(args.compare_driver, scenario)
                assert baseline.returncode == 0, baseline.stderr
                assert len(records) == len(baseline_records), scenario
                for index, (record, previous) in enumerate(
                    zip(records, baseline_records)
                ):
                    message = record["msg"]
                    if (
                        message.get("function") == "drop_pending_to"
                        and "committable_indices" not in previous["msg"]["state"]
                    ):
                        # Only baseline comparison omits this legacy missing field.
                        state = dict(message["state"])
                        del state["committable_indices"]
                        message = {**message, "state": state}
                    # Repacking retains map order but excludes process IDs and time.
                    assert msgpack.packb(message) == msgpack.packb(
                        flatten_legacy_trace(previous["msg"])
                    ), (scenario, index, record["msg"], previous["msg"])
        else:
            proc = subprocess.run(
                [args.driver, os.path.realpath(scenario)],
                capture_output=True,
                text=True,
                check=False,
            )
        out, err = proc.stdout, proc.stderr
        test_result = test_result and proc.returncode == 0

        if err:
            err_list.append([os.path.basename(scenario), err])
            with block(ostream, "stderr", 3):
                ostream.write(err)

        mermaid, log = separate_log_lines(
            out + "\n" + "\n".join(json.dumps(e) for e in as_log_lines(records)),
            noop if "deprecated" in scenario else preprocess_for_trace_validation,
        )

        with block(ostream, "diagram", 3, "mermaid", ["sequenceDiagram"]):
            ostream.write(mermaid)

        ## Do not create an empty ndjson file if log is emtpy.
        if log:
            with open(
                os.path.join(args.output, f"{os.path.basename(scenario)}.ndjson"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(log)

    write_error_report(err_list)

    if not test_result or err_list:
        sys.exit(1)
