# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import sys
import os
import json
from subprocess import Popen, PIPE
from raft_scenarios_gen import generate_scenarios
from contextlib import contextmanager
from collections import defaultdict
from heapq import merge


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
        fmt_s = "   | {{:<{}}} | {{:<{}}} |\n".format(scenario_len, stderr_len)
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
    # Log may be empty if CCF_RAFT_TRACING=OFF
    if not log:
        return log
    log_by_node = defaultdict(list)
    initial_node = None
    last_cmd = ""
    for line in log:
        entry = json.loads(line)
        if "cmd" in entry:
            last_cmd = entry["cmd"]
            continue
        node = entry["msg"]["state"]["node_id"]
        entry["cmd"] = last_cmd
        entry["cmd_prefix"] = entry["cmd"].split(",")[0]
        last_cmd = ""
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

    def head():
        return log_by_node[initial_node].pop(0)

    assert head()["msg"]["function"] == "become_leader"
    assert head()["msg"]["function"] == "add_configuration"
    signature = head()
    assert signature["msg"]["function"] == "replicate", signature
    assert signature["msg"]["globally_committable"], signature
    commit = head()
    assert commit["msg"]["function"] == "commit", commit
    assert commit["msg"]["args"]["idx"] == 2, commit
    # Commit becomes bootstrap, the entry point into the trace validation
    commit["msg"]["function"] = "bootstrap"
    log_by_node[initial_node].insert(0, commit)
    return [
        json.dumps(e)
        for e in merge(*log_by_node.values(), key=lambda e: int(e["h_ts"]))
    ]


def noop(log):
    return log


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
    parser.add_argument("files", nargs="*", type=str, help="Path to scenario files")
    parser.add_argument(
        "-o", "--output", type=str, help="Output directory", default=os.path.join("consensus")
    )

    args = parser.parse_args()

    err_list = []
    test_result = True

    files = expand_files(args.files)

    if args.gen_scenarios:
        files += generate_scenarios()

    ostream = sys.stdout

    # Create consensus-specific output directory
    if args.output is None:
        output_dir = os.path.join("consensus")
    else:
        output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    for scenario in files:
        ostream.write("## {}\n\n".format(os.path.basename(scenario)))
        with block(ostream, "steps", 3):
            with open(scenario, "r", encoding="utf-8") as scen:
                ostream.write(scen.read())
        proc = Popen(
            [args.driver, os.path.realpath(scenario)],
            stdout=PIPE,
            stderr=PIPE,
            stdin=PIPE,
        )
        out, err = proc.communicate()
        test_result = test_result and proc.returncode == 0

        if err:
            err_list.append([os.path.basename(scenario), err.decode()])
            with block(ostream, "stderr", 3):
                ostream.write(err.decode())

        mermaid, log = separate_log_lines(
            out.decode(),
            noop if "deprecated" in scenario else preprocess_for_trace_validation,
        )

        with block(ostream, "diagram", 3, "mermaid", ["sequenceDiagram"]):
            ostream.write(mermaid)

        ## Do not create an empty ndjson file if log is emtpy.
        if log:
            with open(
                os.path.join(output_dir, f"{os.path.basename(scenario)}.ndjson"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(log)

    write_error_report(err_list)

    if not test_result or err_list:
        sys.exit(1)
