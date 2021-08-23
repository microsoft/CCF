# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import sys
import os
from subprocess import Popen, PIPE
from raft_scenarios_gen import generate_scenarios
from contextlib import contextmanager


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


def strip_log_lines(text):
    ol = []
    for line in text.split(os.linesep):
        if line.startswith("<RaftDriver>"):
            ol.append(line[len("<RaftDriver>") :])
    return os.linesep.join(ol)


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

    args = parser.parse_args()

    err_list = []
    test_result = True

    files = expand_files(args.files)

    if args.gen_scenarios:
        files += generate_scenarios()

    ostream = sys.stdout

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

        with block(ostream, "diagram", 3, "mermaid", ["sequenceDiagram"]):
            ostream.write(strip_log_lines(out.decode()))

    write_error_report(err_list)

    if not test_result or err_list:
        sys.exit(1)
