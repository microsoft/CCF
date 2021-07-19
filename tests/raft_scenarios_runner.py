# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
from subprocess import Popen, PIPE
from raft_scenarios_gen import generate_scenarios
from contextlib import contextmanager


def scenarios(path):
    for scenario in sorted(os.listdir(path)):
        yield os.path.join(path, scenario)


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
        errors = [(error[0], error[1].replace('\n', ' <br> ')) for error in errors]
        scenario_len = max(len('Scenario'), *(len(error[0]) for error in errors))
        stderr_len = max(len('stderr'), *(len(error[1]) for error in errors))
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


if __name__ == "__main__":
    driver, path, doc = sys.argv[1], sys.argv[2], sys.argv[3]
    err_list = []
    test_result = True

    generate_scenarios(path)

    ostream = sys.stdout

    for scenario in scenarios(path):
        ostream.write("## {}\n\n".format(os.path.basename(scenario)))
        with block(ostream, "steps", 3):
            with open(scenario, "r") as scen:
                ostream.write(scen.read())
        proc = Popen(
            [driver, os.path.realpath(scenario)],
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
