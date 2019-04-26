# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
from subprocess import Popen, PIPE
from raft_scenarios_gen import generate_scenarios
from contextlib import contextmanager

RAFT_TEST_FILE_NAME = "raft_tests.md"


def scenarios(path):
    for scenario in sorted(os.listdir(path)):
        yield os.path.join(path, scenario)


@contextmanager
def block(fd, title, level, lang=None, lines=None):
    fd.write(level * "#" + title + "\n\n")
    fd.write("```" + (lang or "") + "\n")
    for line in lines or []:
        fd.write(line + "\n")
    yield
    fd.write("\n```\n\n")


@contextmanager
def error_report_block(fd, errors=None):
    fd.seek(0, 0)
    if errors:
        fd.write("???+ error \n")
        fd.write(4 * " " + "| Scenario | stderr |\n")
        fd.write(4 * " " + "|----------|--------|\n")
        for error in errors:
            fd.write(4 * " " + "| " + error[0] + " | ")
            stderr_lines = error[1].split("\n")
            for err in stderr_lines:
                if err:
                    fd.write(4 * " " + "```" + err + "``` <br>")
            fd.write(4 * " " + "|\n")
    else:
        fd.write("??? success \n")
    yield


def prepend_error_report(fd, errors=None):
    content = raft.read()
    raft.seek(0, 0)
    with error_report_block(raft, errors):
        raft.write("***\n")
    raft.write(content)


def strip_log_lines(text):
    ol = []
    for line in text.split(os.linesep):
        if not line.startswith("["):
            ol.append(line)
    return os.linesep.join(ol)


if __name__ == "__main__":
    driver, path, doc = sys.argv[1:]
    err_list = []
    test_result = True

    generate_scenarios(path)

    with open(os.path.join(doc, RAFT_TEST_FILE_NAME), "w") as raft:
        for scenario in scenarios(path):
            raft.write("##{}\n\n".format(os.path.basename(scenario)))
            with block(raft, "steps", 3):
                with open(scenario, "r") as scen:
                    raft.write(scen.read())
            proc = Popen([driver], stdout=PIPE, stderr=PIPE, stdin=PIPE)
            out, err = proc.communicate(input=open(scenario, "rb").read())
            test_result = test_result and proc.returncode == 0

            if err:
                err_list.append([os.path.basename(scenario), err.decode()])
                with block(raft, "stderr", 3):
                    raft.write(err.decode())

            with block(raft, "diagram", 3, "mermaid", ["sequenceDiagram"]):
                raft.write(strip_log_lines(out.decode()))

    with open(os.path.join(doc, RAFT_TEST_FILE_NAME), "r+") as raft:
        prepend_error_report(raft, err_list)

    if not test_result or err_list:
        sys.exit(1)
