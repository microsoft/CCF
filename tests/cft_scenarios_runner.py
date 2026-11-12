# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import json
import os
import pathlib
import sys
from contextlib import contextmanager

from cft_scenarios_gen import generate_scenarios
from cft_trace import run_driver


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


def driver_diagram(text):
    mermaid = []
    for line in text.split(os.linesep):
        if line.startswith("<CftDriver>"):
            mermaid.append(line[len("<CftDriver>") :])
    return os.linesep.join(mermaid) + os.linesep


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

    parser.add_argument("driver", type=str, help="Path to cft_driver binary")
    parser.add_argument("--gen-scenarios", action="store_true")
    parser.add_argument("files", nargs="*", type=str, help="Path to scenario files")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output directory",
        default=os.path.join("consensus"),
    )

    args = parser.parse_args()

    err_list = []
    test_result = True

    files = expand_files(args.files)

    if args.gen_scenarios:
        files += generate_scenarios()

    ostream = sys.stdout

    # Create the CCF consensus protocol output directory.
    os.makedirs(args.output, exist_ok=True)
    raw_output = pathlib.Path(args.output) / "raw"
    raw_output.mkdir(exist_ok=True)

    for scenario in files:
        raw_trace = raw_output / f"{os.path.basename(scenario)}.ndjson"
        raw_trace.unlink(missing_ok=True)
        ostream.write(f"## {os.path.basename(scenario)}\n\n")
        with block(ostream, "steps", 3), open(scenario, "r", encoding="utf-8") as scen:
            ostream.write(scen.read())
        proc, records = run_driver(args.driver, scenario)
        out, err = proc.stdout, proc.stderr
        test_result = test_result and proc.returncode == 0

        if proc.returncode == 0 and not err and records:
            raw_trace.write_text(
                "".join(
                    json.dumps(record, allow_nan=False) + "\n" for record in records
                ),
                encoding="utf-8",
            )

        if err:
            err_list.append([os.path.basename(scenario), err])
            with block(ostream, "stderr", 3):
                ostream.write(err)

        with block(ostream, "diagram", 3, "mermaid", ["sequenceDiagram"]):
            ostream.write(driver_diagram(out))

    write_error_report(err_list)

    if not test_result or err_list:
        sys.exit(1)
