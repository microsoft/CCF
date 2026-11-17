# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import json
import os
import pathlib
import sys
from contextlib import contextmanager

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
    for path in map(pathlib.Path, files):
        all_files += sorted(path.glob("*.lean")) if path.is_dir() else [path]
    return all_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("driver", type=str, help="Path to cft_driver binary")
    parser.add_argument(
        "files",
        nargs="*",
        type=str,
        help="Paths to Lean scenario files, each registering the scenario named by its stem",
    )
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

    ostream = sys.stdout

    # Create the CCF consensus protocol output directory.
    os.makedirs(args.output, exist_ok=True)
    raw_output = pathlib.Path(args.output) / "raw"
    raw_output.mkdir(exist_ok=True)

    for source in files:
        name = source.stem
        raw_trace = raw_output / f"{name}.ndjson"
        raw_trace.unlink(missing_ok=True)
        ostream.write(f"## {name}\n\n")
        with block(ostream, "steps", 3, "lean"):
            ostream.write(source.read_text(encoding="utf-8"))
        proc, records = run_driver(args.driver, name)
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
            err_list.append([name, err])
            with block(ostream, "stderr", 3):
                ostream.write(err)

        with block(ostream, "diagram", 3, "mermaid", ["sequenceDiagram"]):
            ostream.write(driver_diagram(out))

    write_error_report(err_list)

    if not test_result or err_list:
        sys.exit(1)
