# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import tempfile
import filecmp

class SchemaRstGenerator:
    def __init__(self):
        self._depth = 0
        self._prefix = []
        self._lines = []

    def add_line(self, line, depth=None):
        self._lines.append("| " + "   " * (depth or self._depth) + line)

    def add_kv_line(self, k, v):
        self.add_line(f"*{k}*: {v}", self._depth + 1)

    def start_property(self, header):
        if self._lines and self._lines[-1] != "|":
            self._lines.append("|")
        self.add_line(header)
        self._depth += 1

    def end_property(self):
        assert self._depth > 0
        self._depth -= 1

    def render(self):
        return "\n".join(self._prefix) + "\n".join(self._lines)


def dump_object(output: SchemaRstGenerator, obj: dict, path: list = []):
    required = obj.get("required", [])
    properties = obj.get("properties", {})

    def prefix():
        _prefix = "".join(f"{e}" for e in path)
        return _prefix

    for k, v in properties.items():
        output.start_property(f":configproperty:`{prefix()}{k}`")

        dump(output, v, path + [f"{k}."], required=k in required)

        output.end_property()

    additional = obj.get("additionalProperties", None)
    if additional:
        assert isinstance(additional, dict)

        k = "[name]"
        if path and path[-1].endswith("."):
            path[-1] = path[-1][:-1]
        output.start_property(f":configproperty:`{prefix()}{k}`")
        dump(output, additional, path + [f"{k}."])
        output.end_property()


def monospace_literal(v):
    return f"``{json.dumps(v)}``"


def dump(output: SchemaRstGenerator, obj: dict, path=[], required=False):
    desc = obj.get("description", None)
    if desc:
        if desc[-1] != ".":
            desc = desc + "."
        output.add_line(desc)

    if required:
        output.add_line("*Required*")

    if "enum" in obj:
        output.add_kv_line(
            "Values", ", ".join(monospace_literal(v) for v in obj["enum"])
        )

    default = obj.get("default", None)
    if default:
        output.add_kv_line("Default", monospace_literal(default))

    minimum = obj.get("minimum", None)
    if minimum:
        output.add_kv_line("Minimum", monospace_literal(minimum))

    maximum = obj.get("maximum", None)
    if maximum:
        output.add_kv_line("Maximum", monospace_literal(maximum))

    t = obj.get("type")
    if t == "object":
        dump_object(output, obj, path)
    else:
        if isinstance(t, list):
            t = " | ".join(t)
        output.add_kv_line("Type", t)


def generate_configuration_docs(input_file_path, output_file_path):
    with open(input_file_path, "r") as in_:
        j = json.load(in_)

    lines = [
        ".. This is an auto-generated file. DO NOT EDIT.",
        "",
        "Configuration Options",
        "---------------------",
        "",
    ]
    output = SchemaRstGenerator()
    dump_object(output, j)
    out = "\n".join(lines) + output.render()

    # Only update output file if the file will be modified
    with tempfile.NamedTemporaryFile("w") as temp:
        temp.write(out)
        temp.flush()
        if not os.path.exists(output_file_path) or not filecmp.cmp(
            temp.name, output_file_path
        ):
            with open(output_file_path, "w") as out_:
                out_.write(out)
            print(f"Configuration file successfully generated at {output_file_path}")


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print(f"Usage: {sys.argv[0]} <input_path> <output_path>")
        sys.exit(1)

    generate_configuration_docs(sys.argv[1], sys.argv[2])
