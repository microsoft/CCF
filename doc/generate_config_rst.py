# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json
import tempfile
import filecmp

# Generated document is included in existing page, so
# start at heading of depth 1 (equivalent to markdown h2.)
START_DEPTH = 1


class MinimalRstGenerator:
    def __init__(self):
        self._lines = [".."]
        self._lines.append("  This is an auto-generated file. DO NOT EDIT.\n")

    def _add_lines(self, lines):
        self._lines.extend(lines)
        self._lines.append("\n")

    def add_heading(self, text, depth):
        depth_to_char = {0: "=", 1: "-", 2: "~", 3: "+"}
        self._add_lines([text, depth_to_char[depth] * len(text)])

    def add_line(self, text):
        self._add_lines([text])

    def render(self):
        return "\n".join(self._lines)


def print_attributes(entry):
    def stringify_output(s):
        return f"``{json.dumps(s)}``"

    desc = ""
    if "description" in entry:
        desc += entry["description"]
    if "enum" in entry:
        desc += f'. (values: {", ".join(stringify_output(s) for s in entry["enum"])})'
    if "default" in entry:
        desc += f'. Default: {stringify_output(entry["default"])}'
    if "minimum" in entry:
        desc += f'. Minimum: {stringify_output(entry["minimum"])}'
    return desc


def print_entry(output, entry, name, required=False, depth=0):
    desc = ""
    if depth == START_DEPTH:
        output.add_heading(f"``{name}``", START_DEPTH)
    else:
        desc += f"- ``{name}``: "
    desc += print_attributes(entry)
    if required:
        desc += ". Required"
    output.add_line(f"{desc}.")


def has_subobjs(obj):
    if not isinstance(obj, dict):
        return False
    return any(
        k in ["properties", "additionalProperties", "items"] for k in obj.keys()
    ) and ("items" not in obj or obj["items"]["type"] == "object")


def print_object(output, obj, depth=0, required_entries=None, additional_desc=None):
    required_entries = required_entries or []
    for k, v in obj.items():
        if has_subobjs(v):
            output.add_heading(f"``{k}``", depth)
            if "description" in v:
                output.add_line(
                    f'{"**Required.** " if k in required_entries else ""}{v["description"]}.'
                )
            if additional_desc is not None:
                output.add_line(f"Note: {additional_desc}.")

            reqs = v.get("required", [])

            if "properties" in v:
                print_object(
                    output, v["properties"], depth=depth + 1, required_entries=reqs
                )
                # Strict schema with no extra fields allowed https://github.com/microsoft/CCF/issues/3813
                assert (
                    "allOf" in v or v.get("additionalProperties") == False
                ), f"AdditionalProperties not set to false in {k}:{v}"
            if "additionalProperties" in v:
                if isinstance(v["additionalProperties"], dict):
                    print_object(
                        output,
                        v["additionalProperties"]["properties"],
                        depth=depth + 1,
                        required_entries=v["additionalProperties"].get("required", []),
                    )
            if "items" in v and v["items"]["type"] == "object":
                print_object(
                    output,
                    v["items"]["properties"],
                    depth=depth + 1,
                    required_entries=reqs,
                )
            if "allOf" in v:
                for e in v["allOf"]:
                    ((k_, cond_),) = e["if"]["properties"].items()
                    print_object(
                        output,
                        e["then"]["properties"],
                        depth=depth + 1,
                        required_entries=reqs,
                        additional_desc=f'Only if ``{k_}`` is ``"{cond_["const"]}"``',
                    )
        elif k == "additionalProperties" and isinstance(v, bool):
            # Skip display of additionalProperties if bool as it is used
            # to make the schema stricter
            pass
        else:
            print_entry(output, v, name=k, required=k in required_entries, depth=depth)


def generate_configuration_docs(input_file_path, output_file_path):
    with open(input_file_path, "r") as in_:
        j = json.load(in_)

    output = MinimalRstGenerator()
    output.add_heading("Configuration Options", START_DEPTH)
    print_object(
        output, j["properties"], required_entries=j["required"], depth=START_DEPTH
    )
    assert (
        j.get("additionalProperties") == False
    ), f"AdditionalProperties not set to false in top level schema"

    out = output.render()
    # Only update output file if the file will be modified
    with tempfile.NamedTemporaryFile("w") as temp:
        temp.write(out)
        temp.flush()
        if not os.path.exists(output_file_path) or not filecmp.cmp(
            temp.name, output_file_path
        ):
            with open(output_file_path, "w") as out_:
                out_.write(output.render())
            print(f"Configuration file successfully generated at {output_file_path}")


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print(f"Usage: {sys.argv[0]} <input_path> <output_path>")
        sys.exit(1)

    generate_configuration_docs(sys.argv[1], sys.argv[2])
