# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
from rstcloth import RstCloth
from loguru import logger as LOG


def print_attributes(entry):
    def stringify_output(entry, s):
        s = f'"{s}"' if entry["type"] == "string" else s
        return f"``{s}``"

    desc = ""
    if "description" in entry:
        desc += entry["description"]
    if "enum" in entry:
        desc += f' (values: {", ".join(map(lambda s: stringify_output(entry, s), entry["enum"]))})'
    if "default" in entry:
        default_str = entry["default"]
        if entry["type"] == "string":
            default_str = f'"{default_str}"'
        desc += f". Default: ``{default_str}``"
    return desc


def print_entry(output, entry, name, depth=0):
    desc = ""
    if depth == 0:
        heading = depth_to_heading(output, 0)
        heading(f"``{name}``")
        output.newline()
    else:
        desc += f"- ``{name}``: "
    desc += print_attributes(entry)
    output.content(f"{desc}.")
    output.newline()


def depth_to_heading(output, depth):
    if depth == 0:
        return output.h2
    elif depth == 1:
        return output.h3
    elif depth == 2:
        return output.h4
    else:
        return output.h5


def has_subobjs(obj):
    return any(
        k in ["properties", "additionalProperties", "items"] for k in obj.keys()
    ) and ("items" not in obj or obj["items"]["type"] == "object")


def print_object(output, obj, depth=0, required_entries=None, additional_desc=None):
    required_entries = required_entries or []
    for k, v in obj.items():
        heading = depth_to_heading(output, depth)
        if has_subobjs(v):
            LOG.error(required_entries)
            heading(f"``{k}``")
            output.newline()
            if "description" in v:
                output.content(
                    f'{"**Required.** " if k in required_entries else ""}{v["description"]}.'
                )
                output.newline()
            if additional_desc is not None:
                output.content(f"Note: {additional_desc}.")
                output.newline()

            reqs = v.get("required", [])

            if "properties" in v:
                print_object(
                    output, v["properties"], depth=depth + 1, required_entries=reqs
                )
            if "additionalProperties" in v:
                print_object(
                    output,
                    v["additionalProperties"]["properties"],
                    depth=depth + 1,
                    required_entries=reqs,
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
        else:
            print_entry(output, v, name=k, depth=depth)


# TODO:
# - network [DONE]
# - recursion [DONE]
# - command [DONE]
# - required field [DONE]
# - pattern
# - description for each top field [DONE]
# - rpc_interfaces: key is name of interface [DONE]
# - references

if __name__ == "__main__":
    LOG.info("Generating configuration documentation")

    if len(sys.argv) <= 2:
        LOG.error(f"Usage: {sys.argv[0]} <input_path> <output_path>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r") as f:
        j = json.load(f)

    output = RstCloth(line_width=1000)

    output.h2("Configuration Options")
    output.newline()

    print_object(output, j["properties"], required_entries=j["required"])

    output.print_content()
    output.write(output_file)
    LOG.success(f"Configuration file successfully generated at {output_file}")
