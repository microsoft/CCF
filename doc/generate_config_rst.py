# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import json

# We can document each sub schema as either a header-led
# section, or a nested definition list.
# The latter is more readable thanks to indentation, but
# the former adds automatic links and in-page navigation.
# This is a compromise between both approaches - add headers
# down to a certain depth.
HEADER_DEPTH = 2


class MinimalRstGenerator:
    def __init__(self, document_root):
        self._depth = 0
        self._prefix = []
        self._lines = []
        self.document_root = document_root

    def add_line(self, line=""):
        self._lines.append(line)

    def _start_header_section(self, text):
        depth_to_char = {
            0: "#",
            1: "-",
            2: "~",
            3: "+",
            4: '"',
            5: "_",
        }
        self.add_line()
        self.add_line(text)
        self.add_line(depth_to_char[self._depth] * len(text))
        self.add_line()

    def start_section(self, header, prefix=""):
        if prefix:
            prefix = f"`{prefix}`"
            self._start_header_section(f"{prefix} {header}")
        else:
            self._start_header_section(header)
        self._depth += 1

    def end_section(self):
        self.add_line()
        assert self._depth > 0
        self._depth -= 1

    def start_definition(self, term):
        self.add_line()
        self.add_line(term)

    def add_definition_line(self, line):
        self.add_line(f"   |   {line}")

    def end_definition(self):
        self.add_line()

    def render(self):
        return "\n".join(self._prefix) + "\n".join(self._lines)


def lookup_ref(document_root: dict, json_ref: str):
    keys = json_ref.split("/")
    if keys[0] != "#":
        raise ValueError(
            f"Can only resolve fragment-bound refs (ie - absolute within the current document). Cannot handle '{json_ref}'"
        )

    obj = document_root
    for key in keys[1:]:
        if key in obj:
            obj = obj[key]
        else:
            raise ValueError(
                f"Unable to resolve '{json_ref}' - couldn't find '{key}' in {json.dumps(obj)}"
            )

    return obj


def has_subobjs(obj):
    return any(k in obj.keys() for k in ["properties", "additionalProperties", "items"])


def dump_property(
    output: MinimalRstGenerator,
    property_name: str,
    obj: dict,
    required: bool = False,
    path: list | None = None,
    conditions: list | None = None,
    section_qualifier: str | None = None,
):
    if path is None:
        path = []
    if conditions is None:
        conditions = []

    prefix = "".join(path)

    # Don't document empty ("any") schema
    if len(obj) == 0:
        return

    ref = obj.get("$ref")
    if ref:
        referenced_obj = lookup_ref(output.document_root, ref)
        obj = {
            **referenced_obj,
            **{k: v for k, v in obj.items() if k != "$ref"},
        }

    t = obj.get("type")

    metadata = []
    if required:
        metadata.append("**Required**")
    if t is not None:
        if isinstance(t, list):
            t = " | ".join(t)
        metadata.append(f"**Type**: {t}")
    if "enum" in obj:
        metadata.append(
            f"**Values**: {', '.join(monospace_literal(v) for v in obj['enum'])}"
        )
    if "default" in obj:
        metadata.append(f"**Default**: {monospace_literal(obj['default'])}")
    if "minimum" in obj:
        metadata.append(f"**Minimum**: {monospace_literal(obj['minimum'])}")
    if "maximum" in obj:
        metadata.append(f"**Maximum**: {monospace_literal(obj['maximum'])}")

    if has_subobjs(obj) or len(path) == 0:
        section_title = f"``{prefix}{property_name}``"
        if section_qualifier:
            section_title += f" ({section_qualifier})"

        output.start_section(section_title)
        for condition in conditions:
            output.add_line(f"(Only applies if {condition})")

        desc = obj.get("description", None)
        if desc:
            # Insert a trailing full-stop, but only if not present in original string
            if desc[-1] != ".":
                desc = desc + "."
            output.add_line(desc)

        for line in metadata:
            output.add_line(line)

        if t == "object":
            dump_object(output, obj, path + [f"{property_name}."])
        elif t == "array":
            dump_property(
                output,
                "[item]",
                obj.get("items", {}),
                path=path + [f"{property_name}."],
            )

        output.end_section()

    else:
        output.start_definition(f"``{property_name}``")

        desc = ""
        desc = obj.get("description", "")
        if desc:
            # Insert a trailing full-stop, but only if not present in original string
            if desc[-1] != ".":
                desc = desc + "."
            output.add_definition_line(desc)

        for line in metadata:
            output.add_definition_line(line)

        output.end_definition()


def dump_object(
    output: MinimalRstGenerator,
    obj: dict,
    path: list | None = None,
    conditions: list | None = None,
):
    if path is None:
        path = []
    if conditions is None:
        conditions = []

    props = []

    def add_prop(name, obj, required=False, **kwargs):
        props.append(
            {
                "property_name": name,
                "obj": obj,
                "required": required,
                "path": path,
                "conditions": kwargs.pop("conditions", conditions),
            }
        )

    def gather_properties(obj, **kwargs):
        required = obj.get("required", [])
        properties = obj.get("properties", {})

        for k, v in properties.items():
            add_prop(
                k,
                v,
                k in required,
                **kwargs,
            )

        additional = obj.get("additionalProperties", None)
        if additional:
            assert isinstance(additional, dict)
            add_prop("[name]", additional, **kwargs)

        all_of = obj.get("allOf", None)
        if all_of:
            for schema in all_of:
                gather_properties(schema)

        if_el = obj.get("if", None)
        if if_el:
            assert "then" in obj, "Missing 'then' clause from JSON schema"
            assert (
                not "else" in obj
            ), "'else' clause from JSON schema currently unsupported"

            extra_conditions = []
            for k, cond in if_el["properties"].items():
                assert "const" in cond, "Only 'const' conditions supported"
                goal_s = monospace_literal(cond["const"])
                extra_conditions.append(
                    f"{''.join(path)}{k} is {goal_s}"
                )

            gather_properties(obj["then"], conditions=conditions + extra_conditions)

    gather_properties(obj)

    property_counts = {}
    for p in props:
        name = p["property_name"]
        property_counts[name] = property_counts.get(name, 0) + 1

    for p in props:
        section_qualifier = None
        if property_counts[p["property_name"]] > 1 and p["conditions"]:
            section_qualifier = " and ".join(p["conditions"])
        dump_property(
            output=output,
            section_qualifier=section_qualifier,
            **p,
        )


def monospace_literal(v):
    return f"``{json.dumps(v)}``"


def generate_configuration_docs(input_file_path, output_file_path):
    with open(input_file_path, "r") as in_:
        j = json.load(in_)

    lines = [
        ".. This is an auto-generated file. DO NOT EDIT.",
        "",
        "Configuration Options",
        "^^^^^^^^^^^^^^^^^^^^^",
        "",
    ]
    output = MinimalRstGenerator(j)
    dump_object(output, j)
    out = "\n".join(lines) + output.render()

    if os.path.exists(output_file_path):
        with open(output_file_path, "r") as current:
            if current.read() == out:
                return

    with open(output_file_path, "w") as out_:
        out_.write(out)
    print(f"Configuration file successfully generated at {output_file_path}")


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print(f"Usage: {sys.argv[0]} <input_path> <output_path>")
        sys.exit(1)

    generate_configuration_docs(sys.argv[1], sys.argv[2])
