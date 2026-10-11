#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Checks the RDP_TRACE records of node logs against trace.schema.json.

python3 check-schema.py LOG...
"""

import collections
import json
import pathlib
import sys

import jsonschema

MARKER = "RDP_TRACE "


def problems(validator: jsonschema.Draft202012Validator, record) -> list:
    """The schema errors of a record. JSON Schema has no discriminator, so a
    record that matches no branch of the oneOf is reported with the errors of
    the branch for its kind, rather than as matching none."""
    found = []
    for error in validator.iter_errors(record):
        if error.validator != "oneOf":
            found.append(f"{error.json_path}: {error.message}")
        elif isinstance(record, dict) and "kind" in record:
            branches = collections.defaultdict(list)
            for sub in error.context:
                branches[sub.relative_schema_path[0]].append(sub)
            found += [
                f"{e.json_path}: {e.message}"
                for errors in branches.values()
                if all(list(e.relative_path) != ["kind"] for e in errors)
                for e in errors
            ] or [f"$.kind: {record['kind']!r} is not a record kind"]
    return found


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    schema_path = pathlib.Path(__file__).parent / "trace.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    records = errors = 0
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8") as log:
            for line, text in enumerate(log, 1):
                _, marker, body = text.partition(MARKER)
                if not marker:
                    continue
                records += 1
                try:
                    found = problems(validator, json.loads(body))
                except json.JSONDecodeError as e:
                    found = [str(e)]
                for problem in found:
                    print(f"{path}:{line}: {problem}")
                errors += len(found)
    print(f"{records} records, {errors} schema errors")
    return 1 if errors or not records else 0


if __name__ == "__main__":
    sys.exit(main())
