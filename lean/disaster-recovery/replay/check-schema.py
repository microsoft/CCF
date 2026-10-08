#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Checks the RDP_TRACE records of node logs against trace.schema.json.

python3 check-schema.py LOG...
"""

import json
import pathlib
import sys

import jsonschema

MARKER = "RDP_TRACE "


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
                    problems = [
                        f"{e.json_path}: {e.message}"
                        for e in validator.iter_errors(json.loads(body))
                    ]
                except json.JSONDecodeError as e:
                    problems = [str(e)]
                for problem in problems:
                    print(f"{path}:{line}: {problem}")
                errors += len(problems)
    print(f"{records} records, {errors} schema errors")
    return 1 if errors or not records else 0


if __name__ == "__main__":
    sys.exit(main())
