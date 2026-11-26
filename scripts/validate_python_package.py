#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import email.parser
import zipfile
from pathlib import Path


def validate_wheel(wheel_path: Path, expected_version: str) -> None:
    with zipfile.ZipFile(wheel_path) as wheel:
        metadata_paths = [
            name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_paths) != 1:
            raise ValueError(
                f"Expected one METADATA file in {wheel_path}, "
                f"found {len(metadata_paths)}"
            )
        metadata = email.parser.BytesParser().parsebytes(wheel.read(metadata_paths[0]))

    if metadata["Name"] != "ccf":
        raise ValueError(f"Expected project name ccf, found {metadata['Name']}")
    if metadata["Version"] != expected_version:
        raise ValueError(
            f"Expected version {expected_version}, found {metadata['Version']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a CCF Python wheel")
    parser.add_argument("wheel", type=Path)
    parser.add_argument("expected_version")
    args = parser.parse_args()
    validate_wheel(args.wheel, args.expected_version)


if __name__ == "__main__":
    main()
