#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Copy Glaze's JSON header closure without modifying upstream bytes.

--source is an include root containing glaze/, such as an upstream checkout's
include/ directory. --output is a dedicated directory named glaze, such as
3rdparty/exported/glaze. ENTRY_POINTS lists the headers used by CCF.
All conditional branches are scanned, without evaluating the preprocessor.
Quoted includes must resolve within Glaze; non-Glaze angle includes are external.
Source provenance and license notices are maintained separately.
"""

import argparse
import re
import sys
from pathlib import Path

ENTRY_POINTS = (
    "glaze/json/read.hpp",
    "glaze/json/write.hpp",
    "glaze/json/schema.hpp",
)

# Preserve quoted include operands while hiding comments and raw string bodies.
TOKENS = re.compile(
    r'R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=delimiter)"'
    r'|//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
INCLUDE = re.compile(r"^[^\S\n]*#[^\S\n]*(include(?:_next)?)\b([^\n]*)", re.MULTILINE)
LITERAL = re.compile(r'\s*(?:"([^"\n]+)"|<([^>\n]+)>)\s*')


class VendorError(RuntimeError):
    pass


def collect_headers(source: Path) -> dict[Path, bytes]:
    """Stage a deterministic include closure in memory before any output writes."""
    root = (source / "glaze").resolve()
    if not root.is_dir():
        raise VendorError(f"Source must contain a glaze/ directory: {source}")

    pending = [source / entry for entry in ENTRY_POINTS]
    headers = {}
    while pending:
        path = pending.pop().resolve()
        if not path.is_relative_to(root):
            raise VendorError(f"Include escapes the Glaze source directory: {path}")
        relative = path.relative_to(root)
        if relative in headers:
            continue
        if not path.is_file():
            raise VendorError(f"Missing Glaze header: {path}")
        content = path.read_bytes()
        headers[relative] = content
        text = re.sub(r"\\\r?\n", "", content.decode("utf-8-sig"))
        text = TOKENS.sub(
            lambda match: (
                re.sub(r"[^\n]", " ", match[0])
                if match[0].startswith(("//", "/*", 'R"'))
                else match[0]
            ),
            text,
        )
        for directive in INCLUDE.finditer(text):
            literal = LITERAL.fullmatch(directive[2])
            if directive[1] != "include" or literal is None:
                raise VendorError(
                    f"{path}: unsupported include directive: {directive[0].strip()}"
                )
            name = literal[1] or literal[2]
            if name.startswith("glaze/"):
                pending.append(source / name)
            elif literal[1] is not None:
                pending.append(path.parent / name)
    return dict(sorted(headers.items()))


def output_files(output: Path) -> dict[Path, Path]:
    files = {}
    if output.exists():
        if not output.is_dir():
            raise VendorError(f"Output must be a directory: {output}")
        for path in sorted(output.rglob("*")):
            if path.is_symlink() or not path.resolve().is_relative_to(output):
                raise VendorError(f"Output must not contain symlinks: {path}")
            if path.is_file():
                files[path.relative_to(output)] = path
    return files


def vendor(source: Path, output: Path, check: bool) -> int:
    source = source.resolve()
    if output.is_symlink():
        raise VendorError(f"Output must not be a symlink: {output}")
    output = output.resolve()
    if output.name != "glaze" or any(
        path.is_relative_to(output) for path in (Path.cwd(), Path.home())
    ):
        raise VendorError("Output must be a dedicated directory named glaze")
    if any(
        root.is_relative_to(output) or output.is_relative_to(root)
        for root in (source, (source / "glaze").resolve())
    ):
        raise VendorError("Source and output directories must not overlap")

    headers = collect_headers(source)
    existing = output_files(output)
    missing = sorted(headers.keys() - existing.keys())
    changed = sorted(
        relative
        for relative in headers.keys() & existing.keys()
        if headers[relative] != existing[relative].read_bytes()
    )
    surplus = sorted(existing.keys() - headers.keys())
    if check:
        for label, paths in (
            ("Missing", missing),
            ("Changed", changed),
            ("Surplus", surplus),
        ):
            for path in paths:
                print(f"{label}: {path.as_posix()}")
        if missing or changed or surplus:
            return 1
    else:
        # Check file/directory conflicts before writing or deleting anything.
        for relative in headers:
            target = output / relative
            if target.is_dir() or any(parent.is_file() for parent in target.parents):
                raise VendorError(f"Output path conflicts with a header: {target}")
        for relative in sorted(missing + changed):
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(headers[relative])
        for relative in surplus:
            existing[relative].unlink()
    action = "Verified" if check else "Vendored"
    print(f"{action} {len(headers)} headers ({sum(map(len, headers.values()))} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, required=True, help="Include root containing glaze/"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Dedicated vendored glaze/ directory"
    )
    parser.add_argument(
        "--check", action="store_true", help="Report missing, changed or surplus files"
    )
    args = parser.parse_args(argv)
    try:
        return vendor(args.source, args.output, args.check)
    except (VendorError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
