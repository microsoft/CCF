#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath

SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
PUBLIC_API_COMPONENT = "ccf-api"
INCLUDE = re.compile(
    r'^\s*#\s*include\s*(?:"(?P<quoted>[^"\n]+)"|<(?P<angled>[^>\n]+)>)'
)
INCLUDE_DIRECTIVE = re.compile(r"^\s*#\s*include\b")
COMMENTS_AND_LITERALS = re.compile(
    r'(?P<raw>(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})'
    r"\(.*?\)(?P=delimiter)\")"
    r'|(?P<string>(?:u8|u|U|L)?"(?:\\.|[^"\\\n])*")'
    r"|(?P<char>(?:u|U|L)?'(?:\\.|[^'\\\n])*')"
    r"|(?P<line_comment>//[^\n]*)"
    r"|(?P<block_comment>/\*.*?\*/)",
    re.DOTALL,
)


def strip_comments(source):
    def replace(match):
        if match.group("string") is not None or match.group("char") is not None:
            return match.group(0)
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return COMMENTS_AND_LITERALS.sub(replace, source)


def logical_lines(source):
    pending = ""
    start_line = 1

    for line_number, line in enumerate(source.splitlines(), 1):
        if not pending:
            start_line = line_number
        if line.endswith("\\"):
            pending += line[:-1]
        else:
            yield start_line, pending + line
            pending = ""

    if pending:
        yield start_line, pending


def component_for(path, root):
    try:
        relative = path.relative_to(root / "src")
        return relative.parts[0] if len(relative.parts) > 1 else None
    except ValueError:
        pass

    try:
        relative = path.relative_to(root / "include" / "ccf")
        return relative.parts[0] if len(relative.parts) > 1 else PUBLIC_API_COMPONENT
    except ValueError:
        return None


def resolve_include(path, including_file, root, quoted):
    candidates = []
    if quoted:
        candidates.append(including_file.parent / path)
    candidates.extend((root / "include" / path, root / "src" / path))

    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate.is_file():
            return candidate
    return None


def is_internal_spelling(path, source_components, public_components):
    parts = PurePosixPath(path).parts
    if not parts:
        return False
    if path.startswith(("./", "../")):
        return True
    if parts[0] in source_components:
        return True
    return (
        len(parts) > 1
        and parts[0] == "ccf"
        and (parts[1] in public_components or len(parts) == 2)
    )


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Check direct dependencies between CCF source components."
    )
    parser.add_argument(
        "--root", type=Path, default=script_dir.parent, help="Repository root"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=script_dir / "source-dependencies.json",
        help="Dependency policy",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        config = json.loads(args.config.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"Unable to read dependency policy: {error}", file=sys.stderr)
        return 1

    excluded_parts = set(config["excluded_path_parts"])
    excluded_suffixes = tuple(config["excluded_file_suffixes"])
    allowed_dependencies = {
        component: set(dependencies)
        for component, dependencies in config["allowed_internal_dependencies"].items()
    }

    source_components = {
        path.name for path in (root / "src").iterdir() if path.is_dir()
    }
    public_root = root / "include" / "ccf"
    public_components = {path.name for path in public_root.iterdir() if path.is_dir()}
    known_components = source_components | public_components | {PUBLIC_API_COMPONENT}
    unknown_sources = set(allowed_dependencies) - source_components
    unknown_targets = set().union(*allowed_dependencies.values()) - known_components
    if unknown_sources or unknown_targets:
        unknown = ", ".join(sorted(unknown_sources | unknown_targets))
        print(f"Unknown component in dependency policy: {unknown}", file=sys.stderr)
        return 1

    edges = {}
    errors = []
    source_files = sorted(
        path
        for path in (root / "src").rglob("*")
        if path.is_file()
        and path.suffix.lower() in SOURCE_EXTENSIONS
        and not excluded_parts.intersection(path.relative_to(root).parts)
        and not path.stem.endswith(excluded_suffixes)
    )

    for source_file in source_files:
        source_component = component_for(source_file, root)
        if source_component is None:
            continue

        source = strip_comments(source_file.read_text())
        for line_number, line in logical_lines(source):
            match = INCLUDE.match(line)
            if match is None:
                if INCLUDE_DIRECTIVE.match(line):
                    errors.append(
                        (
                            source_file.relative_to(root),
                            line_number,
                            "non-literal include",
                        )
                    )
                continue

            include_path = match.group("quoted") or match.group("angled")
            included_file = resolve_include(
                include_path, source_file, root, match.group("quoted") is not None
            )
            if included_file is None:
                if is_internal_spelling(
                    include_path, source_components, public_components
                ):
                    errors.append(
                        (
                            source_file.relative_to(root),
                            line_number,
                            f"unresolved internal include {include_path!r}",
                        )
                    )
                continue

            target_component = component_for(included_file, root)
            if target_component is None or target_component == source_component:
                continue

            edge = (source_component, target_component)
            delimiter = '"' if match.group("quoted") is not None else "<"
            terminator = '"' if delimiter == '"' else ">"
            edges.setdefault(edge, []).append(
                (
                    source_file.relative_to(root),
                    line_number,
                    f"#include {delimiter}{include_path}{terminator}",
                )
            )

    if errors:
        print("Source dependency analysis failed:", file=sys.stderr)
        for path, line_number, message in sorted(errors):
            print(f"  {path}:{line_number}: {message}", file=sys.stderr)
        return 1

    violations = []
    for (source, target), evidence in sorted(edges.items()):
        if (
            source in allowed_dependencies
            and target not in allowed_dependencies[source]
        ):
            violations.append((source, target, evidence))

    if violations:
        for source, target, evidence in violations:
            print(f"Forbidden source dependency: {source} -> {target}")
            for path, line_number, directive in sorted(evidence):
                print(f"  {path}:{line_number}: {directive}")
            allowed = ", ".join(sorted(allowed_dependencies[source])) or "none"
            print(f"Allowed internal dependencies for {source}: {allowed}")
        return 1

    print("No source dependency violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
