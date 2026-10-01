#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import graphlib
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


def resolve_include(path, including_file, root, quoted, generated_headers):
    candidates = []
    if quoted:
        candidates.append(including_file.parent / path)
    candidates.extend((root / "include" / path, root / "src" / path))

    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate.is_file() or candidate in generated_headers:
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


def includes_in(path, root, generated_headers, is_internal, errors):
    """Yield (line_number, directive, included_file) for each include in path
    which resolves to a repository file. Includes which cannot be analysed are
    recorded in errors instead."""
    source = strip_comments(path.read_text())
    for line_number, line in logical_lines(source):
        match = INCLUDE.match(line)
        if match is None:
            if INCLUDE_DIRECTIVE.match(line):
                errors.append(
                    (path.relative_to(root), line_number, "non-literal include")
                )
            continue

        quoted = match.group("quoted") is not None
        include_path = match.group("quoted") or match.group("angled")
        included_file = resolve_include(
            include_path, path, root, quoted, generated_headers
        )
        if included_file is None:
            if is_internal(include_path):
                errors.append(
                    (
                        path.relative_to(root),
                        line_number,
                        f"unresolved internal include {include_path!r}",
                    )
                )
            continue

        directive = f'"{include_path}"' if quoted else f"<{include_path}>"
        yield line_number, f"#include {directive}", included_file


def public_component_for(path, public_root, overrides):
    """A public header belongs to the longest override matching it, where a
    trailing slash matches a directory. Otherwise it belongs to its top-level
    directory under include/ccf, and a top-level header is its own component."""
    relative = path.relative_to(public_root).as_posix()
    for override in sorted(overrides, key=len, reverse=True):
        if relative == override or (
            override.endswith("/") and relative.startswith(override)
        ):
            return f"ccf/{overrides[override]}"
    return f"ccf/{relative.split('/')[0]}"


def find_cycle(edges):
    graph = {}
    for source, target in edges:
        graph.setdefault(source, set()).add(target)
    try:
        graphlib.TopologicalSorter(graph).prepare()
    except graphlib.CycleError as error:
        return list(reversed(error.args[1]))
    return None


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=(
            "Check direct dependencies between CCF source components, and "
            "between public header components."
        )
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
    generated_headers = {
        (root / path).resolve() for path in config["generated_headers"]
    }
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

    # Every source component must have a policy, and the policies must not
    # allow a cycle. Since every include is then checked against a policy, no
    # cycle can form between source components.
    missing_policies = source_components - set(allowed_dependencies)
    if missing_policies:
        missing = ", ".join(sorted(missing_policies))
        print(f"Missing dependency policy for: {missing}", file=sys.stderr)
        return 1

    try:
        graphlib.TopologicalSorter(allowed_dependencies).prepare()
    except graphlib.CycleError as error:
        cycle = " -> ".join(reversed(error.args[1]))
        print(f"Dependency policy allows a cycle: {cycle}", file=sys.stderr)
        return 1

    public_overrides = config["public_component_overrides"]
    unknown_overrides = sorted(
        header
        for header in public_overrides
        if not (
            (public_root / header).is_dir()
            if header.endswith("/")
            else (public_root / header).is_file()
        )
    )
    if unknown_overrides:
        unknown = ", ".join(unknown_overrides)
        print(f"Unknown public header in overrides: {unknown}", file=sys.stderr)
        return 1

    def is_internal(include_path):
        return is_internal_spelling(include_path, source_components, public_components)

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

        for line_number, directive, included_file in includes_in(
            source_file, root, generated_headers, is_internal, errors
        ):
            target_component = component_for(included_file, root)
            if target_component is None or target_component == source_component:
                continue

            edges.setdefault((source_component, target_component), []).append(
                (source_file.relative_to(root), line_number, directive)
            )

    # Public headers are a separate layer, as a component's interface may be
    # used by components that its implementation depends on. They must only
    # include public headers, and their components must not form a cycle.
    public_edges = {}
    private_includes = []
    public_headers = sorted(
        path
        for path in public_root.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
    )

    for header in public_headers:
        header_component = public_component_for(header, public_root, public_overrides)
        for line_number, directive, included_file in includes_in(
            header, root, generated_headers, is_internal, errors
        ):
            location = (header.relative_to(root), line_number, directive)
            if not included_file.is_relative_to(public_root):
                private_includes.append(location)
                continue

            target_component = public_component_for(
                included_file, public_root, public_overrides
            )
            if target_component != header_component:
                public_edges.setdefault(
                    (header_component, target_component), []
                ).append(location)

    if errors:
        print("Include analysis failed:", file=sys.stderr)
        for path, line_number, message in sorted(errors):
            print(f"  {path}:{line_number}: {message}", file=sys.stderr)
        return 1

    status = 0
    violations = []
    for (source, target), evidence in sorted(edges.items()):
        if target not in allowed_dependencies[source]:
            violations.append((source, target, evidence))

    if violations:
        for source, target, evidence in violations:
            print(f"Forbidden source dependency: {source} -> {target}")
            for path, line_number, directive in sorted(evidence):
                print(f"  {path}:{line_number}: {directive}")
            allowed = ", ".join(sorted(allowed_dependencies[source])) or "none"
            print(f"Allowed internal dependencies for {source}: {allowed}")
        status = 1
    else:
        print("No source dependency violations")

    if private_includes:
        print("Public headers include private headers:")
        for path, line_number, directive in sorted(private_includes):
            print(f"  {path}:{line_number}: {directive}")
        status = 1

    cycle = find_cycle(public_edges)
    if cycle is not None:
        print(f"Public header components form a cycle: {' -> '.join(cycle)}")
        for source, target in zip(cycle, cycle[1:]):
            path, line_number, directive = min(public_edges[(source, target)])
            print(f"  {path}:{line_number}: {directive}")
        status = 1

    if not private_includes and cycle is None:
        print("No public header dependency violations")

    return status


if __name__ == "__main__":
    sys.exit(main())
