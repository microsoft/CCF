#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""clang-tidier.py: require braces around non-empty switch case bodies."""

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from itertools import islice
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
QUERY_FILE = Path(__file__).with_name("case-scopes.query")
CPP_EXTENSIONS = {".cpp", ".cc", ".cxx", ".c++", ".C"}
HEADER_EXTENSIONS = {
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".h++",
    ".H",
    ".inc",
    ".inl",
    ".ipp",
    ".tpp",
    ".def",
}


class CheckError(RuntimeError):
    pass


def parse_jobs(value: str) -> int:
    return (os.cpu_count() or 1) if value == "auto" else int(value)


def find_clang_query(executable: str | None = None) -> str:
    for candidate in [executable] if executable else ["clang-query-18", "clang-query"]:
        if path := shutil.which(candidate):
            return path
    raise CheckError(
        f"Cannot find {executable or 'clang-query-18 or clang-query'}; "
        "install Clang's extra tools (18 or newer), or set --clang-query."
    )


def compilation_sources(build_dir: Path, root: Path) -> list[Path]:
    database = build_dir / "compile_commands.json"
    try:
        entries = json.loads(database.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise CheckError(f"Invalid compilation database {database}: {error}") from error
    if not isinstance(entries, list):
        raise CheckError(f"Expected a list of compile commands in {database}")

    sources = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(key), str) or not entry[key]
            for key in ("directory", "file")
        ):
            raise CheckError(f"Invalid compile command {index} in {database}")
        directory = (build_dir / entry["directory"]).resolve()
        source = (directory / entry["file"]).resolve()
        if (
            source.suffix not in CPP_EXTENSIONS
            or not source.is_relative_to(root)
            or "3rdparty" in source.relative_to(root).parts
            or (build_dir != root and source.is_relative_to(build_dir))
        ):
            continue
        if not source.is_file():
            raise CheckError(f"Compilation database source is missing: {source}")
        sources.add(source)

    if not sources:
        raise CheckError(f"No first-party C++ translation units found in {database}")
    # clang-query visits every compile command for a file, including variants.
    return sorted(sources)


def modified_sources(root: Path, sources: list[Path]) -> list[Path]:
    executable = shutil.which("git")
    if executable is None or not (root / ".git").exists():
        print("Git worktree unavailable; checking all first-party C++ sources.")
        return sources

    changed = set()
    for arguments in (
        [
            "ls-files",
            "--modified",
            "--others",
            "--exclude-standard",
            "--full-name",
            "-z",
        ],
        ["diff", "--cached", "--name-only", "--no-renames", "-z"],
    ):
        result = subprocess.run(
            [executable, "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise CheckError(
                f"Cannot list modified files with Git (exit {result.returncode}): "
                f"{os.fsdecode(result.stderr).strip()}"
            )
        changed.update(
            root / os.fsdecode(path) for path in result.stdout.split(b"\0") if path
        )

    source_set = set(sources)
    if any(
        path.suffix in HEADER_EXTENSIONS | {".c", ".cmake", ".in"}
        or "3rdparty" in path.relative_to(root).parts
        or path.name
        in {
            "CMakeLists.txt",
            "CMakePresets.json",
            "CMakeUserPresets.json",
            Path(__file__).name,
            QUERY_FILE.name,
        }
        # Some .cpp files are included as headers rather than compiled separately.
        or (path.suffix in CPP_EXTENSIONS and path.resolve() not in source_set)
        for path in changed
    ):
        print("Shared C++ inputs or check configuration changed; checking all sources.")
        return sources
    return [source for source in sources if source in changed]


def check_source(
    executable: str, build_dir: Path, source: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            executable,
            "--use-color=false",
            "--extra-arg=-fdiagnostics-format=clang",
            "--extra-arg=-fshow-column",
            "-p",
            str(build_dir),
            "-f",
            str(QUERY_FILE),
            str(source),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def match_count(source: Path, result: subprocess.CompletedProcess[str]) -> int:
    print(result.stdout, end="")
    if result.returncode != 0:
        raise CheckError(f"clang-query failed for {source} (exit {result.returncode})")
    # clang-query 18 can return success after recovering from compilation errors.
    if re.search(r"(?m)^(?:.*:\d+:\d+: )?(?:fatal )?error:", result.stdout):
        raise CheckError(f"clang-query reported compilation errors for {source}")
    counts = re.findall(r"(?m)^(\d+) match(?:es)?\.$", result.stdout)
    if len(counts) != 1:
        raise CheckError(f"Expected exactly one clang-query match summary for {source}")
    return int(counts[0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-p", "--build-dir", type=Path, default=Path("build"))
    parser.add_argument(
        "--clang-query",
        default=os.environ.get("CLANG_QUERY"),
        help="clang-query executable (default: CLANG_QUERY, clang-query-18, clang-query)",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=parse_jobs,
        default=min(4, os.cpu_count() or 1),
        help=(
            "maximum concurrent clang-query processes; 'auto' uses the detected "
            "CPU count (default: up to 4 available CPUs)"
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="check all first-party C++ sources instead of Git working-tree changes",
    )
    parser.add_argument(
        "sources",
        nargs="*",
        type=Path,
        help="explicit translation units to check regardless of Git changes",
    )
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.all and args.sources:
        parser.error("--all cannot be combined with explicit sources")

    try:
        build_dir = args.build_dir.resolve()
        sources = compilation_sources(build_dir, ROOT_DIR)
        if args.sources:
            requested = {source.resolve() for source in args.sources}
            unknown = requested.difference(sources)
            if unknown:
                raise CheckError(
                    "Not first-party C++ compilation database sources: "
                    + ", ".join(str(source) for source in sorted(unknown))
                )
            sources = sorted(requested)
        elif not args.all:
            sources = modified_sources(ROOT_DIR, sources)
            if not sources:
                print(
                    "No modified first-party C++ sources to check. "
                    "Use --all for a full scan."
                )
                return 0
        executable = find_clang_query(args.clang_query)
        matches = 0
        remaining = iter(sources)
        completed = 0
        with ThreadPoolExecutor(max_workers=min(args.jobs, len(sources))) as executor:
            pending = {
                executor.submit(check_source, executable, build_dir, source): source
                for source in islice(remaining, args.jobs)
            }
            try:
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        source = pending.pop(future)
                        completed += 1
                        print(
                            f"[{completed}/{len(sources)}] {source.relative_to(ROOT_DIR)}",
                            flush=True,
                        )
                        matches += match_count(source, future.result())
                    for source in islice(remaining, len(done)):
                        pending[
                            executor.submit(check_source, executable, build_dir, source)
                        ] = source
            finally:
                for future in pending:
                    future.cancel()
        if matches:
            raise CheckError(
                f"{matches} non-empty case/default body match(es) need braces. "
                "Declarations in shared headers may be reported by multiple files."
            )
    except (CheckError, OSError) as error:
        print(f"Case scope check failed: {error}", file=sys.stderr)
        return 1

    print(f"Case scopes checked in {len(sources)} C++ translation unit(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
