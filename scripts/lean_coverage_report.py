#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Compute CI line/branch coverage and code/spec LoC for each Lean specification.

Reads the Lean-to-C++ file mapping in ``lean/COVERAGE_MAPPING.md``, fetches the
latest patched ``llvm-cov report`` from the GitHub Actions ``coverage-history``
artifact (or reads a local report via ``--report``), and prints a summary table
with C++ code LoC, Lean spec LoC, total Lean LoC, line coverage, and branch
coverage per specification.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from coverage_summary import (
    DEFAULT_REPOSITORY,
    FileCoverage,
    extract_coverage,
    extract_file_coverage,
)

DEFAULT_MAPPING = "lean/COVERAGE_MAPPING.md"
DEFAULT_BRANCH = "main"

_SPEC_HEADING_RE = re.compile(r"^##\s+.+?\(`lean/([^/`]+)`\)\s*$")
_SUBSECTION_RE = re.compile(r"^###\s+(.+?)\s*$")
_MARKDOWN_LINK_PATH_RE = re.compile(r"\[`((?:src|include)/[^`]+)`\]\([^)]+\)")
_CODE_PATH_RE = re.compile(r"`((?:src|include)/[^`]+)`")
_HISTORY_FILENAME_RE = re.compile(r"^(\d+)-(\d+)\.txt$")

# Bullet prefixes that introduce commentary or explicitly excluded files rather
# than files mapped to the specification.
_NON_MAPPING_BULLET_PREFIXES = (
    "- **Partial coverage",
    "- **Unmodeled paths",
    "- **Explicitly excluded",
)


class SpecMapping(NamedTuple):
    name: str
    core_files: list[str]
    questionable_files: list[str]


class SpecMetrics(NamedTuple):
    name: str
    files: list[str]
    missing_from_report: list[str]
    code_loc: int
    spec_loc: int
    total_lean_loc: int
    lines: int
    missed_lines: int
    branches: int
    missed_branches: int

    @property
    def lines_hit(self) -> int:
        return self.lines - self.missed_lines

    @property
    def branches_hit(self) -> int:
        return self.branches - self.missed_branches

    @property
    def line_coverage(self) -> float | None:
        return _percentage(self.lines, self.missed_lines)

    @property
    def branch_coverage(self) -> float | None:
        return _percentage(self.branches, self.missed_branches)


class ReportSource(NamedTuple):
    text: str
    description: str
    run_id: int | None = None
    run_number: str | None = None


def _percentage(total: int, missed: int) -> float | None:
    if total == 0:
        return None
    return 100.0 * (total - missed) / total


def _format_percentage(value: float | None) -> str:
    return f"{value:.2f}%" if value is not None else "-"


def _extract_bullet_paths(line: str) -> list[str]:
    """Extract repo-relative implementation paths from the subject of a bullet.

    Only inspects the portion of the bullet before the first ``:`` (when a
    colon is present outside link targets) so files mentioned only in
    explanatory prose are not captured.
    """
    body = line[2:].strip()
    # Find the first colon not inside (...) link syntax.
    depth = 0
    subject = body
    for idx, ch in enumerate(body):
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == ":" and depth == 0:
            subject = body[:idx]
            break

    paths: list[str] = []
    seen: set[str] = set()
    for pattern in (_MARKDOWN_LINK_PATH_RE, _CODE_PATH_RE):
        for match in pattern.finditer(subject):
            path = match.group(1)
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def parse_coverage_mapping(text: str) -> list[SpecMapping]:
    """Parse ``lean/COVERAGE_MAPPING.md`` into per-specification file lists."""
    mappings: list[SpecMapping] = []
    current_name: str | None = None
    current_core: list[str] = []
    current_questionable: list[str] = []
    section: str | None = None

    def flush() -> None:
        nonlocal current_name, current_core, current_questionable
        if current_name is not None:
            mappings.append(
                SpecMapping(
                    name=current_name,
                    core_files=current_core,
                    questionable_files=current_questionable,
                )
            )
        current_name = None
        current_core = []
        current_questionable = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        spec_match = _SPEC_HEADING_RE.match(line)
        if spec_match:
            flush()
            current_name = spec_match.group(1)
            section = None
            continue

        if current_name is None:
            continue

        sub_match = _SUBSECTION_RE.match(line)
        if sub_match:
            heading = sub_match.group(1).lower()
            if heading.startswith("core implementation"):
                section = "core"
            elif heading.startswith("questionable"):
                section = "questionable"
            else:
                section = None
            continue

        if section is None or not line.startswith("- "):
            continue

        if any(line.startswith(prefix) for prefix in _NON_MAPPING_BULLET_PREFIXES):
            continue

        target = current_core if section == "core" else current_questionable
        for path in _extract_bullet_paths(line):
            if path not in target:
                target.append(path)

    flush()
    return mappings


def count_cpp_loc(text: str) -> int:
    """Count non-blank, non-comment C/C++ lines of code (SLOC)."""
    loc = 0
    in_block_comment = False
    raw_delim: str | None = None

    for line in text.splitlines():
        i = 0
        n = len(line)
        has_code = False
        in_string = False
        in_char = False

        while i < n:
            if raw_delim is not None:
                end_marker = ")" + raw_delim + '"'
                pos = line.find(end_marker, i)
                has_code = True
                if pos == -1:
                    i = n
                else:
                    i = pos + len(end_marker)
                    raw_delim = None
                continue

            if in_block_comment:
                end_pos = line.find("*/", i)
                if end_pos == -1:
                    i = n
                else:
                    i = end_pos + 2
                    in_block_comment = False
                continue

            ch = line[i]
            if in_string:
                has_code = True
                if ch == "\\" and i + 1 < n:
                    i += 2
                elif ch == '"':
                    in_string = False
                    i += 1
                else:
                    i += 1
                continue

            if in_char:
                has_code = True
                if ch == "\\" and i + 1 < n:
                    i += 2
                elif ch == "'":
                    in_char = False
                    i += 1
                else:
                    i += 1
                continue

            if ch == "/" and i + 1 < n:
                nxt = line[i + 1]
                if nxt == "/":
                    break
                if nxt == "*":
                    in_block_comment = True
                    i += 2
                    continue

            if ch == "R" and i + 1 < n and line[i + 1] == '"':
                paren = line.find("(", i + 2)
                if paren != -1:
                    candidate = line[i + 2 : paren]
                    if all(c not in " \t()\\" for c in candidate):
                        has_code = True
                        raw_delim = candidate
                        i = paren + 1
                        continue

            if ch == '"':
                has_code = True
                in_string = True
                i += 1
                continue

            if ch == "'":
                has_code = True
                in_char = True
                i += 1
                continue

            if not ch.isspace():
                has_code = True
            i += 1

        if has_code:
            loc += 1

    return loc


def count_lean_loc(text: str) -> int:
    """Count non-blank, non-comment Lean lines of code (SLOC).

    Handles Lean's nested ``/- ... -/`` block comments (including ``/--`` and
    ``/-!`` doc comments) and ``--`` line comments.
    """
    loc = 0
    block_depth = 0

    for line in text.splitlines():
        i = 0
        n = len(line)
        has_code = False
        in_string = False

        while i < n:
            if block_depth > 0:
                if line[i : i + 2] == "/-":
                    block_depth += 1
                    i += 2
                elif line[i : i + 2] == "-/":
                    block_depth -= 1
                    i += 2
                else:
                    i += 1
                continue

            ch = line[i]
            if in_string:
                has_code = True
                if ch == "\\" and i + 1 < n:
                    i += 2
                elif ch == '"':
                    in_string = False
                    i += 1
                else:
                    i += 1
                continue

            if line[i : i + 2] == "--":
                break
            if line[i : i + 2] == "/-":
                block_depth += 1
                i += 2
                continue
            # Lean char literals like '"' or '\n' (distinct from identifier primes like x').
            if ch == "'":
                if i + 3 < n and line[i + 1] == "\\" and line[i + 3] == "'":
                    has_code = True
                    i += 4
                    continue
                if i + 2 < n and line[i + 1] != "\\" and line[i + 2] == "'":
                    has_code = True
                    i += 3
                    continue
            if ch == '"':
                has_code = True
                in_string = True
                i += 1
                continue

            if not ch.isspace():
                has_code = True
            i += 1

        if has_code:
            loc += 1

    return loc


def _is_spec_lean_file(rel_path: Path) -> bool:
    """Return True for Model and Properties files (the human-reviewed spec)."""
    parts = rel_path.parts
    if len(parts) == 2 and parts[1] in ("Model.lean", "Properties.lean"):
        return True
    return len(parts) >= 3 and parts[1] in ("Model", "Properties")


def count_lean_package_loc(package_dir: Path) -> tuple[int, int]:
    """Return ``(spec_loc, total_lean_loc)`` for a Lean package directory."""
    spec_loc = 0
    total_loc = 0
    for root, dirs, filenames in os.walk(package_dir):
        dirs[:] = [d for d in dirs if d not in (".lake", "scripts")]
        for filename in sorted(filenames):
            if not filename.endswith(".lean"):
                continue
            file_path = Path(root) / filename
            rel = file_path.relative_to(package_dir)
            loc = count_lean_loc(file_path.read_text(encoding="utf-8"))
            total_loc += loc
            if _is_spec_lean_file(rel):
                spec_loc += loc
    return spec_loc, total_loc


def _run_gh(args: Sequence[str]) -> str:
    try:
        proc = subprocess.run(
            ["gh", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "GitHub CLI 'gh' is required to fetch CI coverage artifacts."
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise RuntimeError(f"'gh {' '.join(args)}' failed: {detail}") from exc
    return proc.stdout


def _select_latest_report(directory: Path) -> tuple[int, str, str]:
    """Select the newest complete ``<run_id>-<run_number>.txt`` report."""
    candidates: list[tuple[int, str, Path]] = []
    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        match = _HISTORY_FILENAME_RE.match(entry.name)
        if match:
            candidates.append((int(match.group(1)), match.group(2), entry))

    for run_id, run_number, path in sorted(candidates, reverse=True):
        text = path.read_text(encoding="utf-8", errors="replace")
        if extract_coverage(text) is not None and extract_file_coverage(text):
            return run_id, run_number, text

    raise RuntimeError("No complete llvm-cov report found in downloaded artifact")


def fetch_ci_coverage_report(
    repo: str,
    branch: str,
    run_id: int | None = None,
) -> ReportSource:
    """Download the latest coverage-history artifact from GitHub Actions."""
    slug = branch.replace("/", "-")
    artifact_name = f"coverage-history-{slug}"

    if run_id is not None:
        candidate_run_ids = [run_id]
    else:
        raw = _run_gh(
            [
                "api",
                f"repos/{repo}/actions/artifacts?name={artifact_name}&per_page=100",
            ]
        )
        payload = json.loads(raw)
        artifacts = [
            a
            for a in payload.get("artifacts", [])
            if not a.get("expired", False)
            and a.get("workflow_run", {}).get("head_branch") == branch
        ]
        artifacts.sort(key=lambda a: a.get("created_at", ""), reverse=True)
        candidate_run_ids = []
        seen_ids: set[int] = set()
        for artifact in artifacts:
            wf_id = artifact.get("workflow_run", {}).get("id")
            if isinstance(wf_id, int) and wf_id not in seen_ids:
                seen_ids.add(wf_id)
                candidate_run_ids.append(wf_id)
        if not candidate_run_ids:
            raise RuntimeError(
                f"No non-expired '{artifact_name}' artifacts found for branch "
                f"'{branch}' in {repo}."
            )

    last_error: str | None = None
    for candidate_id in candidate_run_ids[:10]:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                _run_gh(
                    [
                        "run",
                        "download",
                        str(candidate_id),
                        "--repo",
                        repo,
                        "--name",
                        artifact_name,
                        "--dir",
                        tmpdir,
                    ]
                )
                report_run_id, report_run_number, text = _select_latest_report(
                    Path(tmpdir)
                )
                return ReportSource(
                    text=text,
                    description=(
                        f"{repo} run #{report_run_number} (ID {report_run_id}, "
                        f"artifact `{artifact_name}` on `{branch}`)"
                    ),
                    run_id=report_run_id,
                    run_number=report_run_number,
                )
            except RuntimeError as exc:
                last_error = str(exc)

    raise RuntimeError(
        f"Failed to download '{artifact_name}' from {repo}: {last_error}"
    )


def _lookup_coverage(
    path: str,
    by_path: dict[str, FileCoverage],
) -> FileCoverage | None:
    if path in by_path:
        return by_path[path]
    suffix = "/" + path
    matches = [entry for k, entry in by_path.items() if k.endswith(suffix)]
    if len(matches) == 1:
        return matches[0]
    return None


def compute_metrics(
    repo_root: Path,
    mappings: Sequence[SpecMapping],
    coverage_files: Sequence[FileCoverage],
    include_questionable: bool = False,
) -> tuple[list[SpecMetrics], SpecMetrics, int]:
    """Aggregate LoC and coverage metrics per specification and overall."""
    by_path: dict[str, FileCoverage] = {entry.path: entry for entry in coverage_files}
    loc_cache: dict[str, int] = {}

    def cpp_loc(rel_path: str) -> int:
        if rel_path not in loc_cache:
            full_path = repo_root / rel_path
            loc_cache[rel_path] = count_cpp_loc(full_path.read_text(encoding="utf-8"))
        return loc_cache[rel_path]

    per_spec: list[SpecMetrics] = []
    all_unique_files: list[str] = []
    seen_files: set[str] = set()

    for mapping in mappings:
        files = list(mapping.core_files)
        if include_questionable:
            for path in mapping.questionable_files:
                if path not in files:
                    files.append(path)

        code_loc = 0
        lines = missed_lines = branches = missed_branches = 0
        missing: list[str] = []

        for path in files:
            code_loc += cpp_loc(path)
            cov = _lookup_coverage(path, by_path)
            if cov is None:
                missing.append(path)
            else:
                lines += cov.lines
                missed_lines += cov.missed_lines
                branches += cov.branches
                missed_branches += cov.missed_branches

            if path not in seen_files:
                seen_files.add(path)
                all_unique_files.append(path)

        spec_loc, total_lean_loc = count_lean_package_loc(
            repo_root / "lean" / mapping.name
        )
        per_spec.append(
            SpecMetrics(
                name=mapping.name,
                files=files,
                missing_from_report=missing,
                code_loc=code_loc,
                spec_loc=spec_loc,
                total_lean_loc=total_lean_loc,
                lines=lines,
                missed_lines=missed_lines,
                branches=branches,
                missed_branches=missed_branches,
            )
        )

    total_code_loc = sum(cpp_loc(path) for path in all_unique_files)
    total_lines = total_missed_lines = total_branches = total_missed_branches = 0
    total_missing: list[str] = []
    for path in all_unique_files:
        cov = _lookup_coverage(path, by_path)
        if cov is None:
            total_missing.append(path)
        else:
            total_lines += cov.lines
            total_missed_lines += cov.missed_lines
            total_branches += cov.branches
            total_missed_branches += cov.missed_branches

    total_metrics = SpecMetrics(
        name="Total (unique)",
        files=all_unique_files,
        missing_from_report=total_missing,
        code_loc=total_code_loc,
        spec_loc=sum(m.spec_loc for m in per_spec),
        total_lean_loc=sum(m.total_lean_loc for m in per_spec),
        lines=total_lines,
        missed_lines=total_missed_lines,
        branches=total_branches,
        missed_branches=total_missed_branches,
    )

    common_dir = repo_root / "lean" / "common"
    common_lean_loc = (
        count_lean_package_loc(common_dir)[1] if common_dir.is_dir() else 0
    )

    return per_spec, total_metrics, common_lean_loc


def _format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    right_align: Sequence[bool],
    markdown: bool,
) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render_row(cells: Sequence[str]) -> str:
        formatted = [
            cell.rjust(widths[i]) if right_align[i] else cell.ljust(widths[i])
            for i, cell in enumerate(cells)
        ]
        if markdown:
            return "| " + " | ".join(formatted) + " |"
        return "  ".join(formatted)

    lines = [render_row(headers)]
    if markdown:
        sep = [
            (
                ("-" * max(3, widths[i] - 1) + ":")
                if right_align[i]
                else ("-" * max(3, widths[i]))
            )
            for i in range(len(headers))
        ]
        lines.append("| " + " | ".join(sep) + " |")
    else:
        lines.append("  ".join("-" * w for w in widths))

    for row in rows:
        lines.append(render_row(row))
    return "\n".join(lines)


def render_report(
    per_spec: Sequence[SpecMetrics],
    total: SpecMetrics,
    common_lean_loc: int,
    source: ReportSource,
    include_questionable: bool,
    per_file: bool,
    coverage_files: Sequence[FileCoverage],
    repo_root: Path,
    markdown: bool = True,
) -> str:
    headers = [
        "Item",
        "Files",
        "Code LoC",
        "Spec LoC",
        "Total Lean LoC",
        "Lines (Hit/Total)",
        "Line Cov",
        "Branches (Hit/Total)",
        "Branch Cov",
    ]
    right_align = [False, True, True, True, True, True, True, True, True]

    rows: list[list[str]] = []
    for item in [*per_spec, total]:
        label = f"**{item.name}**" if markdown and item is total else item.name
        rows.append(
            [
                label,
                str(len(item.files)),
                f"{item.code_loc:,}",
                f"{item.spec_loc:,}",
                f"{item.total_lean_loc:,}",
                f"{item.lines_hit:,}/{item.lines:,}",
                _format_percentage(item.line_coverage),
                f"{item.branches_hit:,}/{item.branches:,}",
                _format_percentage(item.branch_coverage),
            ]
        )

    out: list[str] = [_format_table(headers, rows, right_align, markdown)]

    scope = "core + questionable" if include_questionable else "core only"
    notes = [
        f"Coverage source: {source.description} (scope: {scope}).",
        (
            "Code LoC counts non-blank, non-comment C/C++ lines; "
            "Spec LoC counts non-blank, non-comment Lean lines in Model and Properties; "
            "Total Lean LoC includes Proofs, TraceValidation/Replay, and Tests "
            f"(shared lean/common adds {common_lean_loc:,} LoC)."
        ),
    ]
    if total.missing_from_report:
        missing_list = ", ".join(
            f"`{p}`" if markdown else p for p in total.missing_from_report
        )
        notes.append(
            f"Mapped files absent from llvm-cov report (0 instrumented lines; counted in Code LoC): {missing_list}."
        )

    out.append("")
    out.extend(notes)

    if per_file:
        by_path = {entry.path: entry for entry in coverage_files}
        file_headers = [
            "Item",
            "File",
            "Code LoC",
            "Lines (Hit/Total)",
            "Line Cov",
            "Branches (Hit/Total)",
            "Branch Cov",
        ]
        file_align = [False, False, True, True, True, True, True]
        file_rows: list[list[str]] = []
        for item in per_spec:
            for path in item.files:
                loc = count_cpp_loc((repo_root / path).read_text(encoding="utf-8"))
                cov = _lookup_coverage(path, by_path)
                if cov is None:
                    line_str = "-"
                    line_cov = "-"
                    branch_str = "-"
                    branch_cov = "-"
                else:
                    line_str = f"{cov.lines - cov.missed_lines:,}/{cov.lines:,}"
                    line_cov = _format_percentage(
                        _percentage(cov.lines, cov.missed_lines)
                    )
                    branch_str = (
                        f"{cov.branches - cov.missed_branches:,}/{cov.branches:,}"
                    )
                    branch_cov = _format_percentage(
                        _percentage(cov.branches, cov.missed_branches)
                    )
                file_rows.append(
                    [
                        item.name,
                        f"`{path}`" if markdown else path,
                        f"{loc:,}",
                        line_str,
                        line_cov,
                        branch_str,
                        branch_cov,
                    ]
                )
        out.append("")
        out.append(_format_table(file_headers, file_rows, file_align, markdown))

    return "\n".join(out)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report CI line/branch coverage and code/spec LoC per Lean "
            "specification from lean/COVERAGE_MAPPING.md."
        )
    )
    parser.add_argument(
        "--mapping",
        default=DEFAULT_MAPPING,
        help=f"Path to coverage mapping Markdown file (default: {DEFAULT_MAPPING}).",
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPOSITORY,
        help=f"GitHub repository to fetch artifacts from (default: {DEFAULT_REPOSITORY}).",
    )
    parser.add_argument(
        "--branch",
        default=DEFAULT_BRANCH,
        help=f"Branch whose coverage-history artifact to fetch (default: {DEFAULT_BRANCH}).",
    )
    parser.add_argument(
        "--run-id",
        type=int,
        default=None,
        help="Specific GitHub Actions Coverage workflow run ID to download.",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Path to a local llvm-cov report file (skips GitHub artifact download).",
    )
    parser.add_argument(
        "--include-questionable",
        action="store_true",
        help="Include questionable/partial files alongside core implementation files.",
    )
    parser.add_argument(
        "--per-file",
        action="store_true",
        help="Also print a per-file breakdown table.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "text"),
        default="markdown",
        help="Output table format (default: markdown).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    mapping_path = Path(args.mapping)
    if not mapping_path.is_absolute():
        mapping_path = repo_root / mapping_path

    mappings = parse_coverage_mapping(mapping_path.read_text(encoding="utf-8"))
    if not mappings:
        print(f"No specification mappings found in {mapping_path}.", file=sys.stderr)
        return 1

    if args.report is not None:
        report_path = Path(args.report)
        source = ReportSource(
            text=report_path.read_text(encoding="utf-8", errors="replace"),
            description=str(report_path),
        )
    else:
        source = fetch_ci_coverage_report(args.repo, args.branch, args.run_id)

    coverage_files = extract_file_coverage(source.text)
    if not coverage_files:
        print("No per-file coverage rows found in report.", file=sys.stderr)
        return 1

    per_spec, total, common_lean_loc = compute_metrics(
        repo_root=repo_root,
        mappings=mappings,
        coverage_files=coverage_files,
        include_questionable=args.include_questionable,
    )

    print(
        render_report(
            per_spec=per_spec,
            total=total,
            common_lean_loc=common_lean_loc,
            source=source,
            include_questionable=args.include_questionable,
            per_file=args.per_file,
            coverage_files=coverage_files,
            repo_root=repo_root,
            markdown=(args.format == "markdown"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
