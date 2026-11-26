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
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, NamedTuple

from coverage_summary import (
    DEFAULT_REPOSITORY,
    FileCoverage,
    extract_coverage,
    extract_file_coverage,
)

DEFAULT_MAPPING = "lean/COVERAGE_MAPPING.md"
DEFAULT_BRANCH = "main"
EXPORT_JSON_ARTIFACT = "coverage-export-json"
HTML_REPORT_ARTIFACT = "coverage-report-html"

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
    masked: bool = False
    branches_available: bool = True

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
        if not self.branches_available:
            return None
        return _percentage(self.branches, self.missed_branches)


class BranchRecord(NamedTuple):
    line: int
    col: int
    end_line: int
    end_col: int
    true_count: int
    false_count: int


class DetailedFileCoverage(NamedTuple):
    lines: dict[int, int]
    branches: list[BranchRecord] | None = None


class ReportSource(NamedTuple):
    text: str
    description: str
    run_id: int | None = None
    run_number: str | None = None
    detail_description: str | None = None


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


def count_cpp_loc(text: str, included_lines: set[int] | None = None) -> int:
    """Count non-blank, non-comment C/C++ lines of code (SLOC).

    When ``included_lines`` is given, every line is still lexed to keep block
    comment and raw-string state accurate, but only 1-based line numbers in
    ``included_lines`` are counted.
    """
    loc = 0
    in_block_comment = False
    raw_delim: str | None = None

    for line_no, line in enumerate(text.splitlines(), start=1):
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

        if has_code and (included_lines is None or line_no in included_lines):
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


def _expand_mask_ranges(
    mask_path: Path,
    rel_path: str,
    source_lines: Sequence[str],
    entries: Sequence[dict[str, Any]],
    kind: str,
) -> set[int]:
    num_lines = len(source_lines)
    selected: set[int] = set()
    for entry in entries:
        start = int(entry["start"])
        end = int(entry["end"])
        if not (1 <= start <= end <= num_lines):
            raise ValueError(
                f"{mask_path}: {rel_path} {kind} range {start}-{end} "
                f"is out of bounds (file has {num_lines} lines)"
            )
        start_anchor = entry.get("start_anchor")
        if start_anchor and start_anchor not in source_lines[start - 1]:
            raise ValueError(
                f"{mask_path}: {rel_path}:{start} start_anchor "
                f"{start_anchor!r} not found in {source_lines[start - 1]!r}"
            )
        end_anchor = entry.get("end_anchor")
        if end_anchor and end_anchor not in source_lines[end - 1]:
            raise ValueError(
                f"{mask_path}: {rel_path}:{end} end_anchor "
                f"{end_anchor!r} not found in {source_lines[end - 1]!r}"
            )
        selected.update(range(start, end + 1))
    return selected


def load_spec_mask(
    repo_root: Path,
    spec_name: str,
    mapped_files: Sequence[str] | None = None,
) -> dict[str, set[int]]:
    """Load and validate ``lean/<spec>/coverage_mask.json`` if present.

    Returns a mapping from repo-relative file path to the 1-based set of
    included line numbers. Files without an entry in the mask are omitted from
    the returned dict (meaning the whole file is included). Raises
    ``ValueError`` if any line range is out of bounds or an anchor fails to
    match the current source file.
    """
    mask_path = repo_root / "lean" / spec_name / "coverage_mask.json"
    if not mask_path.is_file():
        return {}

    payload = json.loads(mask_path.read_text(encoding="utf-8"))
    if payload.get("spec") not in (None, spec_name):
        raise ValueError(
            f"{mask_path}: 'spec' is {payload.get('spec')!r}, expected {spec_name!r}"
        )

    files_cfg = payload.get("files", {})
    if not isinstance(files_cfg, dict):
        raise TypeError(f"{mask_path}: 'files' must be an object")

    mapped_set = set(mapped_files) if mapped_files is not None else None
    result: dict[str, set[int]] = {}

    for rel_path, rule in files_cfg.items():
        if mapped_set is not None and rel_path not in mapped_set:
            raise ValueError(
                f"{mask_path}: masked file '{rel_path}' is not in the "
                f"'{spec_name}' mapping"
            )
        source_path = repo_root / rel_path
        if not source_path.is_file():
            raise ValueError(f"{mask_path}: file '{rel_path}' does not exist")
        source_lines = source_path.read_text(encoding="utf-8").splitlines()
        num_lines = len(source_lines)

        include_entries = rule.get("include")
        exclude_entries = rule.get("exclude", [])
        if include_entries is not None:
            included = _expand_mask_ranges(
                mask_path, rel_path, source_lines, include_entries, "include"
            )
        else:
            included = set(range(1, num_lines + 1))
        if exclude_entries:
            included -= _expand_mask_ranges(
                mask_path, rel_path, source_lines, exclude_entries, "exclude"
            )
        result[rel_path] = included

    return result


def _parse_html_count(raw: str) -> int:
    """Parse an llvm-cov HTML execution count cell such as '0', '42', or '1.2k'."""
    text = raw.strip()
    if not text:
        return 0
    if text.isdigit():
        return int(text)
    suffix_mult = {"k": 1_000, "M": 1_000_000, "G": 1_000_000_000}
    if text[-1] in suffix_mult:
        return max(1, int(float(text[:-1]) * suffix_mult[text[-1]]))
    return 1


class _HtmlTopLevelLineParser(HTMLParser):
    """Extract per-line execution counts from the top-level llvm-cov HTML table."""

    def __init__(self) -> None:
        super().__init__()
        self.table_depth = 0
        self.in_tr = False
        self.td_idx = -1
        self.cur_td_class = ""
        self.cur_text: list[str] = []
        self.line_no: int | None = None
        self.cls: str | None = None
        self.cnt: str | None = None
        self.lines: dict[int, int] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag == "table":
            self.table_depth += 1
        elif self.table_depth == 1:
            if tag == "tr":
                self.in_tr = True
                self.td_idx = -1
                self.line_no = self.cls = self.cnt = None
            elif self.in_tr and tag == "td":
                self.td_idx += 1
                self.cur_td_class = attr_map.get("class") or ""
                self.cur_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self.table_depth -= 1
        elif self.table_depth == 1:
            if self.in_tr and tag == "td":
                txt = "".join(self.cur_text).strip()
                if self.td_idx == 0 and txt.isdigit():
                    self.line_no = int(txt)
                elif self.td_idx == 1:
                    self.cls = self.cur_td_class
                    self.cnt = txt
            elif tag == "tr" and self.in_tr:
                if (
                    self.line_no is not None
                    and self.cls in ("covered-line", "uncovered-line")
                    and self.cnt
                ):
                    self.lines[self.line_no] = _parse_html_count(self.cnt)
                self.in_tr = False

    def handle_data(self, data: str) -> None:
        if self.table_depth == 1 and self.in_tr and self.td_idx in (0, 1):
            self.cur_text.append(data)


def parse_html_file_coverage(html_text: str) -> dict[int, int]:
    """Return ``{line_no: hit_count}`` for instrumented lines in an llvm-cov HTML file."""
    parser = _HtmlTopLevelLineParser()
    parser.feed(html_text)
    return parser.lines


def load_html_coverage_dir(
    html_dir: Path,
    target_files: Sequence[str],
) -> dict[str, DetailedFileCoverage]:
    """Load per-line coverage from an extracted ``coverage-report-html`` directory."""
    all_html = [
        p.as_posix() for p in html_dir.rglob("*.html") if p.name != "index.html"
    ]
    details: dict[str, DetailedFileCoverage] = {}
    for rel_path in target_files:
        suffix = "/" + rel_path + ".html"
        matches = [p for p in all_html if p == rel_path + ".html" or p.endswith(suffix)]
        if not matches:
            continue
        html_path = Path(min(matches, key=len))
        line_counts = parse_html_file_coverage(
            html_path.read_text(encoding="utf-8", errors="replace")
        )
        details[rel_path] = DetailedFileCoverage(lines=line_counts, branches=None)
    return details


def _lines_from_llvm_segments(segments: Sequence[Sequence[Any]]) -> dict[int, int]:
    """Decode ``llvm-cov export`` file segments into per-line hit counts.

    Follows LLVM's ``LineCoverageStats`` rules so each physical instrumented
    line is counted once.
    """
    if not segments:
        return {}

    by_line: dict[int, list[tuple[int, int, bool, bool, bool]]] = {}
    min_line = int(segments[0][0])
    max_line = min_line
    for seg in segments:
        line = int(seg[0])
        col = int(seg[1])
        count = int(seg[2])
        has_count = bool(seg[3])
        is_entry = bool(seg[4])
        is_gap = bool(seg[5]) if len(seg) > 5 else False
        by_line.setdefault(line, []).append((col, count, has_count, is_entry, is_gap))
        min_line = min(min_line, line)
        max_line = max(max_line, line)

    result: dict[int, int] = {}
    wrapped: tuple[int, int, bool, bool, bool] | None = None
    for line in range(min_line, max_line + 1):
        line_segs = by_line.get(line, [])
        wrapped_active = (
            wrapped is not None
            and wrapped[2]
            and not wrapped[4]
            and not (line_segs and line_segs[0][0] == 1 and not line_segs[0][2])
        )
        entry_counts = [seg[1] for seg in line_segs if seg[2] and seg[3] and not seg[4]]
        if wrapped_active or entry_counts:
            candidates = list(entry_counts)
            if wrapped_active and wrapped is not None:
                candidates.append(wrapped[1])
            result[line] = max(candidates)
        if line_segs:
            wrapped = line_segs[-1]
    return result


def parse_llvm_cov_export_json(
    payload: dict[str, Any],
) -> dict[str, DetailedFileCoverage]:
    """Parse ``llvm-cov export -format=text`` JSON into per-file line and branch data."""
    details: dict[str, DetailedFileCoverage] = {}
    for export_entry in payload.get("data", []):
        for file_entry in export_entry.get("files", []):
            filename = str(file_entry.get("filename", ""))
            if not filename:
                continue
            line_counts = _lines_from_llvm_segments(file_entry.get("segments", []))
            branch_map: dict[tuple[int, int, int, int], tuple[int, int]] = {}
            for raw_branch in file_entry.get("branches", []):
                if len(raw_branch) < 6:
                    continue
                line_start = int(raw_branch[0])
                col_start = int(raw_branch[1])
                line_end = int(raw_branch[2])
                col_end = int(raw_branch[3])
                true_count = int(raw_branch[4])
                false_count = int(raw_branch[5])
                key = (line_start, col_start, line_end, col_end)
                prev = branch_map.get(key)
                if prev is None:
                    branch_map[key] = (true_count, false_count)
                else:
                    branch_map[key] = (
                        max(prev[0], true_count),
                        max(prev[1], false_count),
                    )
            branches = [
                BranchRecord(k[0], k[1], k[2], k[3], v[0], v[1])
                for k, v in sorted(branch_map.items())
            ]
            details[filename] = DetailedFileCoverage(
                lines=line_counts,
                branches=branches,
            )
    return details


def load_export_json(path: Path) -> dict[str, DetailedFileCoverage]:
    """Load an ``llvm-cov export`` JSON file (plain ``.json`` or ``.json.gz``)."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
    return parse_llvm_cov_export_json(payload)


def fetch_ci_detailed_coverage(
    repo: str,
    run_id: int,
    target_files: Sequence[str],
) -> tuple[dict[str, DetailedFileCoverage], str]:
    """Fetch per-line (and when available, per-branch) coverage for a CI run.

    Prefers ``coverage-export-json`` (which includes branch regions) and falls
    back to ``coverage-report-html`` (line counts only) on runs that do not
    upload the JSON export artifact.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        try:
            _run_gh(
                [
                    "run",
                    "download",
                    str(run_id),
                    "--repo",
                    repo,
                    "--name",
                    EXPORT_JSON_ARTIFACT,
                    "--dir",
                    tmpdir,
                ]
            )
            json_files = sorted([*tmp.rglob("*.json.gz"), *tmp.rglob("*.json")])
            if json_files:
                return load_export_json(json_files[0]), EXPORT_JSON_ARTIFACT
        except RuntimeError:
            pass

    with tempfile.TemporaryDirectory() as tmpdir:
        _run_gh(
            [
                "run",
                "download",
                str(run_id),
                "--repo",
                repo,
                "--name",
                HTML_REPORT_ARTIFACT,
                "--dir",
                tmpdir,
            ]
        )
        return (
            load_html_coverage_dir(Path(tmpdir), target_files),
            HTML_REPORT_ARTIFACT,
        )


def _lookup_detailed_coverage(
    path: str,
    by_path: dict[str, DetailedFileCoverage],
) -> DetailedFileCoverage | None:
    if path in by_path:
        return by_path[path]
    suffix = "/" + path
    matches = [k for k in by_path if k.endswith(suffix)]
    if matches:
        return by_path[min(matches, key=len)]
    return None


def _summarize_detailed(
    detail: DetailedFileCoverage,
    included_lines: set[int] | None,
) -> tuple[int, int, int, int, bool]:
    """Return ``(lines, missed_lines, branches, missed_branches, branches_ok)``."""
    lines = missed_lines = 0
    for line_no, count in detail.lines.items():
        if included_lines is None or line_no in included_lines:
            lines += 1
            if count == 0:
                missed_lines += 1

    if detail.branches is None:
        return lines, missed_lines, 0, 0, False

    branches = missed_branches = 0
    for br in detail.branches:
        if included_lines is None or br.line in included_lines:
            branches += 2
            if br.true_count == 0:
                missed_branches += 1
            if br.false_count == 0:
                missed_branches += 1
    return lines, missed_lines, branches, missed_branches, True


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


def _file_metrics(
    path: str,
    included_lines: set[int] | None,
    by_path: dict[str, FileCoverage],
    detailed_by_path: dict[str, DetailedFileCoverage] | None,
) -> tuple[int, int, int, int, bool, bool]:
    """Return ``(lines, missed_lines, branches, missed_branches, branches_ok, present)``."""
    if included_lines is not None:
        detail = (
            _lookup_detailed_coverage(path, detailed_by_path)
            if detailed_by_path is not None
            else None
        )
        if detail is None:
            if _lookup_coverage(path, by_path) is None:
                return 0, 0, 0, 0, True, False
            raise RuntimeError(
                f"File '{path}' has a line mask, but per-line coverage data "
                "is unavailable. Pass --html-dir, --export-json, or fetch from CI."
            )
        lines, missed_lines, branches, missed_branches, branches_ok = (
            _summarize_detailed(detail, included_lines)
        )
        return lines, missed_lines, branches, missed_branches, branches_ok, True

    cov = _lookup_coverage(path, by_path)
    if cov is not None:
        return (
            cov.lines,
            cov.missed_lines,
            cov.branches,
            cov.missed_branches,
            True,
            True,
        )

    if detailed_by_path is not None:
        detail = _lookup_detailed_coverage(path, detailed_by_path)
        if detail is not None:
            lines, missed_lines, branches, missed_branches, branches_ok = (
                _summarize_detailed(detail, None)
            )
            return lines, missed_lines, branches, missed_branches, branches_ok, True

    return 0, 0, 0, 0, True, False


def compute_metrics(
    repo_root: Path,
    mappings: Sequence[SpecMapping],
    coverage_files: Sequence[FileCoverage],
    include_questionable: bool = False,
    spec_masks: dict[str, dict[str, set[int]]] | None = None,
    detailed_coverage: dict[str, DetailedFileCoverage] | None = None,
) -> tuple[list[SpecMetrics], SpecMetrics, int]:
    """Aggregate LoC and coverage metrics per specification and overall."""
    by_path: dict[str, FileCoverage] = {entry.path: entry for entry in coverage_files}
    text_cache: dict[str, str] = {}

    def file_text(rel_path: str) -> str:
        if rel_path not in text_cache:
            text_cache[rel_path] = (repo_root / rel_path).read_text(encoding="utf-8")
        return text_cache[rel_path]

    def cpp_loc(rel_path: str, included_lines: set[int] | None) -> int:
        return count_cpp_loc(file_text(rel_path), included_lines)

    per_spec: list[SpecMetrics] = []
    all_unique_files: list[str] = []
    # Maps each unique file to its merged included line set across specs
    # (None means at least one spec includes the whole file).
    merged_masks: dict[str, set[int] | None] = {}

    for mapping in mappings:
        files = list(mapping.core_files)
        if include_questionable:
            for path in mapping.questionable_files:
                if path not in files:
                    files.append(path)

        mask = (spec_masks or {}).get(mapping.name, {})
        spec_is_masked = any(path in mask for path in files)

        code_loc = 0
        lines = missed_lines = branches = missed_branches = 0
        branches_available = True
        missing: list[str] = []

        for path in files:
            included = mask.get(path)
            code_loc += cpp_loc(path, included)
            f_lines, f_missed, f_br, f_br_missed, f_br_ok, present = _file_metrics(
                path, included, by_path, detailed_coverage
            )
            if not present:
                missing.append(path)
            else:
                lines += f_lines
                missed_lines += f_missed
                if f_br_ok:
                    branches += f_br
                    missed_branches += f_br_missed
                else:
                    branches_available = False

            if path not in merged_masks:
                all_unique_files.append(path)
                merged_masks[path] = None if included is None else set(included)
            elif merged_masks[path] is not None:
                if included is None:
                    merged_masks[path] = None
                else:
                    merged_masks[path] |= included

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
                masked=spec_is_masked,
                branches_available=branches_available,
            )
        )

    total_code_loc = 0
    total_lines = total_missed_lines = total_branches = total_missed_branches = 0
    total_branches_available = True
    total_missing: list[str] = []
    for path in all_unique_files:
        included = merged_masks[path]
        total_code_loc += cpp_loc(path, included)
        f_lines, f_missed, f_br, f_br_missed, f_br_ok, present = _file_metrics(
            path, included, by_path, detailed_coverage
        )
        if not present:
            total_missing.append(path)
        else:
            total_lines += f_lines
            total_missed_lines += f_missed
            if f_br_ok:
                total_branches += f_br
                total_missed_branches += f_br_missed
            else:
                total_branches_available = False

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
        masked=any(m.masked for m in per_spec),
        branches_available=total_branches_available,
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
    spec_masks: dict[str, dict[str, set[int]]] | None = None,
    detailed_coverage: dict[str, DetailedFileCoverage] | None = None,
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
        name = item.name
        if item.masked and item is not total:
            name = f"{name} (masked)"
        label = f"**{name}**" if markdown and item is total else name
        branch_pair = (
            f"{item.branches_hit:,}/{item.branches:,}"
            if item.branches_available
            else "-"
        )
        rows.append(
            [
                label,
                str(len(item.files)),
                f"{item.code_loc:,}",
                f"{item.spec_loc:,}",
                f"{item.total_lean_loc:,}",
                f"{item.lines_hit:,}/{item.lines:,}",
                _format_percentage(item.line_coverage),
                branch_pair,
                _format_percentage(item.branch_coverage),
            ]
        )

    out: list[str] = [_format_table(headers, rows, right_align, markdown)]

    scope = "core + questionable" if include_questionable else "core only"
    detail_note = (
        f"; masked line/branch source: {source.detail_description}"
        if source.detail_description
        else ""
    )
    notes = [
        f"Coverage source: {source.description} (scope: {scope}{detail_note}).",
        (
            "Code LoC counts non-blank, non-comment C/C++ lines; "
            "Spec LoC counts non-blank, non-comment Lean lines in Model and Properties; "
            "Total Lean LoC includes Proofs, TraceValidation/Replay, and Tests "
            f"(shared lean/common adds {common_lean_loc:,} LoC)."
        ),
    ]
    masked_specs = [m.name for m in per_spec if m.masked]
    if masked_specs:
        mask_files = ", ".join(
            (
                f"`lean/{name}/coverage_mask.json`"
                if markdown
                else f"lean/{name}/coverage_mask.json"
            )
            for name in masked_specs
        )
        notes.append(f"Line-range masks applied: {mask_files}.")
    if any(not m.branches_available for m in [*per_spec, total]):
        notes.append(
            "Masked branch coverage requires an llvm-cov JSON export "
            f"(artifact `{EXPORT_JSON_ARTIFACT}` or --export-json); "
            "rows with masked files show '-' for branches when only HTML line coverage is available."
        )
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
            mask = (spec_masks or {}).get(item.name, {})
            for path in item.files:
                included = mask.get(path)
                loc = count_cpp_loc(
                    (repo_root / path).read_text(encoding="utf-8"), included
                )
                f_lines, f_missed, f_br, f_br_missed, f_br_ok, present = _file_metrics(
                    path, included, by_path, detailed_coverage
                )
                if not present:
                    line_str = "-"
                    line_cov = "-"
                    branch_str = "-"
                    branch_cov = "-"
                else:
                    line_str = f"{f_lines - f_missed:,}/{f_lines:,}"
                    line_cov = _format_percentage(_percentage(f_lines, f_missed))
                    if f_br_ok:
                        branch_str = f"{f_br - f_br_missed:,}/{f_br:,}"
                        branch_cov = _format_percentage(_percentage(f_br, f_br_missed))
                    else:
                        branch_str = "-"
                        branch_cov = "-"
                file_label = f"`{path}`" if markdown else path
                if included is not None:
                    file_label += " (masked)"
                file_rows.append(
                    [
                        item.name,
                        file_label,
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
        "--export-json",
        default=None,
        help=(
            "Path to a local llvm-cov export JSON (.json or .json.gz) for "
            "masked line and branch coverage."
        ),
    )
    parser.add_argument(
        "--html-dir",
        default=None,
        help=(
            "Path to an extracted coverage-report-html directory for masked "
            "line coverage."
        ),
    )
    parser.add_argument(
        "--no-masks",
        action="store_true",
        help="Ignore lean/<spec>/coverage_mask.json files and report whole-file numbers.",
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

    spec_masks: dict[str, dict[str, set[int]]] = {}
    if not args.no_masks:
        for mapping in mappings:
            allowed_files = list(mapping.core_files) + list(mapping.questionable_files)
            mask = load_spec_mask(repo_root, mapping.name, allowed_files)
            if mask:
                spec_masks[mapping.name] = mask

    masked_files: list[str] = []
    for mapping in mappings:
        mask = spec_masks.get(mapping.name, {})
        active = list(mapping.core_files)
        if args.include_questionable:
            active.extend(mapping.questionable_files)
        for path in active:
            if path in mask and path not in masked_files:
                masked_files.append(path)

    detailed_coverage: dict[str, DetailedFileCoverage] | None = None
    detail_description: str | None = None

    if args.report is not None:
        report_path = Path(args.report)
        source = ReportSource(
            text=report_path.read_text(encoding="utf-8", errors="replace"),
            description=str(report_path),
        )
        coverage_files = extract_file_coverage(source.text)
    elif args.export_json is not None and args.run_id is None:
        export_path = Path(args.export_json)
        detailed_coverage = load_export_json(export_path)
        detail_description = str(export_path)
        source = ReportSource(
            text="",
            description=str(export_path),
            detail_description=detail_description,
        )
        coverage_files = []
    else:
        source = fetch_ci_coverage_report(args.repo, args.branch, args.run_id)
        coverage_files = extract_file_coverage(source.text)

    if detailed_coverage is None:
        if args.export_json is not None:
            export_path = Path(args.export_json)
            detailed_coverage = load_export_json(export_path)
            detail_description = str(export_path)
        elif args.html_dir is not None:
            html_path = Path(args.html_dir)
            detailed_coverage = load_html_coverage_dir(html_path, masked_files)
            detail_description = str(html_path)
        elif masked_files and source.run_id is not None:
            detailed_coverage, artifact_used = fetch_ci_detailed_coverage(
                args.repo, source.run_id, masked_files
            )
            detail_description = f"artifact `{artifact_used}`"

    if detail_description is not None and source.detail_description is None:
        source = source._replace(detail_description=detail_description)

    if not coverage_files and detailed_coverage is None:
        print("No per-file coverage rows found in report.", file=sys.stderr)
        return 1

    per_spec, total, common_lean_loc = compute_metrics(
        repo_root=repo_root,
        mappings=mappings,
        coverage_files=coverage_files,
        include_questionable=args.include_questionable,
        spec_masks=spec_masks,
        detailed_coverage=detailed_coverage,
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
            spec_masks=spec_masks,
            detailed_coverage=detailed_coverage,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
