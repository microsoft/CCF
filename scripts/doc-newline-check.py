#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Markdown fences may include an info string, for example ```console in the Lean
# READMEs. Their contents must not be interpreted as prose.
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")

# Capture the prose and its alignment separately. This lets a wrapped item such
# as "- All endpoints validate...\n  `latest`." be checked and fixed without
# treating the continuation as an indented code block.
LIST_RE = re.compile(r"^(?P<indent>\s*)(?:[-+*]|\d+[.)])\s+(?P<content>.*)$")

# Issue templates use bold-only labels such as "**Describe the bug**". These
# introduce the following prose but are not themselves incomplete sentences.
MARKUP_HEADING_RE = re.compile(r"^\s*(?:\*\*[^*]+\*\*|__[^_]+__)\s*$")

# .github/workflows/README.md uses explicit records such as "File: ci.yml" and
# "3rd party dependencies: None". Keep this deliberately narrower than a
# general "Label: value" rule, since ordinary prose can also contain a colon.
METADATA_RE = re.compile(r"^(?:File|3rd party dependencies):\s+\S")

# Continuations can begin with opening punctuation or inline markup. For
# example, `latest` in src/node/gov/README.md must still count as prose rather
# than evading the check because its first visible character is a backtick.
PROSE_START_RE = re.compile(r"""^[\s"'(\[<{*_`]*[A-Za-z0-9]""")

# RST headings underline text with repeated punctuation, for example
# "JavaScript API\n--------------". The underline is document structure, not a
# prose continuation.
RST_ADORNMENT_RE = re.compile(
    r"^\s*([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])\1{2,}\s*$"
)

STRUCTURAL_RE = re.compile(
    r"^\s*(?:"
    r"\.\.(?:\s|$)|"  # ".. note::" and other RST directives.
    r"#{1,6}(?:\s|$)|"  # "# Heading" Markdown headings.
    r">(?:\s|$)|"  # "> quoted text" block quotes.
    r"\|.*\|(?:\s*$)|"  # "| Rule | Effect |" table rows.
    r":[A-Za-z0-9_-]+:(?:\s|$)|"  # ":project: CCF" RST fields.
    r"\[[^\]]+\]:\s|"  # "[7.0.19]: https://..." link definitions.
    r"\[[0-9#*]+\](?:\s|$)|"  # "[1]" footnote/citation labels.
    r"</?[A-Za-z][^>]*>"  # "<details>" and other standalone HTML tags.
    r")"
)

# Fix mode splits only prose that it first had to join. The negative lookbehinds
# keep examples such as "e.g. `schema.py`" and "i.e. a value" intact, while a
# joined "The model records no history. The proofs..." becomes two lines.
SENTENCE_BOUNDARY_RE = re.compile(
    r"""(?<![eE]\.[gG]\.)(?<![iI]\.[eE]\.)(?<=[.!?])(?P<closing>["')\]}*_`]*)(?P<space>\s+)(?=[A-Z`*[])"""
)

# "e.g." and "i.e." can end a physical line without ending the sentence.
ABBREVIATION_END_RE = re.compile(r"(?:e\.g|i\.e)\.\s*$", re.IGNORECASE)

# A sentence remains complete when punctuation is followed by closing quotes,
# brackets, emphasis, inline-code markers, or an RST escape. For example,
# 'returns `none`.' must not be joined to the next sentence.
SENTENCE_END_RE = re.compile(r"""[.!?](?:["')\]}*_`]|\\)*\s*$""")


def git_output(arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        check=True,
        capture_output=True,
    )
    return result.stdout


def tracked_documentation_files() -> list[Path]:
    return [
        Path(name)
        for name in git_output(
            [
                "ls-files",
                "-z",
                "--",
                "*.md",
                "*.rst",
            ]
        )
        .decode()
        .split("\0")
        if name and not name.startswith("3rdparty/")
    ]


def is_structural(line: str) -> bool:
    return bool(
        not line.strip()
        or line[0].isspace()
        or LIST_RE.match(line)
        or MARKUP_HEADING_RE.match(line)
        or METADATA_RE.match(line)
        or STRUCTURAL_RE.match(line)
        or RST_ADORNMENT_RE.match(line)
    )


def list_prose_context(lines: list[str], index: int) -> tuple[str, int] | None:
    line = lines[index]
    match = LIST_RE.match(line)
    if match:
        return match.group("content"), index

    indentation = len(line) - len(line.lstrip())
    content = line.lstrip()
    if indentation == 0 or is_structural(content):
        return None

    for previous_index in range(index - 1, -1, -1):
        previous = lines[previous_index]
        if not previous.strip():
            return None

        previous_match = LIST_RE.match(previous)
        if previous_match:
            content_column = previous_match.start("content")
            # Markdown permits up to three extra spaces of hanging indentation.
            # Four more spaces introduce an indented code block within the item.
            if content_column <= indentation < content_column + 4:
                return line.lstrip(), previous_index
            return None

        previous_indentation = len(previous) - len(previous.lstrip())
        if previous_indentation < indentation:
            return None

    return None


def excluded_lines(lines: list[str], markdown: bool) -> set[int]:
    excluded = set()
    fence = None
    frontmatter = bool(lines and lines[0].strip() == "---")
    html_comment = False

    for index, line in enumerate(lines):
        if frontmatter:
            excluded.add(index)
            if index > 0 and line.strip() in ("---", "..."):
                frontmatter = False
            continue

        if html_comment:
            excluded.add(index)
            if "-->" in line:
                html_comment = False
            continue

        if "<!--" in line:
            excluded.add(index)
            if "-->" not in line.split("<!--", 1)[1]:
                html_comment = True
            continue

        if markdown:
            fence_match = FENCE_RE.match(line)
            if fence is None and fence_match:
                marker = fence_match.group(1)
                fence = (marker[0], len(marker))
                excluded.add(index)
                continue
            if fence is not None:
                excluded.add(index)
                marker, minimum_length = fence
                if re.fullmatch(
                    rf"\s*{re.escape(marker)}{{{minimum_length},}}\s*", line
                ):
                    fence = None
    return excluded


def prose_context(
    lines: list[str], index: int, excluded: set[int]
) -> tuple[str, int] | None:
    if index in excluded:
        return None

    list_context = list_prose_context(lines, index)
    if list_context is not None:
        return list_context

    if is_structural(lines[index]):
        return None

    return lines[index], index


def ends_sentence(line: str) -> bool:
    return bool(SENTENCE_END_RE.search(line) and not ABBREVIATION_END_RE.search(line))


def suspicious_newlines(lines: list[str], markdown: bool) -> list[int]:
    findings = []
    excluded = excluded_lines(lines, markdown)

    for index, line in enumerate(lines[:-1]):
        if index in excluded or index + 1 in excluded:
            continue

        current_list_context = list_prose_context(lines, index)
        next_list_context = list_prose_context(lines, index + 1)
        if current_list_context is not None or next_list_context is not None:
            if (
                current_list_context is not None
                and next_list_context is not None
                and current_list_context[1] == next_list_context[1]
                and not ends_sentence(current_list_context[0])
                and PROSE_START_RE.match(next_list_context[0])
            ):
                findings.append(index + 1)
            continue

        next_line = lines[index + 1]
        current_context = prose_context(lines, index, excluded)
        next_context = prose_context(lines, index + 1, excluded)
        if (
            current_context is None
            or next_context is None
            or line.endswith(("  ", "\\"))
            or ends_sentence(line)
            or not PROSE_START_RE.match(next_context[0])
        ):
            continue

        findings.append(index + 1)

    return findings


def format_lines(lines: list[str], markdown: bool) -> tuple[list[str], int]:
    joins = set(suspicious_newlines(lines, markdown))
    if not joins:
        return lines, 0

    formatted = []
    index = 0
    while index < len(lines):
        line = lines[index]
        changed = False
        while index + 1 < len(lines) and index + 1 in joins:
            index += 1
            line = f"{line.rstrip()} {lines[index].lstrip()}"
            changed = True

        if changed:
            list_match = LIST_RE.match(line)
            if list_match:
                continuation = " " * list_match.start("content")
            else:
                continuation = line[: len(line) - len(line.lstrip())]
            line = SENTENCE_BOUNDARY_RE.sub(
                lambda match: match.group("closing") + "\n" + continuation,
                line,
            )
            formatted.extend(line.splitlines())
        else:
            formatted.append(line)
        index += 1

    return formatted, len(joins)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Markdown and RST for mid-sentence newlines."
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="rewrite mid-sentence newlines using one sentence per line",
    )
    parser.add_argument("paths", nargs="*", type=Path)
    arguments = parser.parse_args()

    paths = arguments.paths or tracked_documentation_files()

    failed = False
    fixed = 0
    for path in paths:
        if not path.is_file():
            continue

        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if arguments.fix:
            lines, joins = format_lines(lines, path.suffix.lower() == ".md")
            if joins:
                path.write_text(
                    "\n".join(lines) + ("\n" if text.endswith("\n") else ""),
                    encoding="utf-8",
                )
                fixed += joins
            continue

        for line_number in suspicious_newlines(lines, path.suffix.lower() == ".md"):
            print(
                f"{path}:{line_number}: prose line appears to continue mid-sentence "
                "on the next line"
            )
            failed = True

    if arguments.fix:
        print(f"Fixed {fixed} mid-sentence newlines.")
        return 0

    if failed:
        print(
            "Keep sentences on continuous lines; do not manually wrap prose to a "
            "fixed width.",
            file=sys.stderr,
        )
        return 1

    print("All checked Markdown and RST prose avoids mid-sentence newlines.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
