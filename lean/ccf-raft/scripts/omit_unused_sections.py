#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Apply Lean's unused-section-variable diagnostics to one ported proof file."""

import argparse
import re
from pathlib import Path

DIAGNOSTIC = re.compile(
    r"^(?:error|warning): (?P<path>.+\.lean):(?P<line>\d+):\d+: "
    r"automatically included section variable\(s\) unused in theorem `(?P<name>[^`]+)`:"
)
BINDER = re.compile(r"^\s+(\[.+\])$")


def repairs(log: str, target: Path) -> dict[int, tuple[str, list[str]]]:
    """Read only the target file's explicit unused-instance diagnostics."""
    lines = log.splitlines()
    result = {}
    for position, line in enumerate(lines):
        match = DIAGNOSTIC.match(line)
        if match is None or Path(match["path"]).resolve() != target:
            continue
        binders = []
        for following in lines[position + 1 :]:
            binder = BINDER.match(following)
            if binder is None:
                break
            binders.append(binder[1])
        if not binders:
            raise ValueError(f"Unsupported section-variable diagnostic: {line}")
        result[int(match["line"]) - 1] = (match["name"].split(".")[-1], binders)
    return result


def apply_repairs(text: str, edits: dict[int, tuple[str, list[str]]]) -> str:
    """Insert scoped omissions without altering statements or tactic bodies."""
    lines = text.splitlines(keepends=True)
    for position, (name, binders) in sorted(edits.items(), reverse=True):
        if (
            position >= len(lines)
            or re.search(
                rf"\b(?:lemma|theorem)\s+(?:[A-Za-z0-9_.]+\.)?{re.escape(name)}(?=\s|:|\()",
                lines[position],
            )
            is None
        ):
            raise ValueError(f"Stale diagnostic for {name} at line {position + 1}")
        start = position
        while start and lines[start - 1].lstrip().startswith("@["):
            start -= 1
        previous = start - 1
        while previous >= 0 and not lines[previous].strip():
            previous -= 1
        if previous >= 0 and lines[previous].rstrip().endswith("-/"):
            opening = previous
            while opening >= 0 and "/--" not in lines[opening]:
                if "/-" in lines[opening]:
                    break
                opening -= 1
            if opening >= 0 and lines[opening].lstrip().startswith("/--"):
                start = opening
        if (
            start
            and lines[start - 1].startswith("omit ")
            and lines[start - 1].rstrip().endswith(" in")
        ):
            old = lines[start - 1].strip()[5:-3].strip()
            extra = [binder for binder in binders if binder not in old]
            lines[start - 1] = f"omit {' '.join([old, *extra])} in\n"
        else:
            lines.insert(start, f"omit {' '.join(binders)} in\n")
    return "".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("proof", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "CCFRaft/Proofs"
    target = args.proof.resolve()
    if not target.is_relative_to(root) or target.suffix != ".lean":
        raise ValueError("Target must be a Lean file inside CCFRaft/Proofs")
    edits = repairs(args.log.read_text(), target)
    updated = apply_repairs(target.read_text(), edits)
    target.write_text(updated)
    print(f"{target.name}: scoped {len(edits)} unused-instance declarations")


if __name__ == "__main__":
    main()
