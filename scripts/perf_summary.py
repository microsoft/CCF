# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import argparse
from datetime import datetime, timezone
from typing import List


def list_perf_files(directory: str) -> List[str]:
    """Return the sorted list of file names available in the perf directory."""
    if not os.path.isdir(directory):
        return []
    return sorted(
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    )


def render_markdown_table(directory: str, files: List[str]) -> str:
    """Render a markdown table listing the files available in the directory."""
    lines = [f"## Perf data files in `{directory}`", ""]

    if not files:
        lines.append("_No perf data files found._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| File | Size (bytes) | Modified (UTC) |")
    lines.append("| --- | --- | --- |")
    for name in files:
        path = os.path.join(directory, name)
        size = os.path.getsize(path)
        modified = datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"| {name} | {size} | {modified} |")

    lines.append("")
    lines.append(f"Total: {len(files)} file(s)")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List the files in a perf directory as a markdown table."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="perf",
        help="Directory containing the perf data files (default: perf)",
    )
    args = parser.parse_args()

    files = list_perf_files(args.directory)
    print(render_markdown_table(args.directory, files))


if __name__ == "__main__":
    sys.exit(main())
