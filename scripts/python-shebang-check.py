#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Verify that tracked Python scripts keep shebang lines and executable bits in sync."""

import stat
import subprocess
import sys
from pathlib import Path

EXPECTED_SHEBANG = "#!/usr/bin/env python3"
EXCLUDED_PREFIXES = ("3rdparty/",)


def tracked_python_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        check=True,
        capture_output=True,
    )
    paths: list[Path] = []
    for raw in result.stdout.decode().split("\0"):
        if not raw or raw.startswith(EXCLUDED_PREFIXES):
            continue
        path = Path(raw)
        if path.is_file():
            paths.append(path)
    return paths


def check_file(path: Path) -> list[str]:
    mode = stat.S_IMODE(path.stat().st_mode)
    is_executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    with path.open("r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline().rstrip("\r\n")

    has_shebang = first_line.startswith("#!")
    errors: list[str] = []

    if is_executable and first_line != EXPECTED_SHEBANG:
        errors.append(
            f"{path}: executable Python file must start with '{EXPECTED_SHEBANG}'"
        )
    elif has_shebang:
        if first_line != EXPECTED_SHEBANG:
            errors.append(
                f"{path}: shebang must be '{EXPECTED_SHEBANG}' (found '{first_line}')"
            )
        if not is_executable:
            errors.append(f"{path}: has shebang but is not executable (run chmod +x)")

    return errors


def main() -> int:
    errors: list[str] = []
    for path in tracked_python_files():
        errors.extend(check_file(path))

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("All Python shebangs and executable bits are consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
