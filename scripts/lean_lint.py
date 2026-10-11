# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run Mathlib source/style checks on every first-party Lean source under lean/."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LEAN_ROOT = ROOT / "lean"


def source_files(root: Path) -> list[Path]:
    output = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "lean/",
        ]
    )
    files = sorted(
        {
            root / os.fsdecode(name)
            for name in output.split(b"\0")
            if name.endswith(b".lean")
        }
    )
    files = [file for file in files if file.is_file()]
    if not files:
        raise RuntimeError("No Lean sources found under lean/")
    for file in files:
        if not file.resolve().is_relative_to(root.resolve()):
            raise RuntimeError(f"Lean source points outside the repository: {file}")
    return files


def package_for(file: Path, lean_root: Path) -> Path:
    for parent in file.parents:
        if not parent.is_relative_to(lean_root):
            break
        if any(
            (parent / name).is_file() for name in ("lakefile.toml", "lakefile.lean")
        ):
            return parent
    raise RuntimeError(f"No Lake package owns Lean source {file}")


def toolchain_for(package: Path, lean_root: Path) -> str:
    for parent in (package, *package.parents):
        if not parent.is_relative_to(lean_root):
            break
        toolchain = parent / "lean-toolchain"
        if toolchain.is_file():
            return toolchain.read_text().strip()
    raise RuntimeError(f"No lean-toolchain found for {package}")


def main() -> None:
    files = source_files(ROOT)
    packages = {file: package_for(file, LEAN_ROOT) for file in files}
    expected_toolchain = toolchain_for(LEAN_ROOT, LEAN_ROOT)
    for package in sorted(set(packages.values())):
        actual_toolchain = toolchain_for(package, LEAN_ROOT)
        if actual_toolchain != expected_toolchain:
            raise RuntimeError(
                f"{package}: toolchain {actual_toolchain!r} does not match "
                f"the source linter's {expected_toolchain!r}"
            )

    package_env = os.environ.copy()
    package_env.pop("LEAN_PATH", None)
    package_env.pop("LEAN_SRC_PATH", None)
    for package in sorted(set(packages.values())):
        print(f"Building {package.relative_to(ROOT)}", flush=True)
        subprocess.run(
            ["lake", "--allow-empty", "build", "--wfail"],
            cwd=package,
            env=package_env,
            check=True,
        )

    driver = LEAN_ROOT / "SourceLint.lean"
    failures = []
    with tempfile.TemporaryDirectory(prefix="ccf-lean-lint-") as directory:
        setup = Path(directory) / "module-setup.json"
        for file in files:
            package = packages[file]
            print(f"Linting {file.relative_to(ROOT)}", flush=True)
            with setup.open("w") as output:
                subprocess.run(
                    ["lake", "setup-file", str(file)],
                    cwd=package,
                    env=package_env,
                    stdout=output,
                    check=True,
                )
            prepared = subprocess.run(
                ["lean", "--run", str(driver), str(file), str(setup)],
                cwd=package,
                check=False,
            )
            if prepared.returncode not in (0, 1):
                raise RuntimeError(
                    f"Source lint driver failed with exit code {prepared.returncode}: {file}"
                )
            result = subprocess.run(
                ["lean", f"--setup={setup}", str(file)], cwd=package, check=False
            )
            if prepared.returncode or result.returncode:
                print(
                    f"{file.relative_to(ROOT)}: text checks exited {prepared.returncode}, "
                    f"source checks exited {result.returncode}",
                    file=sys.stderr,
                )
                failures.append(file.relative_to(ROOT))

    if failures:
        raise RuntimeError(
            f"Source/style checks failed for {len(failures)} of {len(files)} files:\n"
            + "\n".join(str(file) for file in failures)
        )
    print(
        f"Source/style checks passed for all {len(files)} Lean files "
        f"in {len(set(packages.values()))} packages."
    )


if __name__ == "__main__":
    main()
