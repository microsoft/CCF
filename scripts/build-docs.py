# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Build documentation versions with their own sources and Python dependencies."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sourcedir", type=Path)
    parser.add_argument("outputdir", type=Path)
    parser.add_argument("-D", dest="defines", action="append", default=[])
    args = parser.parse_args()
    sourcedir = args.sourcedir.resolve()
    root = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], cwd=sourcedir, text=True
        ).strip()
    )
    relative_source = sourcedir.relative_to(root)
    defines = [arg for value in args.defines for arg in ("-D", value)]
    metadata = json.loads(
        subprocess.check_output(
            [
                sys.executable,
                "-m",
                "sphinx_multiversion",
                "--dump-metadata",
                *defines,
                str(sourcedir),
                str(args.outputdir.resolve()),
            ],
            cwd=root,
            text=True,
        )
    )
    if not metadata:
        raise RuntimeError("No matching documentation versions found")

    with tempfile.TemporaryDirectory(prefix="ccf-docs-") as directory:
        workspace = Path(directory)
        for index, (name, data) in enumerate(metadata.items()):
            checkout = workspace / str(index)
            with tempfile.TemporaryFile() as archive:
                subprocess.run(
                    ["git", "archive", f"refs/{data['source']}/{name}"],
                    cwd=root,
                    stdout=archive,
                    check=True,
                )
                archive.seek(0)
                with tarfile.open(fileobj=archive) as contents:
                    contents.extractall(checkout, filter="data")
            data["basedir"] = str(checkout)
            data["sourcedir"] = str(checkout / relative_source)
            data["confdir"] = data["sourcedir"]

        metadata_path = workspace / "versions.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        for name, data in metadata.items():
            checkout = Path(data["basedir"])
            environment = checkout / "env"
            subprocess.run(
                ["uv", "venv", "--python", sys.executable, str(environment)], check=True
            )
            python = environment / "bin" / "python"
            subprocess.run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    str(python),
                    "-e",
                    str(checkout / "python"),
                    "-r",
                    str(Path(data["sourcedir"]) / "requirements.txt"),
                    "-r",
                    str(sourcedir / "historical_ccf_requirements.txt"),
                ],
                check=True,
            )
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "sphinx",
                    "-b",
                    "html",
                    *defines,
                    "-D",
                    f"smv_metadata_path={metadata_path}",
                    "-D",
                    f"smv_current_version={name}",
                    data["sourcedir"],
                    data["outputdir"],
                ],
                cwd=checkout,
                env={
                    **os.environ,
                    "PATH": f"{environment / 'bin'}:{os.environ['PATH']}",
                },
                check=True,
            )


if __name__ == "__main__":
    main()
