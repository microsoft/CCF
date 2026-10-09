#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import urlopen

from validate_python_package import validate_wheel


def validate_release(
    release_tag: str, package_version: str, source_commit: str
) -> None:
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+]*", package_version):
        raise ValueError(f"Invalid Python package version: {package_version}")
    if (
        not release_tag.startswith("ccf-")
        or release_tag.removeprefix("ccf-").replace("-", ".", 1) != package_version
    ):
        raise ValueError("Release tag does not match the Python package version")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("Invalid OneBranch source commit")
    tag_commit = subprocess.check_output(
        ["git", "rev-parse", f"refs/tags/{release_tag}^{{commit}}"], text=True
    ).strip()
    if tag_commit != source_commit:
        raise ValueError("Release tag does not match the OneBranch source commit")
    release = json.loads(
        subprocess.check_output(
            [
                "gh",
                "release",
                "view",
                release_tag,
                "--repo",
                "microsoft/CCF",
                "--json",
                "isDraft",
            ],
            text=True,
        )
    )
    if release["isDraft"] is not False:
        raise ValueError("The GitHub release must be published before attestation")


def download_wheel(
    package_version: str, expected_sha256: str, output_dir: Path
) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Invalid OneBranch wheel SHA-256 digest")
    metadata_url = f"https://pypi.org/pypi/ccf/{quote(package_version, safe='')}/json"
    for attempt in range(6):
        try:
            with urlopen(metadata_url, timeout=30) as response:
                metadata = json.load(response)
            break
        except HTTPError as error:
            if error.code != 404 or attempt == 5:
                raise
            print(
                f"ccf {package_version} is not yet visible on PyPI; retrying in 10s",
                file=sys.stderr,
            )
            time.sleep(10)

    if (
        metadata["info"]["name"] != "ccf"
        or metadata["info"]["version"] != package_version
    ):
        raise ValueError("PyPI metadata does not match the requested CCF package")
    wheels = [
        asset for asset in metadata["urls"] if asset["packagetype"] == "bdist_wheel"
    ]
    if len(wheels) != 1:
        raise ValueError(f"Expected one PyPI wheel, found {len(wheels)}")
    wheel = wheels[0]
    if wheel["yanked"]:
        raise ValueError("The Python package has been yanked from PyPI")
    if wheel["digests"]["sha256"] != expected_sha256:
        raise ValueError("PyPI wheel digest does not match the OneBranch build")
    filename = wheel["filename"]
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", filename):
        raise ValueError("Invalid PyPI wheel filename")
    wheel_url = urlsplit(wheel["url"])
    if wheel_url.scheme != "https" or wheel_url.netloc != "files.pythonhosted.org":
        raise ValueError("Expected an HTTPS wheel URL on files.pythonhosted.org")

    output_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = output_dir / filename
    with urlopen(wheel["url"], timeout=30) as response, wheel_path.open("wb") as output:
        shutil.copyfileobj(response, output)
    with wheel_path.open("rb") as downloaded:
        actual_sha256 = hashlib.file_digest(downloaded, "sha256").hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError("Downloaded wheel digest does not match the OneBranch build")
    validate_wheel(wheel_path, package_version)
    return wheel_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify a OneBranch-published Python wheel before attestation"
    )
    parser.add_argument("release_tag")
    parser.add_argument("package_version")
    parser.add_argument("expected_sha256")
    parser.add_argument("source_commit")
    parser.add_argument("--output-dir", type=Path, default=Path("python-wheel"))
    args = parser.parse_args()
    validate_release(args.release_tag, args.package_version, args.source_commit)
    print(download_wheel(args.package_version, args.expected_sha256, args.output_dir))


if __name__ == "__main__":
    main()
