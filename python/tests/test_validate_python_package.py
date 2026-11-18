# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parents[2] / "scripts" / "validate_python_package.py"
RELEASE_VERSION_SCRIPT = SCRIPT_PATH.with_name("python_release_version.py")
SPEC = importlib.util.spec_from_file_location("validate_python_package", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


@pytest.mark.parametrize(
    "tag, expected",
    [("7.0.25", "7.0.25"), ("8.0.0-dev10", "8.0.0.dev10"), ("8.0.0-rc0", "8.0.0rc0")],
)
def test_python_release_version(tag: str, expected: str) -> None:
    version = subprocess.check_output(
        [
            sys.executable,
            str(RELEASE_VERSION_SCRIPT),
            f"refs/tags/ccf-{tag}",
        ],
        text=True,
    )
    assert version.strip() == expected


@pytest.mark.parametrize("ref", ["refs/heads/main", "ccf-8.0.0-unknown"])
def test_reject_non_release_version(ref: str) -> None:
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(
            [sys.executable, str(RELEASE_VERSION_SCRIPT), ref],
            check=True,
        )


def test_sdk_version_from_checkout(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=CCF Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                *args,
            ],
            cwd=tmp_path,
            text=True,
        ).strip()

    git("init", "--quiet")
    git("commit", "--allow-empty", "-m", "release")
    git("tag", "ccf-7.0.25")
    command = [sys.executable, str(RELEASE_VERSION_SCRIPT)]
    assert subprocess.check_output(command, cwd=tmp_path, text=True).strip() == "7.0.25"

    git("commit", "--allow-empty", "-m", "development")
    git("tag", "ccf-0.0.0-test")
    expected = f"7.0.25.post1+g{git('rev-parse', '--short', 'HEAD')}"
    assert subprocess.check_output(command, cwd=tmp_path, text=True).strip() == expected


def create_wheel(tmp_path: Path, *, name: str = "ccf", version: str = "1.2.3") -> Path:
    wheel_path = tmp_path / f"{name}-{version}-py3-none-any.whl"
    metadata_path = f"{name}-{version}.dist-info/METADATA"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        wheel.writestr(
            metadata_path,
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
    return wheel_path


def test_validate_wheel_accepts_matching_metadata(tmp_path: Path) -> None:
    VALIDATOR.validate_wheel(create_wheel(tmp_path), "1.2.3")


@pytest.mark.parametrize(
    "name, version, expected_error",
    [
        ("other", "1.2.3", "Expected project name ccf"),
        ("ccf", "2.0.0", "Expected version 1.2.3"),
    ],
)
def test_validate_wheel_rejects_mismatched_metadata(
    tmp_path: Path, name: str, version: str, expected_error: str
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        VALIDATOR.validate_wheel(
            create_wheel(tmp_path, name=name, version=version), "1.2.3"
        )


def test_validate_wheel_requires_single_metadata_file(tmp_path: Path) -> None:
    wheel_path = create_wheel(tmp_path)
    with zipfile.ZipFile(wheel_path, "a") as wheel:
        wheel.writestr(
            "other-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: other\nVersion: 1.2.3\n",
        )

    with pytest.raises(ValueError, match="Expected one METADATA file"):
        VALIDATOR.validate_wheel(wheel_path, "1.2.3")
