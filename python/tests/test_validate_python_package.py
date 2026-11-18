# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parents[2] / "scripts" / "validate_python_package.py"
VERSION_SCRIPT = str(SCRIPT_PATH.with_name("derive_python_version.py"))
SPEC = importlib.util.spec_from_file_location("validate_python_package", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


@pytest.mark.parametrize(
    "tag, expected",
    [
        ("ccf-7.0.25", "7.0.25"),
        ("refs/tags/ccf-8.0.0-dev10", "8.0.0.dev10"),
        ("ccf-8.0.0-rc0", "8.0.0rc0"),
        ("refs/heads/main", None),
        ("ccf-invalid", None),
        ("ccf-7.0.25-1-gabc1234", None),  # Local versions cannot be published.
    ],
)
def test_derive_python_version(tag: str, expected: str | None) -> None:
    result = subprocess.run(
        [sys.executable, VERSION_SCRIPT, tag],
        check=False,
        capture_output=True,
        text=True,
    )
    if expected is None:
        assert result.returncode == 2, result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected


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
