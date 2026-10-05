# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import zipfile
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "validate_python_package.py"
SPEC = importlib.util.spec_from_file_location("validate_python_package", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


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
