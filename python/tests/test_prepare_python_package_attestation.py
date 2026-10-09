# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import hashlib
import importlib.util
import io
import json
import zipfile
from http.client import HTTPMessage
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest

SCRIPT_PATH = (
    Path(__file__).parents[2] / "scripts" / "prepare_python_package_attestation.py"
)
SOURCE_COMMIT = "1" * 40


@pytest.fixture
def attestation(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(SCRIPT_PATH.parent))
    spec = importlib.util.spec_from_file_location("prepare_attestation", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def wheel_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as wheel:
        wheel.writestr(
            "ccf-7.0.19.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: ccf\nVersion: 7.0.19\n",
        )
    return output.getvalue()


@pytest.fixture
def metadata(wheel_bytes: bytes) -> dict:
    return {
        "info": {"name": "ccf", "version": "7.0.19"},
        "urls": [
            {
                "packagetype": "bdist_wheel",
                "filename": "ccf-7.0.19-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/ccf.whl",
                "digests": {"sha256": hashlib.sha256(wheel_bytes).hexdigest()},
                "yanked": False,
            }
        ],
    }


def mock_download(
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
) -> Mock:
    request = Mock(
        side_effect=[io.BytesIO(json.dumps(metadata).encode()), io.BytesIO(wheel_bytes)]
    )
    monkeypatch.setattr(attestation, "urlopen", request)
    return request


def test_download_verifies_onebranch_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
) -> None:
    request = mock_download(monkeypatch, attestation, metadata, wheel_bytes)
    wheel_path = attestation.download_wheel(
        "7.0.19", hashlib.sha256(wheel_bytes).hexdigest(), tmp_path
    )
    assert wheel_path.name == "ccf-7.0.19-py3-none-any.whl"
    assert wheel_path.read_bytes() == wheel_bytes
    assert request.call_count == 2


@pytest.mark.parametrize(
    "field, value, expected_error",
    [
        ("yanked", True, "yanked"),
        ("filename", "../ccf.whl", "filename"),
        ("url", "http://files.pythonhosted.org/ccf.whl", "HTTPS wheel URL"),
        ("url", "https://example.com/ccf.whl", "HTTPS wheel URL"),
        ("digests", {"sha256": "0" * 64}, "digest does not match"),
    ],
)
def test_download_rejects_invalid_wheel_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
    field: str,
    value: object,
    expected_error: str,
) -> None:
    metadata["urls"][0][field] = value
    request = mock_download(monkeypatch, attestation, metadata, wheel_bytes)
    with pytest.raises(ValueError, match=expected_error):
        attestation.download_wheel(
            "7.0.19", hashlib.sha256(wheel_bytes).hexdigest(), tmp_path
        )
    assert request.call_count == 1


@pytest.mark.parametrize("wheel_count", [0, 2])
def test_download_requires_one_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
    wheel_count: int,
) -> None:
    metadata["urls"] *= wheel_count
    mock_download(monkeypatch, attestation, metadata, wheel_bytes)
    with pytest.raises(ValueError, match="Expected one PyPI wheel"):
        attestation.download_wheel(
            "7.0.19", hashlib.sha256(wheel_bytes).hexdigest(), tmp_path
        )


def test_download_rejects_changed_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
) -> None:
    mock_download(monkeypatch, attestation, metadata, b"not the published wheel")
    with pytest.raises(ValueError, match="Downloaded wheel digest"):
        attestation.download_wheel(
            "7.0.19", hashlib.sha256(wheel_bytes).hexdigest(), tmp_path
        )


@pytest.mark.parametrize("digest", ["", "abc", "0" * 63, "0" * 65, "0" * 64 + "\n"])
def test_download_rejects_invalid_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    digest: str,
) -> None:
    request = Mock()
    monkeypatch.setattr(attestation, "urlopen", request)
    with pytest.raises(ValueError, match="Invalid OneBranch wheel"):
        attestation.download_wheel("7.0.19", digest, tmp_path)
    request.assert_not_called()


@pytest.mark.parametrize("field, value", [("name", "other"), ("version", "7.0.18")])
def test_download_rejects_mismatched_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
    field: str,
    value: str,
) -> None:
    metadata["info"][field] = value
    request = mock_download(monkeypatch, attestation, metadata, wheel_bytes)
    with pytest.raises(ValueError, match="requested CCF package"):
        attestation.download_wheel(
            "7.0.19", hashlib.sha256(wheel_bytes).hexdigest(), tmp_path
        )
    assert request.call_count == 1


def test_download_retries_only_unpublished_versions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    metadata: dict,
    wheel_bytes: bytes,
) -> None:
    request = Mock(
        side_effect=[
            HTTPError("https://pypi.org", 404, "Not found", HTTPMessage(), None),
            io.BytesIO(json.dumps(metadata).encode()),
            io.BytesIO(wheel_bytes),
        ]
    )
    sleep = Mock()
    monkeypatch.setattr(attestation, "urlopen", request)
    monkeypatch.setattr(attestation.time, "sleep", sleep)
    attestation.download_wheel(
        "7.0.19", hashlib.sha256(wheel_bytes).hexdigest(), tmp_path
    )
    assert request.call_count == 3
    sleep.assert_called_once_with(10)


@pytest.mark.parametrize("status, attempts", [(404, 6), (500, 1)])
def test_download_surfaces_pypi_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    status: int,
    attempts: int,
) -> None:
    request = Mock(
        side_effect=HTTPError(
            "https://pypi.org", status, "Unavailable", HTTPMessage(), None
        )
    )
    monkeypatch.setattr(attestation, "urlopen", request)
    monkeypatch.setattr(attestation.time, "sleep", Mock())
    with pytest.raises(HTTPError):
        attestation.download_wheel("7.0.19", "0" * 64, tmp_path)
    assert request.call_count == attempts


@pytest.mark.parametrize(
    "release_tag, package_version",
    [("ccf-7.0.19", "7.0.19"), ("ccf-8.0.0-dev1", "8.0.0.dev1")],
)
def test_validate_release_matches_tag_and_commit(
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    release_tag: str,
    package_version: str,
) -> None:
    request = Mock(side_effect=[SOURCE_COMMIT, '{"isDraft": false}'])
    monkeypatch.setattr(attestation.subprocess, "check_output", request)
    attestation.validate_release(release_tag, package_version, SOURCE_COMMIT)
    assert request.call_count == 2


@pytest.mark.parametrize(
    "release_tag, package_version, source_commit, responses, expected_error",
    [
        ("main", "7.0.19", SOURCE_COMMIT, [], "Release tag"),
        ("ccf-7.0.18", "7.0.19", SOURCE_COMMIT, [], "Release tag"),
        ("ccf-7.0.19", "../7.0.19", SOURCE_COMMIT, [], "Invalid Python package"),
        ("ccf-7.0.19", "7.0.19", "not-a-commit", [], "Invalid OneBranch"),
        ("ccf-7.0.19", "7.0.19", SOURCE_COMMIT, ["2" * 40], "source commit"),
        (
            "ccf-7.0.19",
            "7.0.19",
            SOURCE_COMMIT,
            [SOURCE_COMMIT, '{"isDraft": true}'],
            "must be published",
        ),
    ],
)
def test_validate_release_rejects_unverified_source(
    monkeypatch: pytest.MonkeyPatch,
    attestation: ModuleType,
    release_tag: str,
    package_version: str,
    source_commit: str,
    responses: list[str],
    expected_error: str,
) -> None:
    request = Mock(side_effect=responses)
    monkeypatch.setattr(attestation.subprocess, "check_output", request)
    with pytest.raises(ValueError, match=expected_error):
        attestation.validate_release(release_tag, package_version, source_commit)
