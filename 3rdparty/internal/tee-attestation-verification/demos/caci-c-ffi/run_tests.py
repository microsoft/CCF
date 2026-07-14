#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Build the CACI C FFI demo and check it against the checked-in golden output.

Run it directly::

    python3 demos/caci-c-ffi/run_tests.py

or through the unittest CLI::

    python3 -m unittest discover --start-directory demos/caci-c-ffi \
        --pattern run_tests.py
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parents[1]
TEST_DATA = DEMO_DIR / "test-data"
DEMO_BINARY_NAME = "tav-caci-c-ffi-demo"

# These arguments mirror the CACI C FFI demo CI job and the demo README.
TRUSTED_DIDX509 = (
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"
    "::eku:1.3.6.1.4.1.311.76.59.1.2"
)
UVM_FEED = "ContainerPlat-AMD-UVM"
MINIMUM_SVN = "104"


def demo_args(report_path: Path) -> list[str]:
    """Build the positional argument list the demo expects."""
    return [
        str(report_path),
        str(REPO_ROOT / "caci" / "tests" / "fixtures" / "host-amd-cert.base64"),
        str(REPO_ROOT / "caci" / "tests" / "fixtures" / "reference-info.base64"),
        TRUSTED_DIDX509,
        str(TEST_DATA / "policy.hex"),
        UVM_FEED,
        MINIMUM_SVN,
    ]


def build_demo(build_dir: Path, *, link_static: bool) -> Path:
    """Configure and build the demo, returning the path to the executable."""
    configure = [
        "cmake",
        "-S",
        str(DEMO_DIR),
        "-B",
        str(build_dir),
        "-G",
        "Ninja",
    ]
    if link_static:
        configure.append("-DTAV_LINK_STATIC=ON")
    subprocess.run(configure, check=True, cwd=REPO_ROOT)
    subprocess.run(["cmake", "--build", str(build_dir)], check=True, cwd=REPO_ROOT)
    return build_dir / DEMO_BINARY_NAME


class DemoTestMixin:
    """Shared build-and-run checks; concrete classes set ``link_static``."""

    link_static = False

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        assert (
            shutil.which("cmake") is not None and shutil.which("ninja") is not None
        ), "cmake and ninja are required to build the demo"
        cls._build_dir = tempfile.TemporaryDirectory()
        cls.binary = build_demo(Path(cls._build_dir.name), link_static=cls.link_static)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._build_dir.cleanup()
        super().tearDownClass()

    def run_demo(self, report_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.binary), *demo_args(report_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_verifies_fixture_matches_golden(self) -> None:
        result = self.run_demo(REPO_ROOT / "caci" / "tests" / "fixtures" / "report.hex")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (TEST_DATA / "sample-output.golden.txt").read_text()
        self.assertEqual(result.stdout, expected)

    def test_empty_report_reports_error(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".hex") as empty_report:
            result = self.run_demo(Path(empty_report.name))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        expected = (TEST_DATA / "empty-report-error.golden.txt").read_text()
        self.assertEqual(result.stderr, expected)


class SharedLibraryDemoTest(DemoTestMixin, unittest.TestCase):
    link_static = False


class StaticLibraryDemoTest(DemoTestMixin, unittest.TestCase):
    link_static = True


if __name__ == "__main__":
    unittest.main()
