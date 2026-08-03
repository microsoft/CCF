#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Test the C# binding as a NuGet consumer.

Pack the binding into a temporary feed, restore the separate test project from
that package, and run the tests without rebuilding the binding from source.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import pathlib
import re
import subprocess
import tempfile
import uuid
import zipfile
import xml.etree.ElementTree as ElementTree


ROOT = pathlib.Path(__file__).resolve().parents[2]
CSHARP_ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE_PROJECT = (
    CSHARP_ROOT / "TeeAttestationVerification" / "TeeAttestationVerification.csproj"
)
TEST_PROJECT = (
    CSHARP_ROOT
    / "TeeAttestationVerification.Tests"
    / "TeeAttestationVerification.Tests.csproj"
)
NATIVE_ASSET = (
    "runtimes/linux-x64/native/libtee_attestation_verification_ffi.so"
)
EXPECTED_NATIVE_DEPENDENCIES = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libc.so.6",
        "libcrypto.so.3",
        "libgcc_s.so.1",
        "libssl.so.3",
    }
)
LOCK_FILE = (
    pathlib.Path(tempfile.gettempdir())
    / "tee-attestation-verification-csharp-tests.lock"
)


def run(command: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def test_package_version() -> str:
    version = ElementTree.parse(PACKAGE_PROJECT).getroot().findtext(
        "./PropertyGroup/Version"
    )
    if not version:
        raise RuntimeError(f"{PACKAGE_PROJECT} does not define Version")
    return f"{version}-test.{uuid.uuid4().hex[:12]}"


def verify_package(package: pathlib.Path, native_library: pathlib.Path) -> None:
    with zipfile.ZipFile(package) as archive:
        entries = set(archive.namelist())
        expected_managed = "lib/net8.0/TeeAttestationVerification.dll"
        expected_documentation = "lib/net8.0/TeeAttestationVerification.xml"
        if expected_managed not in entries:
            raise RuntimeError(f"{package} does not contain {expected_managed}")
        if expected_documentation not in entries:
            raise RuntimeError(f"{package} does not contain {expected_documentation}")
        if NATIVE_ASSET not in entries:
            raise RuntimeError(f"{package} does not contain {NATIVE_ASSET}")
        if any(
            "libssl" in entry.lower() or "libcrypto" in entry.lower()
            for entry in entries
        ):
            raise RuntimeError("OpenSSL libraries must not be bundled in the package")
        native_library.write_bytes(archive.read(NATIVE_ASSET))

    dynamic_section = subprocess.run(
        ["readelf", "--dynamic", "--wide", str(native_library)],
        check=True,
        capture_output=True,
        env={**os.environ, "LC_ALL": "C"},
        text=True,
    ).stdout
    dependencies = frozenset(
        re.findall(r"\(NEEDED\).*Shared library: \[([^]]+)]", dynamic_section)
    )
    if dependencies != EXPECTED_NATIVE_DEPENDENCIES:
        raise RuntimeError(
            f"{NATIVE_ASSET} dependencies differ: expected "
            f"{sorted(EXPECTED_NATIVE_DEPENDENCIES)}, found {sorted(dependencies)}"
        )


def run_tests(configuration: str) -> None:
    version = test_package_version()
    with tempfile.TemporaryDirectory(prefix="tav-csharp-tests-") as temporary:
        temp = pathlib.Path(temporary)
        feed = temp / "feed"
        feed.mkdir()
        env = os.environ.copy()
        env["NUGET_PACKAGES"] = str(temp / "packages")

        run(
            [
                "dotnet",
                "pack",
                str(PACKAGE_PROJECT),
                "--configuration",
                configuration,
                "--output",
                str(feed),
                f"-p:PackageVersion={version}",
            ],
            env=env,
        )

        packages = list(feed.glob("TeeAttestationVerification.*.nupkg"))
        if len(packages) != 1:
            raise RuntimeError(f"Expected one package, found {len(packages)}")
        package = packages[0]
        expected_name = f"TeeAttestationVerification.{version}.nupkg"
        if package.name != expected_name:
            raise RuntimeError(f"Expected {expected_name}, got {package.name}")
        verify_package(package, temp / "libtee_attestation_verification_ffi.so")

        common_properties = [
            f"-p:TavPackageVersion={version}",
        ]
        run(
            [
                "dotnet",
                "restore",
                str(TEST_PROJECT),
                "--source",
                str(feed),
                "--source",
                "https://api.nuget.org/v3/index.json",
                *common_properties,
            ],
            env=env,
        )
        run(
            [
                "dotnet",
                "test",
                str(TEST_PROJECT),
                "--configuration",
                configuration,
                "--no-restore",
                *common_properties,
            ],
            env=env,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pack TeeAttestationVerification and run its public consumer tests"
    )
    parser.add_argument("--configuration", default="Release")
    args = parser.parse_args()

    with LOCK_FILE.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run_tests(args.configuration)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
