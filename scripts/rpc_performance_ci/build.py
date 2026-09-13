# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Build only Basic and its dependencies, before starting any measurements."""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

from common import (
    BUILD_OPTIONS,
    DRIVER,
    HERE,
    REVISIONS,
    ROOT,
    SOURCES,
    VARIANTS,
    VENV,
    assert_clean,
    binary_path,
    client_fingerprint,
    git,
    sha256,
    write_json,
)


def logged(name, command, cwd):
    print(f"{name}: {' '.join(map(str, command))}", flush=True)
    path = ROOT / "build-logs" / f"{name}.log"
    with path.open("w", encoding="utf-8") as output:
        subprocess.run(
            list(map(str, command)),
            cwd=cwd,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=True,
        )


def read_cache(path):
    entries = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith(("//", "#")):
            continue
        name, value = line.split("=", 1)
        entries[name.split(":", 1)[0]] = value
    return entries


def compiler_settings(cache):
    names = {
        *BUILD_OPTIONS,
        "CMAKE_C_COMPILER",
        "CMAKE_CXX_COMPILER",
        "CMAKE_LINKER",
        "CMAKE_AR",
        "CMAKE_RANLIB",
    }
    names.update(
        name
        for name in cache
        if name.startswith(
            ("CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS", "CMAKE_EXE_LINKER_FLAGS")
        )
    )
    return {name: cache[name] for name in sorted(names)}


def verify_pristine_binaries(hashes):
    for variant, expected in hashes.items():
        actual = sha256(binary_path(variant))
        if actual != expected:
            raise RuntimeError(f"Pristine {variant} executable was overwritten")


def build_variant(variant, compilers, pristine_hashes):
    version, output_name, patch_name = VARIANTS[variant]
    source = SOURCES[version]
    build = source / "build"
    assert_clean(source)
    if git(source, "rev-parse", "HEAD") != REVISIONS[version]:
        raise RuntimeError(f"Incorrect source revision for {variant}")
    patch = HERE / patch_name if patch_name else None
    probe = source / "src" / "ccf_queue_probe.h"
    queue_probe = variant.endswith("_queue")
    expected_files = set()
    if patch:
        expected_files = {
            line.removeprefix("+++ b/")
            for line in patch.read_text().splitlines()
            if line.startswith("+++ b/")
        }
        git(source, "apply", "--check", str(patch))
        git(source, "apply", str(patch))
    try:
        if queue_probe:
            if probe.exists():
                raise RuntimeError(f"Refusing to replace {probe}")
            shutil.copyfile(HERE / "ccf_queue_probe.h", probe)
        changed = set(git(source, "diff", "--name-only").splitlines())
        if changed != expected_files:
            raise RuntimeError(f"Unexpected changes for {variant}: {changed}")
        git(source, "diff", "--check")
        untracked = set(
            git(source, "ls-files", "--others", "--exclude-standard").splitlines()
        )
        if untracked != ({"src/ccf_queue_probe.h"} if queue_probe else set()):
            raise RuntimeError(f"Unexpected untracked source files: {untracked}")
        diff = git(source, "diff", "--no-ext-diff", "--binary")
        changed_hashes = {
            name: sha256(source / name) for name in sorted(changed | untracked)
        }
        if variant in ("pr_cached", "pr_read_ahead"):
            for name in (
                "src/enclave/session.h",
                "src/enclave/http_session.h",
                "src/host/tls/openssl_server.h",
            ):
                if "ccf::queue_probe" in (source / name).read_text():
                    raise RuntimeError(
                        "Queue instrumentation leaked into counterfactual"
                    )
        command = [
            "cmake",
            "-S",
            str(source),
            "-B",
            str(build),
            "-GNinja",
            *(f"-D{name}={value}" for name, value in BUILD_OPTIONS.items()),
            *(f"-DCMAKE_{name}_COMPILER={path}" for name, path in compilers.items()),
            "-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="
            + (str(HERE / "output_name.cmake") if patch else ""),
        ]
        if patch:
            command.append(f"-DCCF_DIAGNOSTIC_OUTPUT_NAME={output_name}")
        logged(f"{variant}-configure", command, source)
        logged(
            f"{variant}-build",
            ["cmake", "--build", build, "--target", "basic", "--parallel", "8"],
            source,
        )
        cache = read_cache(build / "CMakeCache.txt")
        for name, expected in BUILD_OPTIONS.items():
            if cache[name] != expected:
                raise RuntimeError(f"Unexpected {name}: {cache[name]}")
        binary = binary_path(variant)
        fingerprint = {
            "variant": variant,
            "revision": git(source, "rev-parse", "HEAD"),
            "tree": git(source, "rev-parse", "HEAD^{tree}"),
            "describe": git(source, "describe", "--tags", "--match=ccf-*"),
            "source_diff": diff,
            "source_diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest(),
            "changed_file_sha256": changed_hashes,
            "patch": patch_name,
            "patch_sha256": sha256(patch) if patch else None,
            "probe_header_sha256": sha256(probe) if queue_probe else None,
            "cmake_injection_sha256": (
                sha256(HERE / "output_name.cmake") if patch else None
            ),
            "configure_command": command,
            "compiler_settings": compiler_settings(cache),
            "cmake_cache": cache,
            "basic_dependency_commands": subprocess.check_output(
                ["ninja", "-C", str(build), "-t", "commands", "basic"], text=True
            ).splitlines(),
            "binary": str(binary),
            "binary_sha256": sha256(binary),
            "binary_bytes": binary.stat().st_size,
            "linked_libraries": subprocess.check_output(
                ["ldd", str(binary)], text=True
            ),
            "build_finished_at": time.time(),
        }
        for name, expected in changed_hashes.items():
            if sha256(source / name) != expected:
                raise RuntimeError(f"Source changed during build: {name}")
        if git(source, "diff", "--no-ext-diff", "--binary") != diff:
            raise RuntimeError("Tracked source changed during build")
        if not patch:
            pristine_hashes[variant] = fingerprint["binary_sha256"]
        verify_pristine_binaries(pristine_hashes)
        write_json(ROOT / "fingerprints" / f"{variant}.json", fingerprint)
        return fingerprint
    finally:
        if queue_probe and probe.exists():
            if sha256(probe) != sha256(HERE / "ccf_queue_probe.h"):
                raise RuntimeError("Refusing to remove a changed probe header")
            probe.unlink()
        if patch:
            git(source, "apply", "--reverse", "--check", str(patch))
            git(source, "apply", "--reverse", str(patch))
        assert_clean(source)


def main():
    ROOT.mkdir(parents=True, exist_ok=False)
    (ROOT / "build-logs").mkdir()
    (ROOT / "sources").mkdir()
    state = {"status": "building", "started_at": time.time()}
    write_json(ROOT / "build-state.json", state)
    try:
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
        git(
            workspace, "merge-base", "--is-ancestor", REVISIONS["base"], REVISIONS["pr"]
        )
        for name, revision in REVISIONS.items():
            git(workspace, "worktree", "add", "--detach", str(SOURCES[name]), revision)
        compilers = {"C": shutil.which("clang"), "CXX": shutil.which("clang++")}
        if not all(compilers.values()):
            raise RuntimeError(f"Required Clang compilers are missing: {compilers}")
        toolchain = {}
        for name in ("clang", "clang++", "cmake", "ninja", "rustc", "ld"):
            path = Path(shutil.which(name))
            toolchain[name] = {
                "path": str(path),
                "sha256": sha256(path),
                "version": subprocess.check_output([str(path), "--version"], text=True),
            }
        manifest = {
            "diagnostic_revision": git(workspace, "rev-parse", "HEAD"),
            "diagnostic_ref": os.environ["GITHUB_REF"],
            "run_id": os.environ["GITHUB_RUN_ID"],
            "revisions": REVISIONS,
            "toolchain": toolchain,
            "build_options": BUILD_OPTIONS,
            "packages": subprocess.check_output(["rpm", "-qa"], text=True).splitlines(),
            "platform": platform.uname()._asdict(),
            "os_release": Path("/etc/os-release").read_text(),
            "cpuinfo": Path("/proc/cpuinfo").read_text(),
            "meminfo": Path("/proc/meminfo").read_text(),
            "affinity": sorted(os.sched_getaffinity(0)),
            "driver": str(DRIVER),
            "variants": {},
        }
        write_json(ROOT / "build-manifest.json", manifest)
        pristine_hashes = {}
        for variant in VARIANTS:
            state["active_variant"] = variant
            write_json(ROOT / "build-state.json", state)
            fingerprint = build_variant(variant, compilers, pristine_hashes)
            if manifest["variants"]:
                first = next(iter(manifest["variants"].values()))
                if fingerprint["compiler_settings"] != first["compiler_settings"]:
                    raise RuntimeError(f"Compiler/flag mismatch in {variant}")
            manifest["variants"][variant] = fingerprint
            write_json(ROOT / "build-manifest.json", manifest)
        logged("shared-python-setup", ["bash", "tests.sh", "-N"], VENV.parent)
        metadata = subprocess.check_output(
            [
                str(VENV / "bin" / "python"),
                "-c",
                (
                    "import ccf, importlib.metadata as m, json, sys; "
                    "print(json.dumps({'prefix': sys.prefix, 'version': sys.version, "
                    "'sdk_paths': list(ccf.__path__), "
                    "'packages': {d.metadata['Name']: d.version for d in m.distributions()}}))"
                ),
            ],
            text=True,
        )
        manifest["shared_python"] = json.loads(metadata)
        if Path(manifest["shared_python"]["prefix"]).resolve() != VENV.resolve():
            raise RuntimeError("The shared Python environment was not used")
        for path in manifest["shared_python"]["sdk_paths"]:
            if not Path(path).resolve().is_relative_to(SOURCES["base"] / "python"):
                raise RuntimeError(f"SDK did not come from baseline: {path}")
        manifest["shared_client"] = client_fingerprint()
        manifest["shared_driver_sha256"] = sha256(DRIVER)
        verify_pristine_binaries(pristine_hashes)
        for source in SOURCES.values():
            assert_clean(source)
        manifest["all_builds_finished_at"] = time.time()
        manifest["pristine_binaries_preserved"] = pristine_hashes
        write_json(ROOT / "build-manifest.json", manifest)
        state["status"] = "complete"
        state["finished_at"] = time.time()
        print(
            "All six builds finished; pristine executables are unchanged.", flush=True
        )
    except BaseException as error:
        state.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        write_json(ROOT / "build-state.json", state)


if __name__ == "__main__":
    main()
