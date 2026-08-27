#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "verify-vendored-dependency.py"
SPEC = importlib.util.spec_from_file_location("verify_vendored_dependency", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)


def run(command: list[str], directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )


class VerifyVendoredDependencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def create_repository(
        self,
        relative_path: str,
        repository_files: dict[str, bytes],
        tag: str | None = None,
    ) -> tuple[Path, str]:
        repository = self.root / "remotes" / relative_path
        repository.mkdir(parents=True)
        run(["git", "init", "--quiet"], repository)
        run(["git", "config", "user.email", "test@example.com"], repository)
        run(["git", "config", "user.name", "Test User"], repository)
        for relative_file, content in repository_files.items():
            path = repository / relative_file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        run(["git", "add", "."], repository)
        run(["git", "commit", "--quiet", "-m", "Initial commit"], repository)
        commit = run(["git", "rev-parse", "HEAD"], repository).stdout.strip()
        if tag is not None:
            run(["git", "tag", tag], repository)
        return repository, commit

    def create_tree(self, name: str, tree_files: dict[str, bytes]) -> Path:
        directory = self.root / name
        for relative_file, content in tree_files.items():
            path = directory / relative_file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return directory

    def write_manifest(
        self,
        components: list[tuple[Path, str, str | None]],
        vendored_files: dict[str, bytes],
    ) -> Path:
        checkout = self.root / "checkout"
        for relative_file, content in vendored_files.items():
            path = checkout / "3rdparty" / relative_file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        registrations = []
        for repository, commit, tag in components:
            git_component = {
                "repositoryUrl": repository.as_uri(),
                "commitHash": commit,
            }
            if tag is not None:
                git_component["tag"] = tag
            registrations.append({"component": {"type": "git", "git": git_component}})
        manifest = checkout / "cgmanifest.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"Registrations": registrations}))
        return manifest

    def test_accepts_one_common_source_root(self) -> None:
        upstream = self.create_tree(
            "upstream",
            {
                "include/foo.h": b"foo\n",
                "include/bar.h": b"bar\n",
                "docs/README.md": b"omitted\n",
            },
        )
        unchanged = self.create_tree(
            "unchanged",
            {"include/foo.h": b"foo\n", "include/bar.h": b"bar\n"},
        )
        stripped = self.create_tree("stripped", {"foo.h": b"foo\n", "bar.h": b"bar\n"})

        self.assertEqual(VERIFIER.verify_tree(unchanged, upstream), 2)
        self.assertEqual(VERIFIER.verify_tree(stripped, upstream), 2)

    def test_rejects_inconsistent_or_invented_rebasing(self) -> None:
        upstream = self.create_tree(
            "upstream",
            {"include/foo.h": b"foo\n", "include/bar.h": b"bar\n"},
        )
        mixed = self.create_tree(
            "mixed", {"include/foo.h": b"foo\n", "bar.h": b"bar\n"}
        )
        invented = self.create_tree(
            "invented", {"src/foo.h": b"foo\n", "src/bar.h": b"bar\n"}
        )

        with self.assertRaisesRegex(VERIFIER.VerificationError, "different upstream"):
            VERIFIER.verify_tree(mixed, upstream)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "cannot produce local path"
        ):
            VERIFIER.verify_tree(invented, upstream)

    def test_rejects_symlinked_vendored_directory(self) -> None:
        upstream = self.create_tree("upstream", {"foo.h": b"foo\n"})
        real_directory = self.create_tree("real-vendored", {"foo.h": b"foo\n"})
        symlinked_vendored = self.root / "symlinked-vendored"
        symlinked_vendored.symlink_to(real_directory, target_is_directory=True)

        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be a symlink"
        ):
            VERIFIER.verify_tree(symlinked_vendored, upstream)

    def test_download_refuses_to_follow_redirect_off_https(self) -> None:
        handler = VERIFIER.HTTPSOnlyRedirectHandler()
        request = VERIFIER.Request("https://example.com/dependency.h")

        with self.assertRaisesRegex(VERIFIER.URLError, "non-HTTPS"):
            handler.redirect_request(
                request, None, 302, "Found", {}, "http://example.com/dependency.h"
            )

        # A same-scheme redirect is still delegated to the base handler.
        redirected = handler.redirect_request(
            request, None, 302, "Found", {}, "https://example.com/moved.h"
        )
        self.assertEqual(redirected.full_url, "https://example.com/moved.h")

        with mock.patch.object(
            VERIFIER._HTTPS_ONLY_OPENER,
            "open",
            side_effect=VERIFIER.URLError("redirected off HTTPS"),
        ), self.assertRaisesRegex(VERIFIER.VerificationError, "Failed to download"):
            VERIFIER.download("https://example.com/dependency.h", 1024)

    def test_rejects_missing_or_modified_files(self) -> None:
        upstream = self.create_tree("upstream", {"include/foo.h": b"foo\n"})
        vendored = self.create_tree(
            "vendored", {"foo.h": b"modified\n", "missing.h": b"missing\n"}
        )

        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "different contents"
        ) as context:
            VERIFIER.verify_tree(vendored, upstream)

        message = str(context.exception)
        self.assertIn("-foo", message)
        self.assertIn("+modified", message)
        self.assertIn("not found upstream", message)

    def test_diff_shows_missing_trailing_newline(self) -> None:
        upstream = self.create_tree("upstream", {"include/foo.h": b"foo\n"})
        vendored = self.create_tree("vendored", {"foo.h": b"foo"})

        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "No newline at end of file"
        ):
            VERIFIER.verify_tree(vendored, upstream)

    def test_diff_reports_binary_files_without_decoding(self) -> None:
        upstream = self.create_tree("upstream", {"include/foo.bin": b"\x00\x01\xff"})
        vendored = self.create_tree("vendored", {"foo.bin": b"\x00\x02\xff"})

        with self.assertRaisesRegex(
            VERIFIER.VerificationError, r"binary files differ \(3 vs 3 bytes\)"
        ):
            VERIFIER.verify_tree(vendored, upstream)

    def test_declared_prefix_exception_is_optional(self) -> None:
        upstream = self.create_tree(
            "upstream",
            {"src/foo.h": b"foo\n", "include/bar.h": b"bar\n"},
        )
        vendored = self.create_tree("vendored", {"foo.h": b"foo\n", "bar.h": b"bar\n"})
        prefixes = {("src",), ("include",)}

        self.assertEqual(VERIFIER.verify_tree(vendored, upstream, prefixes), 2)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "different upstream"):
            VERIFIER.verify_tree(vendored, upstream)

    def test_manifest_and_optional_repository_mode(self) -> None:
        first, first_commit = self.create_repository(
            "owner/first", {"include/first.h": b"first\n"}
        )
        second, second_commit = self.create_repository(
            "owner/second", {"src/second.h": b"second\n"}
        )
        manifest = self.write_manifest(
            [(first, first_commit, None), (second, second_commit, None)],
            {
                "internal/first/first.h": b"first\n",
                "internal/second/second.h": b"second\n",
            },
        )

        all_result = subprocess.run(
            [sys.executable, str(SCRIPT), str(manifest)],
            check=False,
            capture_output=True,
            text=True,
        )
        one_result = subprocess.run(
            [sys.executable, str(SCRIPT), str(manifest), "first"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(all_result.returncode, 0, all_result.stderr)
        self.assertIn("Verified 2 dependencies", all_result.stdout)
        self.assertEqual(one_result.returncode, 0, one_result.stderr)
        self.assertIn("Verified 1 dependencies", one_result.stdout)

    def test_directory_aliases_are_explicit(self) -> None:
        checkout = self.root / "aliases"
        nlohmann = checkout / "3rdparty/exported/nlohmann"
        nlohmann.mkdir(parents=True)
        manifest = checkout / "cgmanifest.json"
        component = VERIFIER.GitComponent(
            "https://github.com/nlohmann/json.git", "0" * 40
        )

        self.assertEqual(VERIFIER.dependency_directory(manifest, component), nlohmann)

        unlisted = VERIFIER.GitComponent(
            "https://github.com/owner/json-library", "0" * 40
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "json-library"):
            VERIFIER.dependency_directory(manifest, unlisted)

    def test_dependency_directory_rejects_symlink_escape(self) -> None:
        checkout = self.root / "escape"
        (checkout / "3rdparty").mkdir(parents=True)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "json").mkdir()
        (checkout / "3rdparty" / "exported").symlink_to(
            outside, target_is_directory=True
        )
        manifest = checkout / "cgmanifest.json"
        component = VERIFIER.GitComponent(
            "https://github.com/nlohmann/json.git", "0" * 40
        )

        with self.assertRaisesRegex(VERIFIER.VerificationError, "Expected one"):
            VERIFIER.dependency_directory(manifest, component)

    def test_dependency_directory_rejects_symlinked_3rdparty_root(self) -> None:
        checkout = self.root / "escape-root"
        checkout.mkdir(parents=True)
        outside = self.root / "outside-root"
        (outside / "exported" / "json").mkdir(parents=True)
        (checkout / "3rdparty").symlink_to(outside, target_is_directory=True)
        manifest = checkout / "cgmanifest.json"
        component = VERIFIER.GitComponent(
            "https://github.com/nlohmann/json.git", "0" * 40
        )

        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be a symlink"
        ):
            VERIFIER.dependency_directory(manifest, component)

    def test_git_tag_must_resolve_to_manifest_commit(self) -> None:
        repository, commit = self.create_repository(
            "owner/dependency", {"dependency.h": b"dependency\n"}, "v1.0.0"
        )
        valid = VERIFIER.GitComponent(repository.as_uri(), commit, "v1.0.0")
        valid_checkout = self.root / "valid-checkout"
        valid_checkout.mkdir()
        VERIFIER.checkout(valid, valid_checkout, valid.tag)

        invalid = VERIFIER.GitComponent(repository.as_uri(), "0" * 40, "v1.0.0")
        invalid_checkout = self.root / "invalid-checkout"
        invalid_checkout.mkdir()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "manifest claims"):
            VERIFIER.checkout(invalid, invalid_checkout, invalid.tag)

    def test_github_asset_is_selected_from_manifest_tag(self) -> None:
        component = VERIFIER.GitComponent(
            "https://github.com/owner/dependency", "0" * 40, "v1.0.0"
        )
        asset_url = (
            "https://github.com/owner/dependency/releases/download/"
            "v1.0.0/dependency.h"
        )
        release = json.dumps(
            {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "name": "dependency.h",
                        "browser_download_url": asset_url,
                    }
                ],
            }
        ).encode()

        with mock.patch.object(
            VERIFIER, "download", side_effect=[release, b"dependency\n"]
        ):
            selected_url, content = VERIFIER.github_asset(component, "dependency.h")

        self.assertEqual(selected_url, asset_url)
        self.assertEqual(content, b"dependency\n")

    def test_versioned_archive_checks_commit_and_archive_version(self) -> None:
        repository, commit = self.create_repository(
            "bellard/quickjs",
            {"VERSION": b"1.0.0\n", "src/dependency.h": b"dependency\n"},
        )
        component = VERIFIER.GitComponent(repository.as_uri(), commit, "1.0.0-2")
        override = VERIFIER.VersionedArchive(
            "https://example.com/dependency-{tag}.tar.xz",
            "VERSION",
            VERIFIER.re.compile(r"(?P<version>\d+\.\d+\.\d+)(?:-\d+)?"),
        )
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:xz") as archive:
            for name, content in {
                "dependency-1.0.0/VERSION": b"1.0.0\n",
                "dependency-1.0.0/src/dependency.h": b"dependency\n",
            }.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))

        work = self.root / "release-work"
        with mock.patch.dict(
            VERIFIER.RELEASE_SOURCES, {component.identity: override}
        ), mock.patch.object(
            VERIFIER, "download", return_value=archive_buffer.getvalue()
        ):
            source, artifact_url = VERIFIER.materialize_source(component, work)

        self.assertEqual(artifact_url, "https://example.com/dependency-1.0.0-2.tar.xz")
        self.assertEqual((source / "dependency-1.0.0/VERSION").read_text(), "1.0.0\n")

    def test_archive_rejects_unsafe_paths(self) -> None:
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:xz") as archive:
            member = tarfile.TarInfo("../escape")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))

        with self.assertRaisesRegex(VERIFIER.VerificationError, "Unsafe"):
            VERIFIER.extract_archive(archive_buffer.getvalue(), self.root / "output")


if __name__ == "__main__":
    unittest.main()
