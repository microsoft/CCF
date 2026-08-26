#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import difflib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

COMMIT_HASH = re.compile(r"[0-9a-fA-F]{40}")
NETWORK_TIMEOUT_SECONDS = 5
MAX_GITHUB_RESPONSE_SIZE = 2 * 1024 * 1024
MAX_ARTIFACT_SIZE = 100 * 1024 * 1024
MAX_EXPANDED_SIZE = 500 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_DIFF_LINES = 40

DIRECTORY_ALIASES = {
    ("nlohmann", "json"): "nlohmann",
    ("project-everest", "everparse"): "evercbor",
    ("thelink2012", "SmallVector"): "small_vector",
    ("microsoft", "TEE-Attestation-Verification"): "tee-attestation-verification",
}


@dataclass(frozen=True)
class GitComponent:
    repository_url: str
    commit: str
    tag: str | None = None

    @property
    def identity(self) -> tuple[str, str]:
        path = PurePosixPath(urlparse(self.repository_url).path.rstrip("/"))
        return path.parent.name, path.name.removesuffix(".git")


@dataclass(frozen=True)
class GitHubAsset:
    name: str


@dataclass(frozen=True)
class VersionedArchive:
    url: str
    version_file: str
    tag_pattern: re.Pattern[str]


RELEASE_SOURCES = {
    ("CLIUtils", "CLI11"): GitHubAsset("CLI11.hpp"),
    ("bellard", "quickjs"): VersionedArchive(
        "https://bellard.org/quickjs/quickjs-{tag}.tar.xz",
        "VERSION",
        re.compile(r"(?P<version>\d{4}-\d{2}-\d{2})(?:-\d+)?"),
    ),
}

# llhttp was historically flattened from 2 upstream directories.
PREFIX_EXCEPTIONS = {
    ("nodejs", "llhttp"): {("src",), ("include",)},
}


class VerificationError(RuntimeError):
    pass


def git(repository: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            env=environment,
            timeout=NETWORK_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise VerificationError("git is required but was not found") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip()
        raise VerificationError(f"git {' '.join(arguments)} failed: {detail}") from exc
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(
            f"git {' '.join(arguments)} exceeded {NETWORK_TIMEOUT_SECONDS} seconds"
        ) from exc
    return result.stdout


def checkout(
    component: GitComponent, destination: Path, tag: str | None = None
) -> None:
    if COMMIT_HASH.fullmatch(component.commit) is None:
        raise VerificationError(
            f"Invalid commit for {component.repository_url}: {component.commit}"
        )
    if component.repository_url.startswith("-"):
        raise VerificationError("Repository URL must not begin with '-'")

    reference = component.commit if tag is None else f"refs/tags/{tag}"
    git(destination, "init", "--quiet")
    if tag is not None:
        git(destination, "check-ref-format", reference)
    git(
        destination,
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=1",
        component.repository_url,
        reference,
    )
    actual_commit = (
        git(destination, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
        .decode()
        .strip()
    )
    if actual_commit != component.commit:
        raise VerificationError(
            f"{reference} resolves to {actual_commit}, "
            f"but the manifest claims {component.commit}"
        )
    git(destination, "checkout", "--quiet", "--detach", "FETCH_HEAD")


def download(
    url: str, maximum_size: int, headers: dict[str, str] | None = None
) -> bytes:
    if urlparse(url).scheme != "https":
        raise VerificationError(f"Download URL must use HTTPS: {url}")
    try:
        with urlopen(
            Request(url, headers=headers or {}),
            timeout=NETWORK_TIMEOUT_SECONDS,
        ) as response:
            content = response.read(maximum_size + 1)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise VerificationError(f"Failed to download {url}: {exc}") from exc
    if len(content) > maximum_size:
        raise VerificationError(f"Download from {url} exceeded {maximum_size} bytes")
    return content


def extract_archive(content: bytes, destination: Path) -> None:
    expanded_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_ARCHIVE_ENTRIES:
                    raise VerificationError("Release archive contains too many entries")

                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise VerificationError(f"Unsafe archive path: {member.name}")
                if not member.isfile() and not member.isdir():
                    continue

                expanded_size += member.size
                if expanded_size > MAX_EXPANDED_SIZE:
                    raise VerificationError("Expanded release archive is too large")
                archive.extract(member, destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise VerificationError(f"Failed to extract release archive: {exc}") from exc


def github_asset(component: GitComponent, asset_name: str) -> tuple[str, bytes]:
    owner, repository = component.identity
    parsed_url = urlparse(component.repository_url)
    if parsed_url.scheme != "https" or parsed_url.hostname != "github.com":
        raise VerificationError("GitHub release source requires a github.com URL")
    if component.tag is None:
        raise VerificationError("GitHub release source requires a manifest tag")

    api_url = (
        f"https://api.github.com/repos/{owner}/{repository}/"
        f"releases/tags/{component.tag}"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        release = json.loads(
            download(api_url, MAX_GITHUB_RESPONSE_SIZE, headers).decode()
        )
        assets = release["assets"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("Invalid GitHub release response") from exc
    if release.get("tag_name") != component.tag or not isinstance(assets, list):
        raise VerificationError("GitHub release response has unexpected metadata")

    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == asset_name
    ]
    if len(matches) != 1 or not isinstance(
        asset_url := matches[0].get("browser_download_url"), str
    ):
        raise VerificationError(
            f"GitHub release {component.tag} does not have one {asset_name} asset"
        )
    return asset_url, download(asset_url, MAX_ARTIFACT_SIZE)


def files(directory: Path, *, vendored: bool = False) -> list[Path]:
    if not directory.is_dir():
        raise VerificationError(f"Directory does not exist: {directory}")

    regular_files = []
    unsupported = []
    for root, directories, names in os.walk(directory):
        root_path = Path(root)
        if root_path == directory and ".git" in directories:
            directories.remove(".git")
        for name in directories[:]:
            path = root_path / name
            if path.is_symlink():
                directories.remove(name)
                if vendored:
                    unsupported.append(path)
        for name in names:
            path = root_path / name
            if stat.S_ISREG(path.lstat().st_mode):
                regular_files.append(path)
            elif vendored:
                unsupported.append(path)

    if unsupported:
        paths = ", ".join(str(path.relative_to(directory)) for path in unsupported)
        raise VerificationError(f"Vendored directory has non-regular entries: {paths}")
    if vendored and not regular_files:
        raise VerificationError(f"Vendored directory contains no files: {directory}")
    return sorted(
        regular_files, key=lambda path: os.fsencode(path.relative_to(directory))
    )


def prefix_for(upstream_path: Path, vendored_path: Path) -> tuple[str, ...] | None:
    upstream_parts = upstream_path.parts
    vendored_parts = vendored_path.parts
    if (
        len(upstream_parts) < len(vendored_parts)
        or upstream_parts[-len(vendored_parts) :] != vendored_parts
    ):
        return None
    return upstream_parts[: -len(vendored_parts)]


def content_diff(
    upstream_path: Path,
    vendored_path: Path,
    upstream_bytes: bytes,
    vendored_bytes: bytes,
) -> str:
    try:
        upstream_text = upstream_bytes.decode("utf-8")
        vendored_text = vendored_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return (
            f"    binary files differ ({len(upstream_bytes)} vs "
            f"{len(vendored_bytes)} bytes)"
        )

    # keepends=True so a missing/extra trailing newline shows up as a diff,
    # rather than being silently dropped by line splitting.
    diff = difflib.unified_diff(
        upstream_text.splitlines(keepends=True),
        vendored_text.splitlines(keepends=True),
        fromfile=f"upstream/{upstream_path}",
        tofile=f"vendored/{vendored_path}",
    )

    lines = []
    for line in diff:
        lines.append(line.rstrip("\n"))
        if line[:1] in " +-" and not line.endswith("\n"):
            lines.append(r"\ No newline at end of file")
    if not lines:
        return "    (no textual difference; files differ only in encoding)"

    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES]
        lines.append(f"... diff truncated after {MAX_DIFF_LINES} lines")
    return "\n".join(f"    {line}" for line in lines)


def verify_tree(
    vendored_directory: Path,
    upstream_directory: Path,
    allowed_prefixes: set[tuple[str, ...]] | None = None,
) -> int:
    vendored_files = files(vendored_directory, vendored=True)
    upstream_by_name: dict[str, list[Path]] = {}
    for path in files(upstream_directory):
        upstream_by_name.setdefault(path.name, []).append(path)

    failures = []
    prefixes_by_file = []
    for vendored_file in vendored_files:
        relative_path = vendored_file.relative_to(vendored_directory)
        candidates = upstream_by_name.get(vendored_file.name, [])
        vendored_content = vendored_file.read_bytes()
        matching = [
            candidate
            for candidate in candidates
            if candidate.read_bytes() == vendored_content
        ]
        if not matching:
            if not candidates:
                failures.append(f"{relative_path}: not found upstream")
            else:
                closest = candidates[0]
                diff = content_diff(
                    closest.relative_to(upstream_directory),
                    relative_path,
                    closest.read_bytes(),
                    vendored_content,
                )
                note = (
                    f" (showing diff against 1 of {len(candidates)} candidates)"
                    if len(candidates) > 1
                    else ""
                )
                failures.append(f"{relative_path}: different contents{note}\n{diff}")
            continue

        prefixes = {
            prefix
            for candidate in matching
            if (
                prefix := prefix_for(
                    candidate.relative_to(upstream_directory), relative_path
                )
            )
            is not None
        }
        if not prefixes:
            failures.append(f"{relative_path}: upstream path cannot produce local path")
            continue
        prefixes_by_file.append((relative_path, prefixes))

    if failures:
        raise VerificationError("\n".join(failures))

    if set.intersection(*(prefixes for _, prefixes in prefixes_by_file)):
        return len(vendored_files)
    if allowed_prefixes and all(
        prefixes & allowed_prefixes for _, prefixes in prefixes_by_file
    ):
        return len(vendored_files)

    details = "\n".join(
        f"{path}: {', '.join('/'.join(prefix) or '.' for prefix in prefixes)}"
        for path, prefixes in prefixes_by_file
    )
    raise VerificationError(f"Files use different upstream roots:\n{details}")


def materialize_source(component: GitComponent, destination: Path) -> tuple[Path, str]:
    destination.mkdir()
    override = RELEASE_SOURCES.get(component.identity)
    if override is None:
        source = destination / "source"
        source.mkdir()
        checkout(component, source)
        return source, component.repository_url
    if component.tag is None:
        raise VerificationError("Release source requires a manifest tag")

    repository = destination / "repository"
    repository.mkdir()
    if isinstance(override, GitHubAsset):
        checkout(component, repository, component.tag)
        asset_url, content = github_asset(component, override.name)
        source = destination / "source"
        source.mkdir()
        (source / override.name).write_bytes(content)
        return source, asset_url

    match = override.tag_pattern.fullmatch(component.tag)
    if match is None:
        raise VerificationError(f"Invalid release tag: {component.tag}")
    expected_version = match.group("version")
    checkout(component, repository)
    try:
        commit_version = (repository / override.version_file).read_text().strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise VerificationError("Cannot read version from claimed commit") from exc
    if commit_version != expected_version:
        raise VerificationError(
            f"Commit version is {commit_version}, expected {expected_version}"
        )

    artifact_url = override.url.format(tag=component.tag)
    source = destination / "source"
    source.mkdir()
    extract_archive(download(artifact_url, MAX_ARTIFACT_SIZE), source)
    version_files = [
        path for path in files(source) if path.name == override.version_file
    ]
    if len(version_files) != 1:
        raise VerificationError("Release archive does not contain one version file")
    try:
        release_version = version_files[0].read_text().strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise VerificationError("Cannot read version from release archive") from exc
    if release_version != expected_version:
        raise VerificationError(
            f"Release version is {release_version}, expected {expected_version}"
        )
    return source, artifact_url


def load_manifest(path: Path) -> list[GitComponent]:
    try:
        registrations = json.loads(path.read_text())["Registrations"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"Invalid manifest {path}") from exc

    components = []
    for index, registration in enumerate(registrations):
        try:
            component = registration["component"]
            if component["type"] != "git":
                continue
            git_component = component["git"]
            repository_url = git_component["repositoryUrl"]
            commit = git_component["commitHash"]
            tag = git_component.get("tag")
        except (KeyError, TypeError) as exc:
            raise VerificationError(f"Invalid Git registration {index}") from exc
        if (
            not isinstance(repository_url, str)
            or not isinstance(commit, str)
            or (tag is not None and not isinstance(tag, str))
        ):
            raise VerificationError(f"Invalid Git registration {index}")
        components.append(GitComponent(repository_url, commit, tag))
    if not components:
        raise VerificationError("Manifest has no Git registrations")
    return components


def dependency_directory(manifest: Path, component: GitComponent) -> Path:
    expected_name = DIRECTORY_ALIASES.get(component.identity, component.identity[1])
    matches = [
        path
        for path in (manifest.parent / "3rdparty").glob("*/*")
        if path.is_dir() and path.name == expected_name
    ]
    if len(matches) != 1:
        raise VerificationError(
            f"Expected one 3rdparty directory named {expected_name}, found {len(matches)}"
        )
    return matches[0]


def select_components(
    components: list[GitComponent], repository: str | None
) -> list[GitComponent]:
    if repository is None:
        return components
    matches = [
        component
        for component in components
        if repository in {component.identity[1], "/".join(component.identity)}
    ]
    if len(matches) != 1:
        raise VerificationError(
            f"Expected one manifest repository named {repository}, found {len(matches)}"
        )
    return matches


def verify_manifest(
    manifest: Path, repository: str | None = None, *, strict: bool = False
) -> tuple[int, int]:
    components = select_components(load_manifest(manifest), repository)
    failures = []
    total_files = 0
    with tempfile.TemporaryDirectory(prefix="ccf-vendored-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        for index, component in enumerate(components):
            try:
                source, source_name = materialize_source(
                    component, temporary_root / str(index)
                )
                allowed_prefixes = (
                    None if strict else PREFIX_EXCEPTIONS.get(component.identity)
                )
                count = verify_tree(
                    dependency_directory(manifest, component),
                    source,
                    allowed_prefixes,
                )
                total_files += count
                print(
                    f"Verified {count} files from {source_name} "
                    f"at {component.commit}"
                )
            except VerificationError as exc:
                failures.append(f"{component.repository_url}: {exc}")

    if failures:
        raise VerificationError("\n\n".join(failures))
    return len(components), total_files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify vendored dependencies listed in a cgmanifest."
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("repository", nargs="?")
    args = parser.parse_args()

    try:
        dependency_count, file_count = verify_manifest(
            args.manifest, args.repository, strict=args.strict
        )
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Verified {dependency_count} dependencies ({file_count} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
