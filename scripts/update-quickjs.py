#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
from dataclasses import dataclass
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ElementTree

QUICKJS_HOME = "https://bellard.org/quickjs/"
QUICKJS_REPOSITORY = "https://github.com/bellard/quickjs"
QUICKJS_COMMITS_FEED = "https://github.com/bellard/quickjs/commits/master/VERSION.atom"
QUICKJS_COMMIT_ARCHIVE = "https://codeload.github.com/bellard/quickjs/tar.gz/{commit}"
QUICKJS_RAW_VERSION = (
    "https://raw.githubusercontent.com/bellard/quickjs/{commit}/VERSION"
)
QUICKJS_DIRECTORY = Path("3rdparty/exported/quickjs")
CGMANIFEST = Path("cgmanifest.json")
CHANGELOG = Path("CHANGELOG.md")

MAX_PAGE_SIZE = 2 * 1024 * 1024
MAX_ARCHIVE_SIZE = 100 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 60
USER_AGENT = "CCF-QuickJS-Updater"

RELEASE_ARCHIVE = re.compile(
    r"^quickjs-(?P<version>\d{4}-\d{2}-\d{2})(?:-(?P<revision>\d+))?\.tar\.xz$"
)
VERSION = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")

# These directories contain upstream documentation, examples, and tests which
# are not consumed by CCF and are intentionally not vendored.
EXCLUDED_DIRECTORIES = frozenset({"doc", "examples", "tests"})
REQUIRED_FILES = frozenset(
    {
        "Changelog",
        "LICENSE",
        "VERSION",
        "cutils.c",
        "cutils.h",
        "dtoa.c",
        "dtoa.h",
        "libregexp-opcode.h",
        "libregexp.c",
        "libregexp.h",
        "libunicode-table.h",
        "libunicode.c",
        "libunicode.h",
        "quickjs-atom.h",
        "quickjs-opcode.h",
        "quickjs.c",
        "quickjs.h",
    }
)


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class Release:
    version: str
    revision: int
    url: str


class ReleasePageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.releases: list[Release] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return

        href = dict(attrs).get("href")
        if href is None:
            return

        archive_name = PurePosixPath(urlparse(href).path).name
        match = RELEASE_ARCHIVE.fullmatch(archive_name)
        if match is None:
            return

        release_url = urljoin(QUICKJS_HOME, href)
        parsed_url = urlparse(release_url)
        if parsed_url.scheme != "https" or parsed_url.hostname not in {
            "bellard.org",
            "www.bellard.org",
        }:
            return

        self.releases.append(
            Release(
                version=match.group("version"),
                revision=int(match.group("revision") or 0),
                url=release_url,
            )
        )


def fetch(url: str, maximum_size: int) -> bytes:
    headers = {"User-Agent": USER_AGENT}

    try:
        with urlopen(
            Request(url, headers=headers), timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            content = response.read(maximum_size + 1)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise UpdateError(f"Failed to download {url}: {exc}") from exc

    if len(content) > maximum_size:
        raise UpdateError(f"Download from {url} exceeded {maximum_size} bytes")
    return content


def find_latest_release(page: bytes) -> Release:
    parser = ReleasePageParser()
    try:
        parser.feed(page.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UpdateError("QuickJS download page is not valid UTF-8") from exc

    if not parser.releases:
        raise UpdateError("No QuickJS source releases found on the download page")

    return max(parser.releases, key=lambda release: (release.version, release.revision))


def find_release_commit(version: str) -> str:
    try:
        feed = ElementTree.fromstring(fetch(QUICKJS_COMMITS_FEED, MAX_PAGE_SIZE))
    except ElementTree.ParseError as exc:
        raise UpdateError("GitHub commits feed is not valid XML") from exc

    namespace = "{http://www.w3.org/2005/Atom}"
    for entry in feed.findall(f"{namespace}entry"):
        commit_id = entry.findtext(f"{namespace}id", default="")
        title = entry.findtext(f"{namespace}title", default="")
        sha = commit_id.rsplit("/", maxsplit=1)[-1]
        if COMMIT_SHA.fullmatch(sha) is None or "release" not in title.lower():
            continue

        try:
            commit_version = fetch(QUICKJS_RAW_VERSION.format(commit=sha), 128).decode(
                "utf-8"
            )
        except UnicodeDecodeError as exc:
            raise UpdateError(
                f"QuickJS VERSION at commit {sha} is not valid UTF-8"
            ) from exc
        if commit_version.strip() == version:
            return sha

    raise UpdateError(f"Could not find the QuickJS {version} release commit")


def extract_release(archive_path: Path, output_directory: Path, version: str) -> Path:
    expected_root = f"quickjs-{version}"
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            members = archive.getmembers()
            if not members:
                raise UpdateError("QuickJS release archive is empty")

            for member in members:
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != expected_root
                ):
                    raise UpdateError(
                        f"Unexpected path in QuickJS archive: {member.name}"
                    )
                if not member.isdir() and not member.isfile():
                    raise UpdateError(
                        f"Unsupported entry in QuickJS archive: {member.name}"
                    )

            archive.extractall(output_directory, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise UpdateError(f"Failed to extract QuickJS archive: {exc}") from exc

    release_root = output_directory / expected_root
    version_path = release_root / "VERSION"
    if not version_path.is_file() or version_path.read_text().strip() != version:
        raise UpdateError(
            f"QuickJS archive does not contain the expected VERSION ({version})"
        )

    missing_files = sorted(
        name for name in REQUIRED_FILES if not (release_root / name).is_file()
    )
    if missing_files:
        raise UpdateError(
            "QuickJS archive is missing required files: " + ", ".join(missing_files)
        )

    return release_root


def verify_release_files(release_root: Path, commit: str) -> None:
    try:
        archive = tarfile.open(
            fileobj=io.BytesIO(
                fetch(
                    QUICKJS_COMMIT_ARCHIVE.format(commit=commit),
                    MAX_ARCHIVE_SIZE,
                )
            ),
            mode="r:gz",
        )
    except (tarfile.TarError, OSError) as exc:
        raise UpdateError(f"Failed to read QuickJS commit archive: {exc}") from exc

    expected_root = f"quickjs-{commit}"
    mismatches = []
    with archive:
        for name in sorted(REQUIRED_FILES):
            try:
                member = archive.getmember(f"{expected_root}/{name}")
                upstream_file = archive.extractfile(member)
            except KeyError:
                upstream_file = None

            if (
                upstream_file is None
                or not member.isfile()
                or upstream_file.read() != (release_root / name).read_bytes()
            ):
                mismatches.append(name)

    if mismatches:
        raise UpdateError(
            "QuickJS archive files do not match release commit "
            f"{commit}: {', '.join(mismatches)}"
        )


def render_cgmanifest(current_content: str, commit: str) -> str:
    if COMMIT_SHA.fullmatch(commit) is None:
        raise UpdateError(f"Invalid QuickJS commit SHA: {commit}")

    try:
        manifest = json.loads(current_content)
    except json.JSONDecodeError as exc:
        raise UpdateError("cgmanifest.json is not valid JSON") from exc

    registrations = manifest.get("Registrations")
    if not isinstance(registrations, list):
        raise UpdateError("cgmanifest.json does not contain Registrations")

    matches = []
    for registration in registrations:
        if not isinstance(registration, dict):
            continue
        component = registration.get("component")
        if not isinstance(component, dict):
            continue
        git_component = component.get("git")
        if not isinstance(git_component, dict):
            continue
        repository_url = git_component.get("repositoryUrl")
        if (
            isinstance(repository_url, str)
            and repository_url.rstrip("/").removesuffix(".git") == QUICKJS_REPOSITORY
        ):
            matches.append(git_component)

    if len(matches) != 1:
        raise UpdateError(
            "Expected exactly one QuickJS registration in cgmanifest.json"
        )

    matches[0]["commitHash"] = commit
    return json.dumps(manifest, indent=2) + "\n"


def render_changelog(
    current_content: str,
    old_version: str,
    new_version: str,
    pr_number: int | None,
) -> str:
    if old_version == new_version:
        return current_content
    if pr_number is None:
        raise UpdateError("--pr-number is required when upgrading QuickJS")

    entry = f"- Upgraded QuickJS from {old_version} to {new_version} (#{pr_number})."
    if entry in current_content:
        return current_content

    version_headers = list(
        re.finditer(r"^## \[[^\]]+\]\s*$", current_content, flags=re.MULTILINE)
    )
    if not version_headers:
        raise UpdateError("CHANGELOG.md does not contain a release section")

    block_start = version_headers[0].start()
    block_end = (
        version_headers[1].start() if len(version_headers) > 1 else len(current_content)
    )
    block_lines = current_content[block_start:block_end].splitlines()
    while block_lines and not block_lines[-1]:
        block_lines.pop()

    dependencies_index = next(
        (index for index, line in enumerate(block_lines) if line == "### Dependencies"),
        None,
    )
    if dependencies_index is None:
        block_lines.extend(["", "### Dependencies", "", entry])
    else:
        section_end = next(
            (
                index
                for index in range(dependencies_index + 1, len(block_lines))
                if block_lines[index].startswith("### ")
            ),
            len(block_lines),
        )
        section = "\n".join(block_lines[dependencies_index:section_end]).rstrip()
        if section == "### Dependencies":
            section = f"{section}\n\n{entry}"
        else:
            section = f"{section}\n{entry}"
        block_lines[dependencies_index:section_end] = section.splitlines()

    updated_block = "\n".join(block_lines) + "\n\n"
    return current_content[:block_start] + updated_block + current_content[block_end:]


def write_file_atomically(path: Path, content: str) -> None:
    mode = path.stat().st_mode
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(content)
        os.chmod(temporary_path, mode)
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def apply_update(
    release_root: Path, quickjs_directory: Path, metadata: dict[Path, str]
) -> None:
    original_metadata = {path: path.read_text() for path in metadata}
    temporary_directory = Path(
        tempfile.mkdtemp(prefix=".quickjs-update-", dir=quickjs_directory.parent)
    )
    preserve_temporary_directory = False
    try:
        staged_directory = temporary_directory / "quickjs"
        original_directory = temporary_directory / "original"
        shutil.copytree(
            release_root,
            staged_directory,
            ignore=shutil.ignore_patterns(*EXCLUDED_DIRECTORIES),
        )

        quickjs_directory.rename(original_directory)
        try:
            staged_directory.rename(quickjs_directory)
            for path, content in metadata.items():
                write_file_atomically(path, content)
        except BaseException:
            try:
                if quickjs_directory.exists():
                    shutil.rmtree(quickjs_directory)
                original_directory.rename(quickjs_directory)
                for path, content in original_metadata.items():
                    write_file_atomically(path, content)
            except BaseException as rollback_error:
                preserve_temporary_directory = True
                raise UpdateError(
                    "QuickJS update rollback failed; the original source is "
                    f"preserved at {original_directory}"
                ) from rollback_error
            raise
    finally:
        if not preserve_temporary_directory:
            shutil.rmtree(temporary_directory)


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Replace CCF's vendored QuickJS with the latest source release and "
            "update its metadata."
        )
    )
    parser.add_argument(
        "--pr-number",
        type=positive_integer,
        help="Pull request number to cite in the release note",
    )
    args = parser.parse_args()

    repository_root = Path(__file__).resolve().parents[1]
    quickjs_directory = repository_root / QUICKJS_DIRECTORY
    cgmanifest_path = repository_root / CGMANIFEST
    changelog_path = repository_root / CHANGELOG

    version_path = quickjs_directory / "VERSION"
    if not version_path.is_file():
        raise UpdateError(f"Could not find vendored QuickJS at {quickjs_directory}")
    old_version = version_path.read_text().strip()
    if VERSION.fullmatch(old_version) is None:
        raise UpdateError(f"Invalid vendored QuickJS version: {old_version}")

    latest_release = find_latest_release(fetch(QUICKJS_HOME, MAX_PAGE_SIZE))
    if latest_release.version < old_version:
        raise UpdateError(
            "Latest published QuickJS version "
            f"({latest_release.version}) is older than the vendored version "
            f"({old_version})"
        )
    if latest_release.version != old_version and args.pr_number is None:
        parser.error("--pr-number is required when upgrading QuickJS")

    release_commit = find_release_commit(latest_release.version)
    cgmanifest = render_cgmanifest(cgmanifest_path.read_text(), release_commit)
    changelog = render_changelog(
        changelog_path.read_text(),
        old_version,
        latest_release.version,
        args.pr_number,
    )

    with tempfile.TemporaryDirectory(prefix="quickjs-download-") as temporary_directory:
        temporary_directory = Path(temporary_directory)
        archive_path = (
            temporary_directory / PurePosixPath(urlparse(latest_release.url).path).name
        )
        archive_path.write_bytes(fetch(latest_release.url, MAX_ARCHIVE_SIZE))
        release_root = extract_release(
            archive_path, temporary_directory, latest_release.version
        )
        verify_release_files(release_root, release_commit)
        apply_update(
            release_root,
            quickjs_directory,
            {
                cgmanifest_path: cgmanifest,
                changelog_path: changelog,
            },
        )

    print(
        f"Updated QuickJS from {old_version} to {latest_release.version} "
        f"({release_commit})"
    )


if __name__ == "__main__":
    try:
        main()
    except UpdateError as exc:
        raise SystemExit(f"error: {exc}") from exc
