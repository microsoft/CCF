# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import re
import os

import subprocess
import git
import urllib
import shutil
import requests
import cimetrics.env

# pylint: disable=import-error, no-name-in-module
from setuptools.extern.packaging.version import Version  # type: ignore

from loguru import logger as LOG


REPOSITORY_NAME = "microsoft/CCF"
REMOTE_URL = f"https://github.com/{REPOSITORY_NAME}"
BRANCH_RELEASE_PREFIX = "release/"
TAG_RELEASE_PREFIX = "ccf-"
TAG_LATEST_RELEASE_PREFIX = f"{TAG_RELEASE_PREFIX}latest-"
TAG_DEVELOPMENT_SUFFIX = "-dev"
TAG_RELEASE_CANDIDATE_SUFFIX = "-rc"
MAIN_BRANCH_NAME = "main"
DEBIAN_PACKAGE_EXTENSION = "_amd64.deb"
# This assumes that CCF is installed at `/opt/ccf`, which is true from 1.0.0
INSTALL_DIRECTORY_PREFIX = "ccf_install_"
INSTALL_DIRECTORY_SUB_PATH = "opt/ccf"
DOWNLOAD_FOLDER_NAME = "downloads"
INSTALL_SUCCESS_FILE = "test_github_infra_installed"
INSTALL_VERSION_FILE_PATH = "share/VERSION"

BACKPORT_BRANCH_PREFIX = "backport/"  # Automatically added by backport CLI

# Note: Releases are identified by tag since releases are not necessarily named, but all
# releases are tagged


def get_version_from_install(install_dir):
    with open(
        os.path.join(install_dir, INSTALL_VERSION_FILE_PATH), "r", encoding="utf-8"
    ) as version_file:
        return f"{TAG_RELEASE_PREFIX}{version_file.read()}"


def is_release_branch(branch_name):
    return branch_name.startswith(BRANCH_RELEASE_PREFIX)


def is_release_tag(tag_name):
    return tag_name.startswith(TAG_RELEASE_PREFIX)


def is_latest_release_tag(tag_name):
    return tag_name.startswith(TAG_LATEST_RELEASE_PREFIX)


def strip_release_branch_name(branch_name):
    assert is_release_branch(branch_name), branch_name
    return branch_name[len(BRANCH_RELEASE_PREFIX) :]


def strip_release_tag_name(tag_name):
    assert is_release_tag(tag_name)
    return tag_name[len(TAG_RELEASE_PREFIX) :]


def strip_non_final_tag_name(tag_name):
    assert is_release_tag(tag_name)
    return f'{TAG_RELEASE_PREFIX}{tag_name.rsplit("-")[1]}'


def strip_backport_prefix(branch_name):
    if branch_name.startswith(BACKPORT_BRANCH_PREFIX):
        return branch_name[len(BACKPORT_BRANCH_PREFIX) :]
    return branch_name


def get_branch_name_from_latest_release_tag_name(tag_name):
    assert is_latest_release_tag(tag_name), tag_name
    branch = tag_name[len(TAG_LATEST_RELEASE_PREFIX) :]
    return branch if branch == MAIN_BRANCH_NAME else f"{BRANCH_RELEASE_PREFIX}{branch}"


def get_major_version_from_release_branch_name(full_branch_name):
    return int(strip_release_branch_name(full_branch_name).split(".")[0])


def get_version_from_tag_name(tag_name):
    assert is_release_tag(tag_name), tag_name
    return Version(strip_release_tag_name(tag_name))


def is_dev_tag(tag_name):
    return is_release_tag(tag_name) and TAG_DEVELOPMENT_SUFFIX in tag_name


def is_release_candidate_tag(tag_name):
    return is_release_tag(tag_name) and TAG_RELEASE_CANDIDATE_SUFFIX in tag_name


def is_non_final_tag(tag_name):
    return is_dev_tag(tag_name) or is_release_candidate_tag(tag_name)


def sanitise_branch_name(branch_name):
    # Note: When checking out a specific tag, Azure DevOps does not know about the
    # branch but only the tag name so automatically convert release tags to release branch
    branch_name = strip_backport_prefix(branch_name)
    if is_dev_tag(branch_name):
        # For simplification, assume that dev tags are only released from main branch
        LOG.debug(f"Considering dev tag {branch_name} as {MAIN_BRANCH_NAME} branch")
        return MAIN_BRANCH_NAME
    elif is_release_tag(branch_name):
        if is_latest_release_tag(branch_name):
            return get_branch_name_from_latest_release_tag_name(branch_name)
        tag_major_version = get_version_from_tag_name(branch_name)
        if tag_major_version == 0:
            return MAIN_BRANCH_NAME
        equivalent_release_branch = f"{BRANCH_RELEASE_PREFIX}{tag_major_version}.x"
        LOG.debug(
            f"Considering release tag {branch_name} as {equivalent_release_branch} release branch"
        )
        return equivalent_release_branch
    return branch_name


def get_release_branch_from_branch_name(branch_name):
    # E.g. returns "release/1.x" for "release/1.0.4" or "release/1.x_test"
    assert is_release_branch(branch_name), branch_name
    return branch_name.split(".")[0] + ".x"


def get_major_version_from_branch_name(branch_name):
    # Returns major version number from branch name, or None if the branch isn't a release branch
    return (
        get_major_version_from_release_branch_name(branch_name)
        if is_release_branch(branch_name)
        else None
    )


def get_debian_package_prefix_with_platform(tag_name, platform="sgx"):
    tag_components = tag_name.split("-")
    tag_components[0] += f"_{platform}"
    return "-".join(tag_components)


def get_debian_package_url_from_tag_name(tag_name, platform="sgx"):
    if get_version_from_tag_name(tag_name) >= Version("3.0.0-rc0"):
        return f'{REMOTE_URL}/releases/download/{tag_name}/{get_debian_package_prefix_with_platform(tag_name, platform).replace("-", "_")}{DEBIAN_PACKAGE_EXTENSION}'
    else:
        return f'{REMOTE_URL}/releases/download/{tag_name}/{tag_name.replace("-", "_")}{DEBIAN_PACKAGE_EXTENSION}'


class GitEnv:
    def __init__(self):
        self.g = git.cmd.Git()
        self.tags = [
            tag.split("tags/")[-1]
            for tag in self.g.ls_remote(REMOTE_URL).split("\n")
            if f"tags/{TAG_RELEASE_PREFIX}" in tag
        ]
        self.release_branches = [
            branch.split("heads/")[-1]
            for branch in self.g.ls_remote(REMOTE_URL).split("\n")
            if "heads/release" in branch
        ]

    def has_release_for_tag_name(self, tag_name):
        return (
            requests.head(
                get_debian_package_url_from_tag_name(tag_name),
                allow_redirects=True,
                timeout=30,
            ).status_code
            == 200
        )

    @staticmethod
    def local_branch():
        # Cheeky! We reuse cimetrics env as a reliable way to retrieve the
        # current branch on any environment (either local checkout or CI run)
        return cimetrics.env.get_env().branch


class Repository:
    """
    Helper class to verify CCF operations compatibility described at
    https://microsoft.github.io/CCF/main/build_apps/release_policy.html#operations-compatibility
    """

    def __init__(self, env=None):
        self.g = env or GitEnv()
        self.tags = self.g.tags

    def _filter_released_tags(self, tags):
        # From a list of tags ordered by semver (latest first), filter out the ones
        # that don't have a release yet
        first_release_tag_idx = -1
        for i, t in enumerate(tags):
            if not self.g.has_release_for_tag_name(t):
                LOG.debug(f"No release available for tag {t}")
                first_release_tag_idx = i
            else:
                break

        return tags[first_release_tag_idx + 1 :]

    def get_latest_dev_tag(self):
        local_branch = cimetrics.env.get_env().branch
        major_version = get_major_version_from_branch_name(local_branch)
        tags = self.get_tags_for_major_version(major_version)
        # Only consider tags that have releases as a release might be in progress
        return self._filter_released_tags(tags)[0]

    def get_tags_for_major_version(self, major_version=None):
        version_re = f"{major_version}\\." if major_version else ""
        tag_re = f"^{TAG_RELEASE_PREFIX}{version_re}([.\\d+]+)(-rc.*|)$"
        tags = sorted(
            (tag for tag in self.tags if re.match(tag_re, tag)),
            key=get_version_from_tag_name,
            reverse=True,
        )

        # Only consider tags that have releases as a release might be in progress
        return self._filter_released_tags(tags)

    def get_latest_tag_for_major_version(self, major_version=None):
        tags = self.get_tags_for_major_version(major_version)
        return tags[0] if tags else None

    def get_tags_for_release_branch(self, release_branch_name=None):
        # Tags are ordered based on semver, with latest first
        # Note: Assumes that N.a.b releases can only be cut from N.x branch,
        # with N a valid major version number
        major_version = (
            get_major_version_from_release_branch_name(release_branch_name)
            if release_branch_name
            else None
        )
        return self.get_tags_for_major_version(major_version)

    def get_lts_releases(self, branch):
        """
        Returns a dict of all release major versions to the the latest release tag on that branch.
        Only release branches older than `branch` are included.
        The oldest release branch is first in the dict.
        """
        branch = sanitise_branch_name(branch)
        releases = {}
        max_major_version = (
            get_major_version_from_release_branch_name(branch)
            if is_release_branch(branch)
            else None
        )
        major_version = 1
        while max_major_version is None or major_version <= max_major_version:
            tag = self.get_latest_tag_for_major_version(major_version)
            if tag is None:
                break
            releases[major_version] = tag
            major_version += 1
        return releases

    def install_release(self, tag, platform="sgx"):
        stripped_tag = strip_release_tag_name(tag)
        install_directory = f"{INSTALL_DIRECTORY_PREFIX}{stripped_tag}"
        if get_version_from_tag_name(tag) >= Version("3.0.0-rc1"):
            install_path = os.path.abspath(
                os.path.join(
                    install_directory, f"{INSTALL_DIRECTORY_SUB_PATH}_{platform}"
                )
            )
        else:
            install_path = os.path.abspath(
                os.path.join(install_directory, INSTALL_DIRECTORY_SUB_PATH)
            )
        debian_package_url = get_debian_package_url_from_tag_name(tag, platform)
        installed_file_path = os.path.join(install_path, INSTALL_SUCCESS_FILE)

        # Skip downloading release if it already exists
        if os.path.isfile(installed_file_path):
            LOG.info(
                f"Using existing release {stripped_tag} already installed at {install_path}"
            )
            return tag, install_path

        debian_package_name = debian_package_url.split("/")[-1]
        download_path = os.path.join(DOWNLOAD_FOLDER_NAME, debian_package_name)
        LOG.info(f"Downloading {debian_package_url} to {download_path}...")
        if not os.path.exists(DOWNLOAD_FOLDER_NAME):
            os.mkdir(DOWNLOAD_FOLDER_NAME)

        shutil.rmtree(download_path, ignore_errors=True)
        urllib.request.urlretrieve(debian_package_url, download_path)

        LOG.info("Unpacking debian package...")
        shutil.rmtree(install_directory, ignore_errors=True)
        install_cmd = ["dpkg-deb", "-R", download_path, install_directory]
        subprocess.run(install_cmd, check=True)

        # Write new file to avoid having to download install again
        open(os.path.join(install_path, INSTALL_SUCCESS_FILE), "w+", encoding="utf-8")

        LOG.info(f"CCF release {tag} successfully installed at {install_path}")
        return tag, install_path

    def get_latest_tag(self, final_only):
        # Based on semver, not chronologically
        release_tags = self.get_tags_for_release_branch(release_branch_name=None)
        final_release_tags = [tag for tag in release_tags if not is_non_final_tag(tag)]
        non_final_release_tags = [tag for tag in release_tags if is_non_final_tag(tag)]
        if not final_only:
            # Discard non-final tags that are already superseded by a final release
            # e.g. discard 1.0.0-rc0 if 1.0.0 is already out
            non_released_non_final_tags = [
                tag
                for tag in non_final_release_tags
                if strip_non_final_tag_name(tag) not in final_release_tags
            ]
            return (
                non_released_non_final_tags[0] if non_released_non_final_tags else None
            )
        return final_release_tags[0] if release_tags else None

    def get_latest_released_tag_for_branch(self, branch, this_release_branch_only):
        """
        If the branch is a release branch, return latest tag on this branch if
        this_release_branch_only is true.
        If no tags are found (i.e. first tag on this release branch) or this_release_branch_only
        is false, return latest tag on _previous_ release branch.
        If the branch is not a release branch, verify compatibility with the
        latest available LTS.
        """
        branch = sanitise_branch_name(branch)
        if is_release_branch(branch):
            LOG.debug(f"{branch} is release branch")

            tags = self.get_tags_for_release_branch(
                get_release_branch_from_branch_name(branch)
            )
            if tags and this_release_branch_only:
                return tags[0]
            elif not this_release_branch_only:
                branch_major_version = get_major_version_from_release_branch_name(
                    branch
                )
                if branch_major_version <= 1:
                    LOG.warning(f"No previous major version for {branch}")
                    return None
                return self.get_latest_tag_for_major_version(branch_major_version - 1)
            else:
                LOG.warning(f"Release branch {branch} has no release yet")
                return None
        else:
            LOG.debug(f"{branch} is development branch")
            # For development branches (e.g. main), only consider non-final tags (e.g. -rc or -dev)
            # that have not been superseded by a later final release when testing compatibility with
            # same branch
            return self.get_latest_tag(final_only=not this_release_branch_only)

    def get_first_tag_for_next_release_branch(self, branch):
        """
        If the branch is a release branch, return first tag for the next release branch.
        If no next branch/tag are found or the branch is not a release branch, return nothing.
        """
        branch = sanitise_branch_name(branch)
        if is_release_branch(branch):
            LOG.debug(f"{branch} is release branch")
            branch_major_version = get_major_version_from_release_branch_name(branch)
            return self.get_latest_tag_for_major_version(branch_major_version + 1)
        else:
            LOG.debug(f"{branch} is development branch")
            return None

    def install_latest_lts_for_branch(
        self, branch, this_release_branch_only, platform="sgx"
    ):
        latest_tag = self.get_latest_released_tag_for_branch(
            branch, this_release_branch_only
        )
        return (
            self.install_release(latest_tag, platform) if latest_tag else (None, None)
        )

    def install_next_lts_for_branch(self, branch, platform="sgx"):
        next_tag = self.get_first_tag_for_next_release_branch(branch)
        return self.install_release(next_tag, platform) if next_tag else (None, None)


if __name__ == "__main__":
    # Run this to test
    class MockGitEnv:
        def __init__(self, tags=None, local_branch=None):
            self.tags = set(tags or ())
            self.local_branch = local_branch or MAIN_BRANCH_NAME

        def mut(self, tag=None, local=None):
            if tag:
                self.tags.add(tag)
                self.local_branch = tag  # Adding new tag triggers compatibility test
            if local:
                self.local_branch = local
            return MockGitEnv(self.tags, self.local_branch)

        def has_release_for_tag_name(self, tag_name):
            # If tag_name is local branch, then the release from this tag
            # must be in progress
            return True if tag_name != self.local_branch else False

    def exp(prev=None, same=None):
        return {"previous LTS": prev, "same LTS": same}

    env = MockGitEnv()
    test_scenario = [
        (env.mut(local="main"), exp()),  # Bare repo
        (env.mut(tag="ccf-0.0.1"), exp()),  # Create new tag
        (env.mut(local="main"), exp(prev="ccf-0.0.1")),  # Development on main
        (env.mut(tag="ccf-1.0.0-rc0"), exp()),  # 1.0 RC0
        (
            env.mut(local="main"),
            exp(same="ccf-1.0.0-rc0", prev="ccf-0.0.1"),
        ),  # Dev on main
        (env.mut(local="release/1.x"), exp(same="ccf-1.0.0-rc0")),  # Dev on new rel/1.x
        (env.mut(tag="ccf-1.0.0-rc1"), exp(same="ccf-1.0.0-rc0")),  # 1.0 RC1
        (
            env.mut(local="main"),
            exp(same="ccf-1.0.0-rc1", prev="ccf-0.0.1"),
        ),  # Dev on main
        (env.mut(local="release/1.x"), exp(same="ccf-1.0.0-rc1")),  # Dev on rel/1.x
        (env.mut(tag="ccf-1.0.0"), exp(same="ccf-1.0.0-rc1")),  # 1.0.0
        (
            env.mut(local="main"),
            exp(prev="ccf-1.0.0"),
        ),  # Dev on main, no more compatibility with 1.0 RC
        (env.mut(local="release/1.x_new"), exp(same="ccf-1.0.0")),  # Branch off rel/1.x
        (env.mut(tag="ccf-1.0.1"), exp(same="ccf-1.0.0")),  # 1.0.1
        (env.mut(local="release/1.x_new"), exp(same="ccf-1.0.1")),  # Branch off rel/1.x
        (env.mut(tag="ccf-2.0.0-dev0"), exp(prev="ccf-1.0.1")),  # 2.0 dev0 tag
        (env.mut(local="main"), exp(prev="ccf-1.0.1")),  # Dev on main
        (env.mut(tag="ccf-2.0.0-dev1"), exp(prev="ccf-1.0.1")),  # 2.0 dev1 tag
        (env.mut(local="release/1.x"), exp(same="ccf-1.0.1")),  # Dev on rel/1.x
        (env.mut(tag="ccf-2.0.0-rc0"), exp(prev="ccf-1.0.1")),  # 2.0 RC0
        (env.mut(local="release/1.x"), exp(same="ccf-1.0.1")),  # Dev on rel/1.x
        (
            env.mut(local="main"),
            exp(same="ccf-2.0.0-rc0", prev="ccf-1.0.1"),
        ),  # Dev on main
        (
            env.mut(tag="ccf-2.0.0"),
            exp(prev="ccf-1.0.1", same="ccf-2.0.0-rc0"),
        ),  # 2.0.0
        (env.mut(local="main"), exp(prev="ccf-2.0.0")),  # Dev on main
        (env.mut(local="release/1.x"), exp(same="ccf-1.0.1")),  # Dev on rel/1.x
        (
            env.mut(local="release/2.x"),
            exp(prev="ccf-1.0.1", same="ccf-2.0.0"),
        ),  # Dev on rel/2.x
        (
            env.mut(local="release/2.x"),
            exp(prev="ccf-1.0.1", same="ccf-2.0.0"),
        ),  # Dev on rel/2.x
        (env.mut(tag="ccf-2.0.1"), exp(prev="ccf-1.0.1", same="ccf-2.0.0")),  # 2.0.1
        (env.mut(local="release/1.x"), exp(same="ccf-1.0.1")),  # Dev on rel/1.x
        (env.mut(tag="ccf-3.0.0-rc0"), exp(prev="ccf-2.0.1")),  # 3.0 RC0
        (
            env.mut(tag="ccf-3.0.0"),
            exp(same="ccf-3.0.0-rc0", prev="ccf-2.0.1"),
        ),  # 3.0.0
        (
            env.mut(local="release/2.x"),
            exp(prev="ccf-1.0.1", same="ccf-2.0.1"),
        ),  # Dev on rel/2.x
        (env.mut(tag="ccf-2.0.2"), exp(prev="ccf-1.0.1", same="ccf-2.0.1")),  # 2.0.2
        (
            env.mut(tag="ccf-3.0.0"),
            exp(same="ccf-3.0.0-rc0", prev="ccf-2.0.2"),
        ),  # 3.0.0
        (
            env.mut(local="release/3.x"),
            exp(prev="ccf-2.0.2", same="ccf-3.0.0"),
        ),  # Dev on rel/3.x
        (
            env.mut(local=f"{BACKPORT_BRANCH_PREFIX}release/3.x"),
            exp(prev="ccf-2.0.2", same="ccf-3.0.0"),
        ),  # backport/ prefix is ignored
        (
            env.mut(tag="unknown-tag"),
            exp(prev="ccf-3.0.0"),
        ),  # Non-release tag
        (
            env.mut(local="unknown_branch"),
            exp(prev="ccf-3.0.0"),
        ),  # Non-release branch
        (
            env.mut(tag="ccf-latest-main"),
            exp(prev="ccf-3.0.0", same=None),
        ),  # Latest release tag
        (
            env.mut(tag="ccf-latest-2.x"),
            exp(prev="ccf-1.0.1", same="ccf-2.0.2"),
        ),  # Latest release tag (2.x)
        (
            env.mut(tag="ccf-latest-3.x"),
            exp(prev="ccf-2.0.2", same="ccf-3.0.0"),
        ),  # Latest release tag (3.x)
    ]

    for e, exp in test_scenario:
        LOG.info("*************")
        LOG.info(f'env: tags: {e.tags or []} (local branch: "{e.local_branch}")')
        repo = Repository(e)

        # Latest LTS (different branch)
        LOG.info(f"Finding latest LTS for different branch for local: {e.local_branch}")
        latest_tag = repo.get_latest_released_tag_for_branch(
            branch=e.local_branch, this_release_branch_only=False
        )
        assert (
            latest_tag == exp["previous LTS"]
        ), f'Prev LTS: {latest_tag} != expected {exp["previous LTS"]}'

        # Latest LTS (same branch)
        LOG.info(f"Finding latest LTS for same branch for local: {e.local_branch}")
        latest_tag_for_this_release_branch = repo.get_latest_released_tag_for_branch(
            branch=e.local_branch, this_release_branch_only=True
        )
        assert (
            latest_tag_for_this_release_branch == exp["same LTS"]
        ), f'Same LTS: {latest_tag_for_this_release_branch} != expected {exp["same LTS"]}'

        # All releases so far
        LOG.info(f"Finding all latest releases so far for local: {e.local_branch}")
        lts_releases = repo.get_lts_releases(e.local_branch)
        if is_release_branch(e.local_branch):
            assert len(lts_releases) == get_major_version_from_release_branch_name(
                e.local_branch
            )

    LOG.success(f"Successfully verified scenario of size {len(test_scenario)}")
