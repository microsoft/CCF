# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.proc

import re
import os
from functools import cmp_to_key
from github import Github
import urllib
import shutil

# pylint: disable=import-error, no-name-in-module
from setuptools.extern.packaging.version import Version  # type: ignore

from loguru import logger as LOG


# Optional. May be useful to avoid GitHub's low rate limits for unauthenticated clients
# https://docs.github.com/en/rest/reference/rate-limit
ENV_VAR_GITHUB_AUTH_TOKEN_NAME = "GITHUB_COMPATIBILITY_TOKEN"

REPOSITORY_NAME = "microsoft/CCF"
BRANCH_RELEASE_PREFIX = "release/"
TAG_RELEASE_PREFIX = "ccf-"
MAIN_BRANCH_NAME = "main"
DEBIAN_PACKAGE_EXTENSION = "_amd64.deb"
# This assumes that CCF is installed at `/opt/ccf`, which is true from 1.0.0
INSTALL_DIRECTORY_PREFIX = "ccf_install_"
INSTALL_DIRECTORY_SUB_PATH = "opt/ccf"
DOWNLOAD_FOLDER_NAME = "downloads"

# Note: Releases are identified by tag since releases are not necessarily named, but all
# releases are tagged


def is_release_branch(branch_name):
    return branch_name.startswith(BRANCH_RELEASE_PREFIX)


def is_release_tag(tag_name):
    return tag_name.startswith(TAG_RELEASE_PREFIX)


def is_main_branch(branch_name):
    return branch_name == MAIN_BRANCH_NAME


def strip_release_branch_name(branch_name):
    assert is_release_branch(branch_name), branch_name
    return branch_name[len(BRANCH_RELEASE_PREFIX) :]


def get_major_version_from_release_branch_name(full_branch_name):
    return int(strip_release_branch_name(full_branch_name).split(".")[0])


def get_version_from_tag_name(tag_name):
    assert is_release_tag(tag_name), tag_name
    return Version(tag_name[len(TAG_RELEASE_PREFIX) :])


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


class Repository:
    """
    Helper class to verify CCF operations compatibility described at
    https://microsoft.github.io/CCF/main/overview/release_policy.html#operations-compatibility
    """

    def __init__(self):
        # TODO: Remove lines below
        import hashlib
        if os.getenv(ENV_VAR_GITHUB_AUTH_TOKEN_NAME):
            LOG.warning(f"Len of token: {len(os.getenv(ENV_VAR_GITHUB_AUTH_TOKEN_NAME))}")
            LOG.error(f"Hash of token: {hashlib.sha256(os.getenv(ENV_VAR_GITHUB_AUTH_TOKEN_NAME).encode()).hexdigest()}")
        # TODO: Remove lines above
        self.g = Github(os.getenv(ENV_VAR_GITHUB_AUTH_TOKEN_NAME))
        self.repo = self.g.get_repo(REPOSITORY_NAME)

    def get_release_branches_names(self):
        # Branches are ordered based on major version, with oldest first
        return sorted(
            [
                branch.name
                for branch in self.repo.get_branches()
                if is_release_branch(branch.name)
            ],
            key=cmp_to_key(
                lambda b1, b2: get_major_version_from_release_branch_name(b2)
                - get_major_version_from_release_branch_name(b1)
            ),
        )

    def get_release_branch_name_before(self, release_branch_name):
        release_branches = self.get_release_branches_names()
        assert (
            release_branch_name in release_branches
        ), f"{release_branch_name} branch is not a valid release branch"
        before_index = release_branches.index(release_branch_name) - 1
        if before_index < 0:
            raise ValueError(f"No prior release branch to {release_branch_name}")
        return release_branches[before_index]

    def get_next_release_branch(self, release_branch_name):
        release_branches = self.get_release_branches_names()
        assert (
            release_branch_name in release_branches
        ), f"{release_branch_name} branch is not a valid release branch"
        after_index = release_branches.index(release_branch_name) + 1
        if after_index >= len(release_branches):
            raise ValueError(f"No release branch after {release_branch_name}")
        return release_branches[after_index]

    def get_tags_with_releases(self):
        # Only consider tags that have releases as perhaps a release is in progress
        # (i.e. tag exists but hasn't got a release just yet)
        all_released_tags = [r.tag_name for r in self.repo.get_releases()]
        return [t for t in self.repo.get_tags() if t.name in all_released_tags]

    def get_release_for_tag(self, tag):
        releases = [r for r in self.repo.get_releases() if r.tag_name == tag.name]
        if not releases:
            raise ValueError(
                f"No releases found for tag {tag}. Has the release for {tag} not been published yet?"
            )
        return releases[0]

    def get_tags_for_release_branch(self, branch_name):
        # Tags are ordered based on semver, with latest first
        # Note: Assumes that N.a.b releases can only be cut from N.x branch,
        # with N a valid major version number
        assert is_release_branch(branch_name), f"{branch_name} is not a release branch"

        release_branch_name = strip_release_branch_name(branch_name)
        release_re = "^{}{}$".format(
            TAG_RELEASE_PREFIX, release_branch_name.replace(".x", "([.\\d+]+)")
        )
        return sorted(
            [
                tag
                for tag in self.get_tags_with_releases()
                if re.match(release_re, tag.name)
            ],
            key=cmp_to_key(
                lambda t1, t2: get_version_from_tag_name(t1.name)
                < get_version_from_tag_name(t2.name)
            ),
        )

    def get_lts_releases(self):
        """
        Returns a dict of all release branches to the the latest release tag on this branch.
        The oldest release branch is first in the dict.
        """
        releases = {}
        for release_branch in self.get_release_branches_names():
            releases[release_branch] = self.get_tags_for_release_branch(release_branch)[
                0
            ]
        return releases

    def install_release(self, tag):
        stripped_tag = tag.name[len(TAG_RELEASE_PREFIX) :]
        release = self.get_release_for_tag(tag)

        install_directory = f"{INSTALL_DIRECTORY_PREFIX}{stripped_tag}"
        debian_package_url = [
            a.browser_download_url
            for a in release.get_assets()
            if re.match(f"ccf_{stripped_tag}{DEBIAN_PACKAGE_EXTENSION}", a.name)
        ][0]

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
        assert infra.proc.ccall(*install_cmd).returncode == 0, "Installation failed"

        install_path = os.path.abspath(
            os.path.join(install_directory, INSTALL_DIRECTORY_SUB_PATH)
        )
        LOG.info(f"CCF release {stripped_tag} successfully installed at {install_path}")
        return stripped_tag, install_path

    def get_latest_tag_for_release_branch(self, branch):
        """
        If the branch is a release branch, return latest tag on this branch.
        If no tags are found (i.e. first tag on this release branch), return latest
        tag on _previous_ release branch.
        If the branch is not a release branch, verify compatibility with the
        latest available LTS.
        """
        if is_release_branch(branch):
            LOG.debug(f"{branch} is release branch")
            tags = self.get_tags_for_release_branch(
                get_release_branch_from_branch_name(branch)
            )
            if tags:
                return tags[0]
            else:
                try:
                    prior_release_branch = self.get_release_branch_name_before(branch)
                    return self.get_tags_for_release_branch(prior_release_branch)[0]
                except ValueError as e:  # No previous release branch
                    LOG.warning(f"{e}. Skipping compatibility test with previous")
                    return None
        else:
            LOG.debug(f"{branch} is development branch")
            latest_release_branch = self.get_release_branches_names()[0]
            LOG.info(f"Latest release branch: {latest_release_branch}")
            return self.get_tags_for_release_branch(latest_release_branch)[0]

    def get_first_tag_for_next_release_branch(self, branch):
        """
        If the branch is a release branch, return first tag for the next release branch.
        If no next branch/tag are found or the branch is not a release branch, return nothing.
        """
        if is_release_branch(branch):
            LOG.debug(f"{branch} is release branch")
            try:
                next_release_branch = self.get_next_release_branch(
                    get_release_branch_from_branch_name(branch)
                )
                LOG.debug(f"{next_release_branch} is next release branch")
                return self.get_tags_for_release_branch(next_release_branch)[-1]
            except ValueError as e:  # No release branch after target branch
                LOG.warning(f"{e}. Skipping compatibility test with next")
                return None
        else:
            LOG.debug(f"{branch} is development branch")
            return None

    def install_latest_lts_for_branch(self, branch):
        latest_tag = self.get_latest_tag_for_release_branch(branch)
        if not latest_tag:
            LOG.info(f"No latest release tag found for {branch}")
            return None, None

        # Note: will currently fail if the tag is created but the release
        # not yet published
        LOG.info(f"Latest release tag: {latest_tag.name}")
        return self.install_release(latest_tag)

    def install_next_lts_for_branch(self, branch):
        next_tag = self.get_first_tag_for_next_release_branch(branch)
        if not next_tag:
            LOG.info(f"No next release tag found for {branch}")
            return None, None

        LOG.info(f"Next release tag: {next_tag.name}")
        return self.install_release(next_tag)
