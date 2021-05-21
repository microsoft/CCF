# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.proc

import re
import os
from functools import cmp_to_key
from github import Github

from loguru import logger as LOG


REPOSITORY_NAME = "microsoft/CCF"
BRANCH_RELEASE_PREFIX = "release/"
TAG_RELEASE_PREFIX = "ccf-"
MAIN_BRANCH_NAME = "main"
DEBIAN_PACKAGE_EXTENSION = "_amd64.deb"
# This assumes that CCF is installed at `/opt/ccf`, which is true from 1.0.0
INSTALL_DIRECTORY_PREFIX = "ccf_install_"
INSTALL_DIRECTORY_SUB_PATH = "opt/ccf"

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


def get_patch_version_from_tag_name(tag_name):
    assert is_release_tag(tag_name), tag_name
    return int(tag_name[len(TAG_RELEASE_PREFIX) :].split(".")[-1])


class Repository:
    def __init__(self):
        self.g = Github()
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
                lambda b1, b2: get_major_version_from_release_branch_name(b1)
                - get_major_version_from_release_branch_name(b2)
            ),
        )

    def get_release_for_tag(self, tag):
        releases = [r for r in self.repo.get_releases() if r.tag_name == tag.name]
        if not releases:
            raise ValueError(
                f"No releases found for tag {tag}. Has the release for {tag} not been published yet?"
            )
        return releases[0]

    def get_tags_from_release_branch(self, branch_name):
        # Tags are ordered based on patch version, with oldest first
        # Note: Assumes that N.a.b releases can only be cut from N.x branch,
        # with N a valid major version number
        assert is_release_branch(branch_name), f"{branch_name} is not a release branch"

        release_branch_name = strip_release_branch_name(branch_name)
        release_re = "^{}{}$".format(
            TAG_RELEASE_PREFIX, release_branch_name.replace(".x", "([.\d+]+)")
        )
        return sorted(
            [tag for tag in self.repo.get_tags() if re.match(release_re, tag.name)],
            key=cmp_to_key(
                lambda t1, t2: get_patch_version_from_tag_name(t1.name)
                - get_patch_version_from_tag_name(t2.name)
            ),
        )

    def get_lts_releases(self):
        """
        Returns a dict of all release branches to the the latest release tag on this branch.
        The oldest release branch is first in the dict.
        """
        releases = {}
        for release_branch in self.get_release_branches_names():
            releases[release_branch] = self.get_tags_from_release_branch(release_branch)[0]
        return releases

    def install_release(self, tag):
        stripped_tag = tag.name[len("ccf-") :]
        release = self.get_release_for_tag(tag)

        install_directory = f"{INSTALL_DIRECTORY_PREFIX}{stripped_tag}"

        debian_package_url = [
            a.browser_download_url
            for a in release.get_assets()
            if re.match(f"ccf_{stripped_tag}{DEBIAN_PACKAGE_EXTENSION}", a.name)
        ][0]

        LOG.info(f"Downloading {debian_package_url}...")
        debian_package_name = debian_package_url.split("/")[-1]
        remove_cmd = ["rm", "-rf", debian_package_name]
        assert (
            infra.proc.ccall(*remove_cmd).returncode == 0
        ), "Previous download cleanup failed"
        download_cmd = ["curl", "-OL", debian_package_url]
        assert (
            infra.proc.ccall(*download_cmd, log_output=False).returncode == 0
        ), "Download failed"

        LOG.info("Unpacking debian package...")
        remove_cmd = ["rm", "-rf", install_directory]
        assert (
            infra.proc.ccall(*remove_cmd).returncode == 0
        ), "Previous install cleanup failed"
        install_cmd = ["dpkg-deb", "-R", debian_package_name, install_directory]
        assert infra.proc.ccall(*install_cmd).returncode == 0, "Installation failed"

        install_path = os.path.abspath(
            os.path.join(install_directory, INSTALL_DIRECTORY_SUB_PATH)
        )
        LOG.success(
            f"CCF release {stripped_tag} successfully installed at {install_path}"
        )
        return stripped_tag, install_path

    def install_latest_lts(self, latest_lts_file=None):
        # TODO: Unused for now, delete completly depending on whether we need reproducible builds,
        # which should be required?
        if latest_lts_file:
            with open(latest_lts_file) as f:
                latest_release = f.readline()
            latest_release_branch = f"{BRANCH_RELEASE_PREFIX}{latest_release}"

            if latest_release_branch not in self.get_release_branches_names():
                raise ValueError(
                    f"Latest release branch {latest_release_branch} is not a valid release branch"
                )
        else:
            latest_release_branch = self.get_release_branches_names()[-1]
        LOG.info(f"Latest release branch for this checkout: {latest_release_branch}")

        tags_for_this_release = self.get_tags_from_release_branch(latest_release_branch)
        LOG.info(f"Found tags: {[t.name for t in tags_for_this_release]}")

        latest_tag_for_this_release = tags_for_this_release[-1]
        LOG.info(f"Most recent tag: {latest_tag_for_this_release.name}")

        return self.install_release(latest_tag_for_this_release)
