# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.proc

import re
import os
from github import Github

from loguru import logger as LOG


REPOSITORY_NAME = "microsoft/CCF"
BRANCH_RELEASE_PREFIX = "release/"
DEBIAN_PACKAGE_EXTENSION = "_amd64.deb"
# This assumes that CCF is installed at `/opt/ccf`, which is true from 1.0.0
INSTALL_DIRECTORY_PREFIX = "ccf_install_"
INSTALL_DIRECTORY_SUB_PATH = "opt/ccf"

# Note: Releases are identified by tag since releases are not necessarily named, but all
# releases are tagged by design


class Repository:
    def __init__(self):
        self.g = Github()
        self.repo = self.g.get_repo(REPOSITORY_NAME)

    def get_release_branches_names(self):
        return [
            branch.name
            for branch in self.repo.get_branches()
            if branch.name.startswith(BRANCH_RELEASE_PREFIX)
        ]

    def get_release_for_tag(self, tag):
        releases = [r for r in self.repo.get_releases() if r.tag_name == tag.name]
        assert (
            len(releases) == 1
        ), f"Found {len(releases)} releases for tag {tag.name}, expected 1"
        return releases[0]

    def get_tags_from_branch(self, branch_name):
        # Assumes that N.a.b releases can only be cut from N.x branch, with N a valid major version number
        assert branch_name.startswith(
            BRANCH_RELEASE_PREFIX
        ), f"{branch_name} is not a release branch"

        release_branch_name = branch_name[len(BRANCH_RELEASE_PREFIX) :]
        release_re = "^ccf-{}$".format(release_branch_name.replace(".x", "([.\d+]+)"))

        # Most recent release is first
        return list(
            ([tag for tag in self.repo.get_tags() if re.match(release_re, tag.name)])
        )

    def get_lts_releases(self):
        """
        Returns a dict of all release branches to the the latest release tag on this branch.
        The oldest release branch is first in the dict.
        """
        releases = {}
        for release_branch in self.get_release_branches_names():
            releases[release_branch] = self.get_tags_from_branch(release_branch)[0]
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
        download_cmd = ["wget", debian_package_url]
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

    def install_latest_lts(self, previous_lts_file):
        # TODO: We could get rid of this if we decide to tag the very first commit on `main` after we've branched for a release. But maybe that's messy?
        with open(previous_lts_file) as f:
            latest_release = f.readline()
        latest_release_branch = f"{BRANCH_RELEASE_PREFIX}{latest_release}"
        LOG.info(f"Latest release branch for this checkout: {latest_release_branch}")

        if latest_release_branch not in self.get_release_branches_names():
            raise ValueError(
                f"Latest release branch {latest_release_branch} is not a valid release branch"
            )

        tags_for_this_release = self.get_tags_from_branch(latest_release_branch)
        LOG.info(f"Found tags: {[t.name for t in tags_for_this_release]}")

        latest_tag_for_this_release = tags_for_this_release[0]
        LOG.info(f"Most recent tag: {latest_tag_for_this_release.name}")

        return self.install_release(latest_tag_for_this_release)
