# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.proc

import re
import os
from github import Github
from setuptools.extern.packaging.version import Version  # type: ignore

from loguru import logger as LOG


REPOSITORY_NAME = "microsoft/CCF"
BRANCH_RELEASE_PREFIX = "release/"
DEBIAN_PACKAGE_EXTENSION = "_amd64.deb"
# This assumes that CCF is installed at `/opt/ccf`, which is true from 1.0.0
INSTALL_DIRECTORY_SUB_PATH = "opt/ccf"


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

    def get_releases_from_release_branch(self, branch_name):
        # Assumes that N.a.b releases can only be cut from N.x branch, with N a valid major version number
        assert branch_name.startswith(
            BRANCH_RELEASE_PREFIX
        ), f"{branch_name} is not a release branch"

        release_branch_name = branch_name[len(BRANCH_RELEASE_PREFIX) :]
        release_re = "^ccf-{}$".format(release_branch_name.replace(".x", "([.\d+]+)"))

        # Most recent tag is first
        return list(
            ([tag for tag in self.repo.get_tags() if re.match(release_re, tag.name)])
        )

    def install_ccf_debian_package(self, debian_package_url, directory_name):
        LOG.info(f"Downloading {debian_package_url}...")
        download_cmd = ["wget", debian_package_url]
        assert (
            infra.proc.ccall(*download_cmd, log_output=False).returncode == 0
        ), "Download failed"

        LOG.info("Unpacking debian package...")
        remove_cmd = ["rm", "-rf", directory_name]
        assert (
            infra.proc.ccall(*remove_cmd).returncode == 0
        ), "Previous install cleanup failed"
        install_cmd = [
            "dpkg-deb",
            "-R",
            debian_package_url.split("/")[-1],
            directory_name,
        ]
        assert infra.proc.ccall(*install_cmd).returncode == 0, "Installation failed"

        install_path = os.path.abspath(
            os.path.join(directory_name, INSTALL_DIRECTORY_SUB_PATH)
        )
        LOG.success(f"CCF release successfully installed at {install_path}")
        return install_path

    def install_latest_lts(self, previous_lts_file):

        with open(previous_lts_file) as f:
            latest_release = f.readline()
        latest_release_branch = f"release/{latest_release}"
        LOG.info(f"Latest release branch for this checkout: {latest_release_branch}")

        if latest_release_branch not in self.get_release_branches_names():
            raise ValueError(
                f"Latest release branch {latest_release_branch} is not a valid release branch"
            )

        tags_for_this_release = self.get_releases_from_release_branch(
            latest_release_branch
        )
        LOG.info(f"Found tags: {[t.name for t in tags_for_this_release]}")

        latest_tag_for_this_release = tags_for_this_release[0]
        LOG.info(f"Most recent tag: {latest_tag_for_this_release.name}")

        releases = [
            r
            for r in self.repo.get_releases()
            if r.tag_name == latest_tag_for_this_release.name
        ]
        assert (
            len(releases) == 1
        ), f"Found {len(releases)} releases for tag {latest_tag_for_this_release.name}, expected 1"
        release = releases[0]
        LOG.info(f"Found release: {release.html_url}")

        stripped_tag = latest_tag_for_this_release.name[len("ccf-") :]
        debian_package_url = [
            a.browser_download_url
            for a in release.get_assets()
            if re.match(f"ccf_{stripped_tag}{DEBIAN_PACKAGE_EXTENSION}", a.name)
        ][0]

        return Version(stripped_tag).release[0], self.install_ccf_debian_package(
            debian_package_url,
            directory_name=f"ccf_install_{latest_tag_for_this_release.name}",
        )