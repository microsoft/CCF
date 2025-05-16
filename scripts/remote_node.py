#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import requests
import subprocess
import os
import shlex
from datetime import datetime
from packaging.version import Version  # type: ignore

from loguru import logger as LOG


def datetime_string():
    dt = datetime.now()
    s = dt.isoformat()
    s = s.replace("-", "")
    s = s.replace(":", "")
    s = s.replace("T", "-")
    s = s[0 : s.find(".")]
    return s


def remove_prefix(s: str, prefix: str):
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s


MINIMAL_CONFIG = """{
  "enclave": {
    "platform": "Virtual",
    "type": "Release"
  },
  "network": {
    "node_to_node_interface": {
      "bind_address": "127.0.0.1:8081",
      "published_address": "<NODE_FQDN>:8081"
    },
    "rpc_interfaces": {
      "interface_name": {
        "bind_address": "127.0.0.1:443",
        "published_address": "<NODE_FQDN>:443"
      }
    }
  },
  "command": {
    "type": "Start",
    "service_certificate_file": "service_cert.pem",
    "start": {
      "constitution_files": [
        "/opt/ccf_virtual/bin/validate.js",
        "/opt/ccf_virtual/bin/apply.js",
        "/opt/ccf_virtual/bin/resolve.js",
        "/opt/ccf_virtual/bin/actions.js"
      ],
      "members": [
        {
          "certificate_file": "member0_cert.pem",
          "encryption_public_key_file": "member0_enc_pubk.pem"
        }
      ]
    }
  }
}
"""


class CCFRelease:
    version: Version
    platform: str
    version_s: str
    base_url: str

    def __init__(self, v: str, platform: str = "virtual"):
        v = remove_prefix(v, "ccf-")
        self.version = Version(v)
        self.version_s = v  # Trust the caller to separate this correctly, ignore Version's stringifier
        self.downloads_base_url = (
            f"https://github.com/microsoft/CCF/releases/download/ccf-{self.version_s}"
        )
        self.platform = platform

    def binary_url(self):
        if self.version.major == 5:
            return f"{self.downloads_base_url}/ccf_{self.platform}_{self.version_s}_amd64.deb"
        elif self.version.major == 6:
            return f"{self.downloads_base_url}/ccf_{self.platform}_devel_{self.version_s}_x86_64.rpm"
        else:
            raise ValueError(
                f"This tool only knows the binary naming pattern for a few release versions - please extend it to handle {self.version_s}"
            )

    def base_image(self):
        if self.version.major >= 6:
            return "mcr.microsoft.com/azurelinux/base/core:3.0"
        else:
            return "mcr.microsoft.com/mirror/docker/library/ubuntu:20.04"

    def ccf_setup_commands(self, node_fqdn):
        if self.version.major >= 6:
            materialised_config = MINIMAL_CONFIG.replace("<NODE_FQDN>", node_fqdn)
            ccf_dir = f"/opt/ccf_{self.platform}"
            return [
                f"curl -kL {self.binary_url()} -o ./ccf.rpm",
                "tdnf install -y ./ccf.rpm",
                "cd /mnt/ccf",
                f"echo '{materialised_config}' >> startup_config.json",
                f"{ccf_dir}/bin/keygenerator.sh --name member0 --gen-enc-key",
                " ".join(
                    [
                        f"{ccf_dir}/bin/cchost",
                        "--config",
                        "startup_config.json",
                        "--enclave-file",
                        f"{ccf_dir}/lib/libjs_generic.virtual.so",
                        "--enclave-log-level",
                        "trace",
                    ]
                ),
            ]
        else:
            return ["TODO"]


def ccall(*args, capture_output=True):
    cmd = shlex.join(args)
    LOG.debug(f"Running: {cmd}")
    result = subprocess.run(args, capture_output=capture_output, check=False)
    if result.stderr and capture_output:
        LOG.error("stderr: {}".format(result.stderr.decode().strip()))
    log_fn = LOG.success if result.returncode == 0 else LOG.error
    log_fn(f"Subprocess exited with returncode {result.returncode}")
    return result


def check_tools():
    LOG.info("Checking required tools are available...")
    assert ccall("az", "--version").returncode == 0, "Azure CLI must be installed"


def check_release(release: CCFRelease):
    LOG.info("Checking release is available...")
    url = release.binary_url()
    res = requests.head(url, allow_redirects=True)
    LOG.debug(f"HEAD {url}")
    assert (
        res.status_code == 200
    ), f"Got {res.status_code} response from {url}. Does this release exist? Does it use a different separator scheme for naming binaries?"


def get_ssh_key():
    ssh_dir = os.path.expanduser("~/.ssh/")
    for f in os.listdir(ssh_dir):
        path = os.path.join(ssh_dir, f)
        if os.path.isfile(path):
            _, ext = os.path.splitext(path)
            if ext == ".pub":
                LOG.debug(f"Using {path} as SSH key")
                with open(path, "r") as file:
                    return file.read().strip()
    raise ValueError(f"No SSH public key found in {ssh_dir}")


def create_aci(args):
    LOG.info("Creating C-ACI deployment")

    bash_cmd = []

    name = f"ccf-tmp-caci-{datetime_string()}"
    fqdn = f"{name}.{args.location}.azurecontainer.io"

    # Install and start CCF node
    bash_cmd.extend(args.version.ccf_setup_commands(fqdn))

    # Spin waiting
    bash_cmd.append("tail -f /dev/null")

    # TODO: Commands to run a CCF node:
    # - Download CCF release
    # - Install it
    # - Copy a config file to the node (provide it in deployment config?)
    # - Run /opt/ccf_{platform}/bin/cchost

    cmd = " && ".join(bash_cmd)

    LOG.info(f"This C-ACI deployment will be called {name}")

    az_create_cmd = [
        "az",
        "deployment",
        "group",
        "create",
        "--verbose",
        "--resource-group",
        args.resource_group,
        "--name",
        name,
        "--template-file",
        "c-aci-template.json",
        "--parameters",
        f"image={args.version.base_image()}",
        "--parameters",
        f"ssh={get_ssh_key()}",
        f"name={name}",
        f"command={cmd}",
        f"location={args.location}",
    ]
    assert (
        ccall(*az_create_cmd, capture_output=False).returncode == 0
    ), "Error creating C-ACI deployment"

    az_show_cmd = [
        "az",
        "container",
        "show",
        "--resource-group",
        args.resource_group,
        "--name",
        name,
        "--query",
        "{state:provisioningState,ip:ipAddress.ip}",
    ]
    assert (
        ccall(*az_show_cmd, capture_output=False).returncode == 0
    ), "Error showing C-ACI container info"

    # TODO: Parse IP address
    # TODO: If no IP address (but "successfully" provisioned), show logs
    az_logs_cmd = [
        "az",
        "container",
        "logs",
        "--follow",
        "--resource-group",
        args.resource_group,
        "--name",
        name,
    ]
    assert (
        ccall(*az_logs_cmd, capture_output=False).returncode == 0
    ), "Error fetching container logs"

    # TODO: Delete the deployed instances on shutdown?


def run():
    parser = argparse.ArgumentParser(description="TODO")

    parser.add_argument(
        "--resource-group",
        help="The Azure resource group to deploy into. If not provided, a new RG will be automatically created.",
    )
    parser.add_argument(
        "--location",
        help="The Azure region to deploy into",
        default="East US 2",
    )
    parser.add_argument(
        "--version",
        help="The CCF version of the node to be launched",
        required=True,
        type=CCFRelease,
    )

    args = parser.parse_args()

    check_tools()
    check_release(args.version)

    if args.resource_group is None:
        args.resource_group = f"ccf-tmp-rg-{datetime_string()}"
        LOG.warning(
            f"Will create new resource group {args.resource_group} (in {args.location})"
        )
        cmd = [
            "az",
            "group",
            "create",
            "--name",
            args.resource_group,
            "--location",
            args.location,
        ]
        assert ccall(*cmd).returncode == 0, "Unable to create resource group"

    create_aci(args)


if __name__ == "__main__":
    run()
