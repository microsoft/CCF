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
from jinja2 import Environment, FileSystemLoader, select_autoescape, StrictUndefined
import json
import time

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


def remove_suffix(s: str, suffix: str):
    if s.endswith(suffix):
        return s[0 : -len(suffix)]
    return s


def render_jinja_json(template_name, args, **kwargs):
    loader = FileSystemLoader(args.jinja_templates)
    environment = Environment(
        loader=loader,
        autoescape=select_autoescape(),
        undefined=StrictUndefined,
    )
    environment.filters["shlex_quote"] = shlex.quote
    template = environment.get_template(template_name)
    output = template.render(**kwargs)

    basename, _ = os.path.splitext(os.path.basename(template_name))
    output_name = os.path.join(args.output_dir, remove_suffix(basename, ".jinja"))

    LOG.info(
        f"Writing rendered {os.path.join(args.jinja_templates, template_name)} to {output_name}"
    )
    with open(output_name, "w", encoding="utf-8") as f:
        # Re-parse to confirm this is valid JSON
        obj = json.loads(output)
        json.dump(obj, f, indent=2)

    return output_name, obj


class CCFRelease:
    def __init__(self, v: str, platform: str = "snp"):
        v = remove_prefix(v, "ccf-")
        self.version = Version(v)
        self.version_s = v  # Trust the caller to separate this correctly, ignore Version's stringifier
        self.downloads_base_url = (
            f"https://github.com/microsoft/CCF/releases/download/ccf-{self.version_s}"
        )
        self.platform = platform

        self.is_azure_linux = self.version.major >= 6
        self.installer_tool = "tdnf" if self.is_azure_linux else "apt"

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

    def ccf_setup_commands(self, args, node_fqdn):
        kwargs = {
            "fqdn": node_fqdn,
            "command": args.command,
            "platform": self.platform,
            "version": args.version.version.major,
        }

        if self.platform == "virtual":
            kwargs["platform_title_case"] = "Virtual"
        elif self.platform == "snp":
            kwargs["platform_title_case"] = "SNP"
        else:
            raise ValueError(f"Unhandled platform: {self.platform}")

        if args.command == "join":
            kwargs["target_rpc_address"] = args.target

        _, config = render_jinja_json(
            "ccf_minimal_config.json.jinja",
            args,
            **kwargs,
        )

        if self.is_azure_linux:
            install = [
                f"curl -kL {self.binary_url()} -o ./ccf.rpm",
                "tdnf install -y ./ccf.rpm",
            ]
        else:
            install = [
                "apt update -y",
                "apt install -y curl gnupg software-properties-common",
                # Add LLVM repo (with key first)
                "curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -",
                "add-apt-repository 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal-15 main'",
                # Manually install az-dcap-client, via Microsoft repo
                "curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -",
                "add-apt-repository 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main'",
                "apt update -y",
                "apt install -y az-dcap-client",
                # Manually install OE host-verify
                "curl -kL https://github.com/openenclave/openenclave/releases/download/v0.19.8/Ubuntu_2004_open-enclave-hostverify_0.19.8_amd64.deb -o oe.deb",
                "apt install -y ./oe.deb",
                # Manually install CCF
                f"curl -kL {self.binary_url()} -o ./ccf.deb",
                "apt install -y ./ccf.deb",
            ]

        # Overwrite installed sample constitution with one that accepts all proposals
        write_auto_accept = [
            f"""echo 'export function resolve() {{ return \\"Accepted\\"; }}' > /opt/ccf_{self.platform}/bin/resolve.js"""
        ]

        write_config = [
            f"echo '{json.dumps(json.dumps(config)).strip('"')}' > /mnt/ccf/config.json"
        ]

        ccf_dir = f"/opt/ccf_{self.platform}"
        start_node = [
            "cd /mnt/ccf",
            "source /mnt/ccf/aci_env",
            shlex.join(
                [
                    f"{ccf_dir}/bin/cchost",
                    "--config",
                    "/mnt/ccf/config.json",
                    "--enclave-file",
                    f"{ccf_dir}/lib/libjs_generic.{self.platform}.so",
                    "--enclave-log-level",
                    "trace",
                ]
            ),
        ]
        return install + write_auto_accept + write_config + start_node


class MemberCertPath:
    def __init__(self, path: str):
        if not os.path.exists(path):
            raise ValueError(f"No member cert found at {path}")
        self.cert_path = path

        dirname, filename = os.path.split(path)
        fileroot = remove_suffix(filename, "_cert.pem")

        encryption_key_path = os.path.join(dirname, f"{fileroot}_enc_pubk.pem")
        if not os.path.exists(encryption_key_path):
            raise ValueError(f"No member encryption public key found at {path}")
        self.encryption_key_path = encryption_key_path


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
    bash_cmd.extend(args.version.ccf_setup_commands(args, fqdn))

    cmd = " && ".join(bash_cmd)

    LOG.info(f"This C-ACI deployment will be called {name}")

    files_to_copy = {}

    if args.command == "start":
        files_to_copy["/mnt/ccf/member0_cert.pem"] = open(
            args.member_cert.cert_path
        ).read()
        files_to_copy["/mnt/ccf/member0_enc_pubk.pem"] = open(
            args.member_cert.encryption_key_path
        ).read()

    elif args.command == "join":
        r = requests.get(f"https://{args.target}/node/network", verify=False, timeout=3)
        assert (
            r.status_code == 200
        ), f"Unable to fetch service info from target node: {r}"
        body = r.json()
        service_cert = body["service_certificate"]
        files_to_copy["/mnt/ccf/service_cert.pem"] = service_cert

    arm_template_path, _ = render_jinja_json(
        "arm_start_ccf_node.json.jinja",
        args,
        command=args.command,
        name=name,
        location=args.location,
        image=args.version.base_image(),
        container_command=cmd,
        ssh_key=get_ssh_key(),
        files_to_copy=files_to_copy,
        is_azure_linux=args.version.is_azure_linux,
        installer_tool=args.version.installer_tool,
    )

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
        arm_template_path,
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
        "{provisioningState:provisioningState,ip:ipAddress.ip,fqdn:ipAddress.fqdn,resourceGroup:resourceGroup,location:location,name:name}",
    ]
    ret = ccall(*az_show_cmd, capture_output=True)
    assert ret.returncode == 0, "Error showing C-ACI info"

    LOG.success(
        f"Deployed new C-ACI instance (a CCF {args.command} node):\n{ret.stdout.decode()}"
    )

    if args.no_delete:
        LOG.info("Exiting")
    else:
        LOG.info(f"Spinning...")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            LOG.info("Loop exited: attempting automatic cleanup")

        az_delete_cmd = [
            "az",
            "container",
            "delete",
            "--yes",
            "--verbose",
            "--resource-group",
            args.resource_group,
            "--name",
            name,
        ]
        assert (
            ccall(*az_delete_cmd, capture_output=False).returncode == 0
        ), "Error deleting container group"


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
    parser.add_argument(
        "--jinja-templates",
        help="Path to directory where jinja templates are stored",
        default=".",
    )
    parser.add_argument(
        "--output-dir",
        help="Path to directory where files created by this tool will be stored",
        default=".",
    )
    parser.add_argument(
        "--no-delete",
        help="By default, this script will clean up resources on shutdown. If this is passed, it will instead leave created resources running",
        action="store_true",
    )

    commands = parser.add_subparsers(
        help="Kind of node to start",
        dest="command",
        required=True,
    )

    start_parser = commands.add_parser("start", help="Start a new service")
    start_parser.add_argument(
        "--member-cert",
        help="Path to member cert which will be sole governor of the new service",
        default="member0_cert.pem",
        type=MemberCertPath,
    )

    join_parser = commands.add_parser("join", help="Join an existing service")
    join_parser.add_argument(
        "--target",
        help="Target address of node to join",
        required=True,
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
