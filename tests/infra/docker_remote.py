# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.remote
import docker
import re
import os
import pathlib
import grp
import infra.github
import time

from loguru import logger as LOG


def is_docker_env():
    """Returns true if the process executing _this_ code already runs inside Docker"""
    return os.path.isfile("/.dockerenv")


def is_azure_devops_env():
    return "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


def map_azure_devops_docker_workspace_dir(workspace_dir):
    return workspace_dir.replace("__w", "/mnt/vss/_work")


# Docker image name prefix
# To update when runtime images are pushed to ACR
MICROSOFT_REGISTRY_NAME = "mcr.microsoft.com"
DOCKER_IMAGE_NAME_PREFIX = "ccf/app/run"

# Network name
AZURE_DEVOPS_CONTAINER_NETWORK_ENV_VAR = "AGENT_CONTAINERNETWORK"
DOCKER_NETWORK_NAME_LOCAL = "ccf_test_docker_network"

# Identifier for all CCF test containers
CCF_TEST_CONTAINERS_LABEL = "ccf_test"

NODE_STARTUP_WRAPPER_SCRIPT = "docker_wrap.sh"
CONTAINER_IP_REPLACE_STR = "CONTAINER_IP"


def kernel_has_sgx_builtin():
    with open("/proc/cpuinfo", "r", encoding="utf-8") as cpu_info:
        f = re.compile("^flags.*sgx.*")
        for line in cpu_info:
            if f.match(line):
                return True
    return False


class DockerRemote(infra.remote.LocalRemote):
    def _stop_container(self, container):
        while True:
            try:
                container.stop()
                container.remove()
                LOG.info(f"Stopped container {container.name}")
                break
            except docker.errors.NotFound:
                break
            except docker.errors.APIError:
                # Container may already be in the process of being cleaned up
                time.sleep(0.5)
                continue

    @staticmethod
    def make_host(host):
        # Bind local RPC address to 0.0.0.0, so that it be can be accessed from outside container
        for _, rpc_interface in host.rpc_interfaces.items():
            rpc_interface.host = "0.0.0.0"
            rpc_interface.public_host = CONTAINER_IP_REPLACE_STR
        return host

    @staticmethod
    def get_node_address(*args, **kwargs):
        return CONTAINER_IP_REPLACE_STR

    def __init__(
        self,
        *args,
        host=None,
        label=None,
        local_node_id=None,
        version=None,
        binary_dir=".",
        node_container_image=None,
        **kwargs,
    ):
        self.docker_client = docker.DockerClient()
        self.container_ip = None  # Assigned when container is started
        self.host = host
        self.binary_dir = binary_dir

        # Sanitise container name, replacing illegal characters with underscores
        self.container_name = f"{label}_{local_node_id}"
        self.container_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.container_name)

        # Create network to connect all containers to (for n2n communication, etc.).
        # In a Docker environment, use existing network (either the one provided by
        # ADO or the one already created by the runner).
        # Otherwise, create network on the fly.
        if is_docker_env() and is_azure_devops_env():
            network_name = os.environ[AZURE_DEVOPS_CONTAINER_NETWORK_ENV_VAR]
        else:
            network_name = DOCKER_NETWORK_NAME_LOCAL

        try:
            self.network = self.docker_client.networks.get(network_name)
        except docker.errors.NotFound:
            LOG.debug(f"Creating network {network_name}")
            self.network = self.docker_client.networks.create(network_name)

        # Stop and delete existing container(s)
        if local_node_id == 0:
            for c in self.docker_client.containers.list(
                all=True, filters={"label": [CCF_TEST_CONTAINERS_LABEL, label]}
            ):
                self._stop_container(c)

        LOG.debug(
            f'Network {self.network.name} [{self.network.attrs["IPAM"]["Config"][0]["Gateway"]}]'
        )

        # Group and device for kernel sgx builtin support (or not)
        if kernel_has_sgx_builtin():
            gid = grp.getgrnam("sgx_prv").gr_gid
            devices = (
                ["/dev/sgx/enclave", "/dev/sgx/provision"]
                if os.path.isdir("/dev/sgx")
                else None
            )
        else:
            gid = os.getgid()
            devices = ["/dev/sgx"] if os.path.isdir("/dev/sgx") else None

        # Mount workspace volume
        cwd = str(pathlib.Path().resolve())
        cwd_host = (
            map_azure_devops_docker_workspace_dir(cwd) if is_azure_devops_env() else cwd
        )

        # Deduce container tag from node version
        repo = infra.github.Repository()
        if node_container_image is None:
            node_container_image = (
                f"{MICROSOFT_REGISTRY_NAME}/{DOCKER_IMAGE_NAME_PREFIX}:"
            )
            if version is not None:
                node_container_image += version
            else:
                suffix = "sgx" if os.path.exists("/dev/sgx") else "virtual-clang15"
                node_container_image += f"{infra.github.strip_release_tag_name(repo.get_latest_dev_tag())}-{suffix}"

        try:
            self.docker_client.images.get(node_container_image)
        except docker.errors.ImageNotFound:
            LOG.info(f"Pulling image {node_container_image}")
            self.docker_client.images.pull(node_container_image)

        super().__init__(*args, host=host, **kwargs)

        self.command = (
            f'./{NODE_STARTUP_WRAPPER_SCRIPT} "{super().get_cmd(include_dir=False)}"'
        )

        self.container = self.docker_client.containers.create(
            node_container_image,
            volumes={cwd_host: {"bind": cwd, "mode": "rw"}},
            devices=devices,
            command=self.command,
            name=self.container_name,
            init=True,
            labels=[label, CCF_TEST_CONTAINERS_LABEL],
            publish_all_ports=True,
            user=f"{os.getuid()}:{gid}",
            working_dir=self.root,
            detach=True,
            auto_remove=True,
        )
        self.network.connect(self.container)
        LOG.debug(f"Created container {self.container_name} [{node_container_image}]")

    def setup(self, use_links=False):
        src_path = os.path.join(self.binary_dir, NODE_STARTUP_WRAPPER_SCRIPT)
        super().setup(use_links=use_links)
        super().cp(src_path, self.root)

    def start(self):
        LOG.info(self.command)
        self.container.start()
        self.container.reload()  # attrs are cached
        self.container_ip = self.container.attrs["NetworkSettings"]["Networks"][
            self.network.name
        ]["IPAddress"]
        for _, rpc_interface in self.host.rpc_interfaces.items():
            rpc_interface.public_host = self.container_ip
        self.hostname = self.container_ip
        LOG.debug(f"Started container {self.container_name} [{self.container_ip}]")

    def stop(self):
        try:
            self.container.stop()
            LOG.info(f"Stopped container {self.container.name}")
        except docker.errors.NotFound:
            pass

    def suspend(self):
        self.container.pause()

    def resume(self):
        self.container.unpause()

    def check_done(self):
        try:
            self.container.reload()
            LOG.debug(self.container.attrs["State"])
            return self.container.attrs["State"]["Status"] != "running"
        except docker.errors.NotFound:
            return True
