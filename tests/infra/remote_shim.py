# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.remote
import docker
import re
import os
import pathlib
import grp
import ipaddress
import infra.github


from loguru import logger as LOG


def is_docker_env():
    """Returns true if the process executing _this_ code already runs inside Docker"""
    return os.path.isfile("/.dockerenv")


def is_azure_devops_env():
    return "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


def map_azure_devops_docker_workspace_dir(workspace_dir):
    return workspace_dir.replace("__w", "/mnt/vss/_work")


# Docker image name prefix
DOCKER_IMAGE_NAME_PREFIX = "ccfciteam/ccf-app-run"

# Network name
AZURE_DEVOPS_CONTAINER_NETWORK_ENV_VAR = "AGENT_CONTAINERNETWORK"
DOCKER_NETWORK_NAME_LOCAL = "ccf_test_docker_network"

# Identifier for all CCF test containers
CCF_TEST_CONTAINERS_LABEL = "ccf_test"


def kernel_has_sgx_builtin():
    with open("/proc/cpuinfo", "r", encoding="utf-8") as cpu_info:
        f = re.compile("^flags.*sgx.*")
        for line in cpu_info:
            if f.match(line):
                return True
    return False


class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


# Current limitations, which should be overcomable:
# 1. No support for SGX kernel built-in support (i.e. 5.11+ kernel) in Docker environment
# 2. No support for concurrent test: all nodes containers attach to the same network at pre-defined IPs
class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.DockerClient()

        label = kwargs.get("label")
        local_node_id = kwargs.get("local_node_id")
        ccf_version = kwargs.get("version")

        # Sanitise container name, replacing illegal characters with underscores
        self.container_name = f"{label}_{local_node_id}"
        self.container_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.container_name)

        # Create network to connect all containers to (for n2n communication, etc.).
        # In a Docker environment, use existing network (either the one provided by
        # ADO or the one already created by the runner).
        # Otherwise, create network on the fly.
        if is_docker_env():
            self.network = self.docker_client.networks.get(
                os.environ[AZURE_DEVOPS_CONTAINER_NETWORK_ENV_VAR]
                if is_azure_devops_env()
                else DOCKER_NETWORK_NAME_LOCAL
            )
        else:
            try:
                self.network = self.docker_client.networks.get(
                    DOCKER_NETWORK_NAME_LOCAL
                )
            except docker.errors.NotFound:
                self.network = self.docker_client.networks.create(
                    DOCKER_NETWORK_NAME_LOCAL
                )

        # Stop and delete existing container(s)
        try:
            if local_node_id == 0:
                for c in self.docker_client.containers.list(
                    all=True, filters={"label": CCF_TEST_CONTAINERS_LABEL}
                ):
                    c.stop()
                    c.remove()
                    LOG.debug(f"Stopped existing container {c.name}")
            c = self.docker_client.containers.get(self.container_name)
            c.stop()
            LOG.debug(f"Stopped container {self.container_name}")
        except docker.errors.NotFound:
            pass

        # Pre-determine IP address of container based on network.
        # This is necessary since the CCF node needs to bind to known addresses
        # at start-up, and the container IP address is not known until the container
        # is started.
        ip_address_offset = 2 if is_docker_env() else 1  # Not ideal...
        self.container_ip = str(
            ipaddress.ip_address(self.network.attrs["IPAM"]["Config"][0]["Gateway"])
            + local_node_id
            + ip_address_offset
        )

        LOG.debug(f"Network {self.network.name} [{self.container_ip}]")

        # Bind local RPC address to 0.0.0.0, so it be can be accessed from outside container
        kwargs["rpc_host"] = "0.0.0.0"
        kwargs["pub_host"] = self.container_ip
        kwargs["node_host"] = self.container_ip

        super().__init__(*args, **kwargs)

        # Group and device for kernel sgx builtin support (or not)
        # TODO: Does not quite yet work locally inside docker (file permission issues, and cannot connect to docker daemon)
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
        image_name = f"{DOCKER_IMAGE_NAME_PREFIX}:"
        if ccf_version is not None:
            image_name += ccf_version
        else:
            image_name += infra.github.strip_release_tag_name(repo.get_latest_dev_tag())

        try:
            self.docker_client.images.get(image_name)
        except docker.errors.ImageNotFound:
            LOG.info(f"Pulling image {image_name}")
            self.docker_client.images.pull(image_name)

        self.command = f'./docker_wrap.sh "{self.remote.get_cmd(include_dir=False)}"'

        self.container = self.docker_client.containers.create(
            image_name,
            volumes={cwd_host: {"bind": cwd, "mode": "rw"}},
            devices=devices,
            command=self.command,
            name=self.container_name,
            labels=[label, CCF_TEST_CONTAINERS_LABEL],
            publish_all_ports=True,
            user=f"{os.getuid()}:{gid}",
            working_dir=self.remote.root,
            detach=True,
            auto_remove=True,  # Container is automatically removed on stop
        )

        self.network.connect(self.container)
        LOG.debug(f"Created container {self.container_name} [{image_name}]")

    def setup(self):
        src_path = os.path.join(self.binary_dir, "docker_wrap.sh")
        self.remote.setup()
        self.remote.cp(src_path, self.remote.root)

    def start(self):
        LOG.info(self.command)
        self.container.start()

        LOG.debug(f"Started container {self.container_name}")

    def stop(self):
        try:
            self.container.stop()
            LOG.debug(f"Stopped container {self.container_name}")
        except docker.errors.NotFound:
            pass
        return self.remote.get_logs()
