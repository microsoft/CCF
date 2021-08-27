# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.remote
import docker
import re
import os
import pathlib
import grp
import ipaddress

from loguru import logger as LOG


def is_docker_env():
    """Returns true if the process executing _this_ code already runs inside Docker"""
    return os.path.isfile("/.dockerenv")


def is_azure_devops_env():
    return "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


def map_azure_devops_docker_workspace_dir(workspace_dir):
    return workspace_dir.replace("__w", "/mnt/vss/_work")


# Network name
AZURE_DEVOPS_CONTAINER_NETWORK_ENV_VAR = "AGENT_CONTAINERNETWORK"
DOCKER_NETWORK_NAME_LOCAL = "ccf_test_docker_network"


def kernel_has_sgx_builtin():
    with open("/proc/cpuinfo", "r") as cpu_info:
        filter = re.compile("^flags.*sgx.*")
        for line in cpu_info:
            if filter.match(line):
                return True
    return False


class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.DockerClient()

        rpc_host = kwargs.get("rpc_host")
        label = kwargs.get("label")
        rpc_port = kwargs.get("rpc_port")
        local_node_id = kwargs.get("local_node_id")

        # Create network to connect all containers to (for n2n communication, etc.).
        # In a Docker environment, use existing network (either the one
        # provided by ADO or the one already created by the runner).
        # Otherwise, create network on the fly.
        if is_docker_env():
            self.network = self.docker_client.networks.get(
                os.environ(AZURE_DEVOPS_CONTAINER_NETWORK_ENV_VAR)
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

        # Pre-determine IP address of container based on network.
        # This is necessary since the CCF node needs to bind to known addresses
        # at start-up, and the container IP address is not known until the container
        # is started.
        # TODO: Can we construct the cchost command after the IP address is known?
        ip_address_offset = 2 if is_docker_env() else 1
        self.container_ip = str(
            ipaddress.ip_address(self.network.attrs["IPAM"]["Config"][0]["Gateway"])
            + local_node_id
            + ip_address_offset
        )

        LOG.debug(f"Network {self.network.name} [{self.container_ip}]")

        # Bind local RPC address to 0.0.0.0, so it be can be accessed from outside container
        kwargs["rpc_host"] = "0.0.0.0"
        if is_docker_env():
            kwargs["pub_host"] = self.container_ip
        kwargs["node_host"] = self.container_ip

        # Expose port to clients running on host if not already in a container
        ports = (
            {f"{rpc_port}/tcp": (rpc_host, rpc_port)} if not is_docker_env() else None
        )

        super().__init__(*args, **kwargs)

        # Sanitise container name from remote name, replacing illegal
        # characters with underscores
        self.container_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.name)

        # TODO: Move this elsewhere as we need to be sure that containers are stopped before using IP addresses
        # Stop and delete existing container
        try:
            # First container with this label stops all other matching containers
            if local_node_id == 0:
                for c in self.docker_client.containers.list(filters={"label": [label]}):
                    LOG.debug(f"Stopping existing container {c.name}")
                    c.stop()

            c = self.docker_client.containers.get(self.container_name)
            c.stop()
            LOG.debug(f"Stopped container {self.container_name}")
        except docker.errors.NotFound:
            pass

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
            devices = ["dev/sgx"] if os.path.isdir("dev/sgx") else None

        # Mount workspace volume
        cwd = str(pathlib.Path().resolve())
        cwd_host = (
            map_azure_devops_docker_workspace_dir(cwd) if is_azure_devops_env() else cwd
        )

        self.container = self.docker_client.containers.create(
            "ccfciteam/ccf-ci:oe0.17.1-focal-docker",  # TODO: Make configurable
            volumes={cwd_host: {"bind": cwd, "mode": "rw"}},
            devices=devices,
            command=f'bash -c "exec {self.remote.get_cmd(include_dir=False)}"',
            ports=ports,
            name=self.container_name,
            labels=[label],
            user=f"{os.getuid()}:{gid}",
            working_dir=self.remote.root,
            detach=True,
            auto_remove=True,  # Container is automatically removed on stop
        )

        self.network.connect(self.container)
        LOG.debug(f"Created container {self.container_name}")

    def start(self):
        LOG.info(self.remote.get_cmd())
        self.container.start()
        LOG.debug(f"Started container {self.container_name}")

    def stop(self):
        try:
            self.container.stop()
            LOG.debug(f"Stopped container {self.container_name}")
        except docker.errors.NotFound:
            pass

        # So prune all unusued networks instead.
        # if (
        #     deleted_networks := self.docker_client.networks.prune()["NetworksDeleted"]
        # ) is not None:
        #     LOG.debug(f"Deleted network {deleted_networks}")
        return self.remote.get_logs()

    def get_target_rpc_host(self):
        return self.container_ip
