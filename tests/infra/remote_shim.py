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


class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def is_env_docker_in_docker():
    return "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()

        self.label = kwargs.get("label")
        rpc_host = kwargs.get("rpc_host")
        self.rpc_port = kwargs.get("rpc_port")
        self.node_port = kwargs.get("node_port")
        self.local_node_id = kwargs.get("local_node_id")
        self.pub_host = kwargs.get("pub_host")

        # Create network shared by all containers in the same test
        # TODO: Detect network name!
        self.network = self.docker_client.networks.get("vsts_network")
        LOG.warning(f"Using network: vsts_network")

        # First IP address is reserved for parent container
        ip_address_offset = 2 if is_env_docker_in_docker() else 1
        self.container_ip = str(
            ipaddress.ip_address(self.network.attrs["IPAM"]["Config"][0]["Gateway"])
            + self.local_node_id
            + ip_address_offset
        )

        LOG.error(f"Container ip: {self.container_ip}")

        kwargs["rpc_host"] = "0.0.0.0"

        if is_env_docker_in_docker():
            kwargs["pub_host"] = self.container_ip

        kwargs["node_host"] = self.container_ip

        super().__init__(*args, **kwargs)

        # Sanitise container name from remote name, replacing illegal
        # characters with underscores
        self.container_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.name)

        # Stop and delete existing container, if it exists
        try:
            # TODO: If local_node_id is 0, also stop all other containers with that label!
            c = self.docker_client.containers.get(self.container_name)
            c.stop()
            c.remove()  # TODO: Delete
            LOG.debug(f"Stopped container {self.container_name}")
        except docker.errors.NotFound:
            pass

        # TODO: Cheeky to get real enclave working on 5.11, at the cost of having all files created in sgx_prv group
        # try:
        #     sgx_prv_group = grp.getgrnam("sgx_prv")  # TODO: Doesn't work
        #     # >= 5.11 kernel
        #     gid = sgx_prv_group.gr_gid
        #     devices = ["/dev/sgx/enclave", "/dev/sgx/provision"]
        # except KeyError:
        #     # # < 5.11 kernel
        #     # gid = os.getgid()
        #     # devices = ["/dev/sgx"]

        devices = None
        running_as_user = f"{os.getuid()}:{119}"
        cwd = str(pathlib.Path().resolve())
        LOG.debug(f"Running as user: {running_as_user}")

        # Expose port to clients running on host if not already in a container
        ports = (
            {f"{self.rpc_port}/tcp": (rpc_host, self.rpc_port)}
            if not is_env_docker_in_docker()
            else None
        )

        self.container = self.docker_client.containers.create(
            "ccfciteam/ccf-ci:oe0.17.1-focal-docker",  # TODO: Make configurable
            volumes={cwd: {"bind": cwd, "mode": "rw"}},
            devices=devices,
            command=f'bash -c "exec {self.remote.get_cmd(include_dir=False)}"',
            ports=ports,
            name=self.container_name,
            user=running_as_user,
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
        # self.container.stop()
        # LOG.debug(f"Stopped container {self.container_name}")

        # Deletings networks by label doesn't seem to work (see https://github.com/docker/docker-py/issues/2611).
        # So prune all unusued networks instead.
        # if (
        #     deleted_networks := self.docker_client.networks.prune()["NetworksDeleted"]
        # ) is not None:
        #     LOG.debug(f"Deleted network {deleted_networks}")
        return self.remote.get_logs()

    def get_rpc_host(self):
        return self.container_ip if is_env_docker_in_docker() else self.pub_host

    def get_target_rpc_host(self):
        return self.container_ip
