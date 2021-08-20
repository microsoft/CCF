# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.remote
import docker
import re
import os
import pathlib
import grp
import ipaddress
import json

from loguru import logger as LOG

# Azure Pipelines specific
def is_env_docker_in_docker():
    return "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


DOCKER_NETWORK_PREFIX_ADO = "vsts_network"


######

DOCKER_NETWORK_NAME_LOCAL = "ccf_test_docker_network"


class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.DockerClient(base_url="unix://var/run/docker.sock")

        LOG.error(json.dumps(self.docker_client.info(), indent=2))

        self.label = kwargs.get("label")
        rpc_host = kwargs.get("rpc_host")
        self.rpc_port = kwargs.get("rpc_port")
        self.node_port = kwargs.get("node_port")
        self.local_node_id = kwargs.get("local_node_id")
        self.pub_host = kwargs.get("pub_host")

        # Create network shared by all containers in the same test
        # or in a ADO environment, use existing network
        if is_env_docker_in_docker():
            for network in self.docker_client.networks.list():
                if network.name.startswith(DOCKER_NETWORK_PREFIX_ADO):
                    self.network = network
                    break
        else:
            self.network = self.docker_client.networks.create(DOCKER_NETWORK_NAME_LOCAL)

        if self.network is None:
            raise ValueError("No network configured to start containers")

        LOG.debug(f"Using network {self.network.name}")
        LOG.error(json.dumps(self.network.attrs, indent=2))

        # First IP address is reserved for parent container
        # Find IP of container to be created
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
        running_as_user = f"{os.getuid()}:{os.getgid()}"
        cwd = str(pathlib.Path().resolve())
        LOG.error(f"cwd: {cwd}")
        LOG.debug(f"Running as user: {running_as_user}")

        # Expose port to clients running on host if not already in a container
        ports = (
            {f"{self.rpc_port}/tcp": (rpc_host, self.rpc_port)}
            if not is_env_docker_in_docker()
            else None
        )

        self.docker_client.images.pull("hello-world")
        self.container = self.docker_client.containers.create(
            "hello-world",  # TODO: Make configurable
            volumes={cwd: {"bind": cwd, "mode": "rw"}},
            # devices=devices,
            # command=f'bash -c "exec {self.remote.get_cmd(include_dir=False)}"',
            # ports=ports,
            name=self.container_name,
            user=running_as_user,
            working_dir=self.remote.root,
            detach=True,
            # auto_remove=True,  # Container is automatically removed on stop
        )

        self.network.connect(self.container)
        LOG.debug(f"Created container {self.container_name}")

    def start(self):
        LOG.info(self.remote.get_cmd())
        self.container.start()
        for l in self.container.logs(stream=True):
            LOG.debug(l.strip())
        LOG.debug(f"Started container {self.container_name}")

    def stop(self):
        try:
            self.container.stop()
            LOG.debug(f"Stopped container {self.container_name}")
        except docker.errors.NotFound:
            pass

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
