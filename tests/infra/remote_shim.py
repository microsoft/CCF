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


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()

        rpc_host = kwargs.get("rpc_host")
        self.rpc_port = kwargs.get("rpc_port")
        self.node_port = kwargs.get("node_port")
        self.local_node_id = kwargs.get("local_node_id")

        LOG.warning(f"Local node id: {self.local_node_id}")
        # LOG.warning(f"Host: {self.host}")
        LOG.warning(f"Rpc port: {self.rpc_port}")
        LOG.warning(f"Node port: {self.node_port}")

        # TODO: Do we really need to port in advance? I think so, because of node-to-node connections
        self.container_ip = str(
            ipaddress.ip_address(
                self.docker_client.api.inspect_network("vsts_network")["IPAM"][
                    "Config"
                ][0]["Gateway"]
            )
            + self.local_node_id
            + 1
        )

        kwargs["rpc_host"] = "0.0.0.0"
        kwargs["node_host"] = self.container_ip

        super().__init__(*args, **kwargs)

        # Sanitise container name from remote name, replacing illegal
        # characters with underscores
        self.container_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.name)

        # Stop and delete existing container, if it exists
        try:
            c = self.docker_client.containers.get(self.container_name)
            c.stop()
            c.remove()
        except docker.errors.NotFound:
            pass

        LOG.error(self.remote.get_cmd(include_dir=False))
        cwd = str(pathlib.Path().resolve())
        LOG.error(f"cwd: {cwd}")

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
        LOG.info(f"Running as user: {running_as_user}")

        self.container = self.docker_client.containers.create(
            "ccfciteam/ccf-ci:oe0.17.1-focal-docker",
            volumes={cwd: {"bind": cwd, "mode": "rw"}},
            devices=devices,
            command=f'bash -c "exec {self.remote.get_cmd(include_dir=False)}"',
            ports={f"{self.rpc_port}/tcp": (rpc_host, self.rpc_port)},
            name=self.container_name,
            user=running_as_user,
            working_dir=self.remote.root,
            detach=True,
            # auto_remove=True,  # Container is automatically removed on stop
        )

        self.docker_client.networks.get("vsts_network").connect(
            self.container
        )  # , ipv4_address=self.container_ip
        # )

        LOG.error(f"IP: {self.container_ip}")

        LOG.error(f"Container: {self.container}")
        LOG.error(f"Container id: {self.container.name}")

    def start(self):
        LOG.warning("Container start")
        self.container.start()
        self.container_ip = self.docker_client.api.inspect_container(self.container.id)[
            "NetworkSettings"
        ]["Networks"]["vsts_network"]["IPAddress"]
        LOG.warning(f"Container IP: {self.container_ip}")
        # input("")
        # LOG.success(self.container.attrs)
        # LOG.success(self.container.status)
        # LOG.success(self.container.top())
        # input("Lala")

    def stop(self):
        LOG.error(f"Stopping container {self.container_name}...")
        self.container.stop()
        LOG.success("Container stopped")
        return self.remote.get_logs()

    def get_rpc_host(self):
        return self.container_ip

