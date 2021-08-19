# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.remote
import docker
import re
import os
import pathlib
import grp

from loguru import logger as LOG


class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()

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
        try:
            sgx_prv_group = grp.getgrnam("sgx_prv")
            gid = sgx_prv_group.gr_gid
        except KeyError:
            gid = os.getgid()

        running_as_user = f"{os.getuid()}:{gid}"
        LOG.info(f"Running as user: {running_as_user}")

        self.container = self.docker_client.containers.create(
            "ccfciteam/ccf-ci:oe0.17.1-focal-docker",
            volumes={cwd: {"bind": cwd, "mode": "rw"}},
            devices=["/dev/sgx/enclave", "/dev/sgx/provision"],
            command=f'bash -c "exec {self.remote.get_cmd(include_dir=False)}"',
            network_mode="host",  # Share network with host, to avoid port mapping
            name=self.container_name,
            user=running_as_user,
            working_dir=self.remote.root,
            detach=True,
            auto_remove=True,  # Container is automatically removed on stop
        )
        LOG.error(f"Container: {self.container}")
        LOG.error(f"Container id: {self.container.name}")
        for line in self.container.logs():
            LOG.error(line)

    def start(self):
        LOG.warning("Container start")
        self.container.start()
        LOG.success(self.container.status)
        LOG.success(self.container.top())

    def stop(self):
        LOG.error(f"Stopping container {self.container_name}...")
        self.container.stop()
        LOG.success("Container stopped")
        return self.remote.get_logs()

