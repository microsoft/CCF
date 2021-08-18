# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.remote
import docker
import pathlib
import os

from loguru import logger as LOG

# TODO: Host and RPC port should be stored somewhere else!
class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


# TODO: This class should handle:
# 1. Volume mapping with permissions
# 2. IP address and port mapping: Done with network_mode="host" (no need for port mapping)


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()

        super().__init__(*args, **kwargs)

        LOG.error(self.remote.get_cmd(include_dir=False))
        cwd = str(pathlib.Path().resolve())

        running_as_user = f"{os.getuid()}:{os.getgid()}"
        LOG.info(f"Running as user: {running_as_user}")

        self.container = self.docker_client.containers.create(
            "ccfciteam/ccf-ci:oe0.17.1-focal-docker",
            volumes={cwd: {"bind": cwd, "mode": "rw"}},
            command=f'bash -c "exec {self.remote.get_cmd(include_dir=False)}"',
            network_mode="host",
            name=self.name,
            user=running_as_user,
            working_dir=self.remote.root,
            detach=True,
        )

    def start(self):
        self.container.start()
        self.docker_client.api.inspect_container(self.container.id)["NetworkSettings"][
            "IPAddress"
        ]

    # TODO: This doesn't seem to work, as SIGTERM isn't sent down to cchost
    def stop(self):
        LOG.error(f"Stopping container {self.name}...")
        self.container.stop()
        LOG.success("Container stopped")
        # TODO: Logs
        return None, None

