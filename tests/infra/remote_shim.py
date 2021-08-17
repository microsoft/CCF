# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import docker
import infra.remote

from loguru import logger as LOG

# TODO: Host and RPC port should be stored somewhere else!
class PassThroughShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.rpc_port = kwargs.get("rpc_port", None)
        self.host = kwargs.get("host", None)

        super().__init__(*args, **kwargs)

    def get_host(self):
        return self.host

    def get_rpc_port(self):
        return self.rpc_port


# TODO: This class should handle:
# 1. Volume mapping with permissions
# 2. IP address and port mapping
# 3.


class DockerShim(infra.remote.CCFRemote):
    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()
        self.node_port = kwargs.get("node_port", None)
        self.rpc_port = kwargs.get("rpc_port", None)

        LOG.error(f"DockerShim: rpc_port: {self.rpc_port}")

        self.host = kwargs.get("host", None)
        LOG.error(f"Host: {self.host}")

        kwargs["host"] = "0.0.0.0"
        super().__init__(*args, **kwargs)

        LOG.error(self.remote.get_cmd())

        self.container = self.docker_client.containers.create(
            "ccfciteam/ccf-ci:oe0.17.1-focal-docker",
            volumes={
                "/home/jumaffre/git/CCF/build/": {
                    "bind": "/home/jumaffre/git/CCF/build",
                    "mode": "rw",
                }
            },
            command=f'bash -c "{self.remote.get_cmd()}"',
            ports={
                f"{self.rpc_port}/tcp": (self.host, self.rpc_port),
                f"{self.node_port}/tcp": (self.host, self.node_port),
            },
            detach=True,
        )

    def start(self):
        self.container.start()
        self.docker_client.api.inspect_container(self.container.id)["NetworkSettings"][
            "IPAddress"
        ]
        LOG.error(
            self.docker_client.api.inspect_container(self.container.id)[
                "NetworkSettings"
            ]["Ports"]
        )

    # TODO: This doesn't seem to work, as SIGTERM isn't sent down to cchost
    def stop(self):
        LOG.error("Stopping container...")
        self.container.stop()
        LOG.success("Container stopped")
        return None, None

    def get_host(self):
        return self.host

    def get_rpc_port(self):
        return self.rpc_port

