# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import time
import docker
import os
import threading
from contextlib import contextmanager
from typing import Optional

from loguru import logger as LOG

from infra.network import Network


class Executor:

    FILE: str

    def __init__(self, node_public_rpc_address: str) -> None:
        self.node_public_rpc_address = node_public_rpc_address

    def run_loop(self, activated_event: threading.Event) -> None:
        raise NotImplementedError()

    def terminate(self) -> None:
        raise NotImplementedError()


class ExecutorThread:
    def __init__(self, executor: Executor):
        self.executor = executor
        self.thread: Optional[threading.Thread] = None
        self.activated_event: Optional[threading.Event] = None

    def start(self):
        assert self.thread == None, "Already started"
        LOG.info("Starting executor")
        self.activated_event = threading.Event()
        self.thread = threading.Thread(
            target=self.executor.run_loop, args=(self.activated_event,)
        )
        self.thread.start()
        assert self.activated_event.wait(
            timeout=3
        ), "Executor failed to activate after 3 seconds"

    def terminate(self):
        assert self.thread != None, "Already terminated"
        LOG.info("Terminating executor")
        self.executor.terminate()
        self.thread.join()
        self.thread = None


@contextmanager
def executor_thread(executor: Executor):
    et = ExecutorThread(executor)
    et.start()
    yield executor
    et.terminate()


class ExecutorContainer:
    def __init__(
        self,
        executor: str,
        node_public_rpc_address: str,
        network_common_dir: str,
        supported_endpoints: str,
    ):
        self._client = docker.DockerClient()

        image_name = "ccfmsrc.azurecr.io/ccf/ci:14-02-2023-virtual"
        self._client.images.pull(image_name)

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        commands = [
            f'/workspaces/CCF/build/env/bin/python3 /workspaces/CCF/tests/external_executor/run_executor.py --executor "{executor}" --node-public-rpc-address "{node_public_rpc_address}" --network-common-dir "{network_common_dir}" --supported-endpoints "{supported_endpoints}"',
        ]
        print("Running container with command", commands)
        self._container = self._client.containers.create(
            image=image_name,
            command=" && ".join(commands),
            volumes={
                "/workspaces/CCF": {
                    "bind": "/workspaces/CCF",
                    "mode": "rw",
                }
            },
            # init=True,
            publish_all_ports=True,
            # detach=False,
            auto_remove=True,
            # entrypoint="/bin/bash",
        )

        print("Created container")
        self._network = self._client.networks.get("ccf_test_docker_network")
        self._network.connect(self._container)

    def start(self):
        self._container.start()
        self._container.reload()  # attrs are cached

        print(
            "Started container",
            self._container.attrs["NetworkSettings"]["Networks"][
                "ccf_test_docker_network"
            ]["IPAddress"],
        )
        print(self._container.attrs["State"])
        print(self._container.logs())
        time.sleep(2)

    def terminate(self):
        print("Terminating container")
        print(self._container.logs())


@contextmanager
def executor_container(
    executor: str,
    node_public_rpc_address: str,
    network: Network,
    supported_endpoints: str,
):
    ec = ExecutorContainer(
        executor,
        node_public_rpc_address,
        network,
        supported_endpoints,
    )
    ec.start()
    yield "Something"
    ec.terminate()
