# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import time
import docker
import threading
from contextlib import contextmanager
from typing import Optional

from loguru import logger as LOG
from abc import ABC, abstractmethod

from infra.network import Network


class Executor(ABC):
    @abstractmethod
    def __init__(self, node_public_rpc_address: str) -> None:
        ...

    @abstractmethod
    def run_loop(self, activated_event: threading.Event) -> None:
        ...

    @abstractmethod
    def terminate(self) -> None:
        ...


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
        network: Network,
        supported_endpoints: str,
    ):
        self._client = docker.DockerClient()

        image_name = "ccfmsrc.azurecr.io/ccf/ci:14-02-2023-virtual"
        LOG.info(f"Pulling image {image_name}")
        self._client.images.pull(image_name)

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        command = "/workspaces/CCF/build/env/bin/python3"
        command += " /workspaces/CCF/tests/external_executor/run_executor.py"
        command += f' --executor "{executor}"'
        command += f' --node-public-rpc-address "{node_public_rpc_address}"'
        command += f' --network-common-dir "{network.common_dir}"'
        command += f' --supported-endpoints "{supported_endpoints}"'
        LOG.info(f"Creating container with command: {command}")
        self._container = self._client.containers.create(
            image=image_name,
            command=command,
            volumes={
                "/workspaces/CCF": {
                    "bind": "/workspaces/CCF",
                    "mode": "rw",
                }
            },
            publish_all_ports=True,
            auto_remove=True,
        )

        LOG.info("Connecting container to network")
        self._network = self._client.networks.get("ccf_test_docker_network")
        self._network.connect(self._container)

    def start(self):
        LOG.info("Starting container...")
        self._container.start()
        time.sleep(2)
        LOG.info("Done")

    def terminate(self):
        LOG.info("Terminating container...")
        self._container.stop()
        LOG.info("Done")


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
