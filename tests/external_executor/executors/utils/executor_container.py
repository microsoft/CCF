# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
import os
import threading
import docker
import time
from infra.docker_env import map_workspace_if_azure_devops

from typing import Set, Tuple
from infra.network import Network
from infra.node import Node

from loguru import logger as LOG

DEFAULT_EXTERNAL_EXECUTOR_IMAGE_PYTHON = "mcr.microsoft.com/cbl-mariner/base/python:3"


CCF_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..")
)


class ExecutorContainer:
    _executors_count = {}

    def print_container_logs(self):
        for line in self._container.logs(stream=True):
            LOG.info(f"[CONTAINER - {self._name}] {line}")

    def __init__(
        self,
        executor: str,
        node: Node,
        network: Network,
        supported_endpoints: Set[Tuple[str, str]],
    ):
        self._client = docker.from_env()
        self._node = node
        self._supported_endpoints = supported_endpoints
        self._thread = None
        if executor not in self._executors_count:
            self._executors_count[executor] = 0
        else:
            self._executors_count[executor] += 1

        self._name = f"{executor}_{self._executors_count[executor]}"

        image_name = DEFAULT_EXTERNAL_EXECUTOR_IMAGE_PYTHON
        LOG.debug(f"Pulling image {image_name}")
        self._client.images.pull(image_name)

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        command = "pip install --upgrade pip &&"
        command += " pip install -r /executor/requirements.txt &&"
        command += " python3 /executor/run_executor.py"
        command += f' --executor "{executor}"'
        command += f' --node-public-rpc-address "{node.get_public_rpc_address()}"'
        command += ' --network-common-dir "/executor/ccf_network"'
        command += f' --supported-endpoints "{",".join([":".join(e) for e in supported_endpoints])}"'
        LOG.debug(f"Creating container with command: {command}")

        self._container = self._client.containers.create(
            image=image_name,
            name="",
            command=f'bash -exc "{command}"',
            volumes={
                map_workspace_if_azure_devops(
                    os.path.join(CCF_DIR, "tests/external_executor")
                ): {
                    "bind": "/executor",
                    "mode": "rw",
                },
                map_workspace_if_azure_devops(os.path.join(CCF_DIR, "tests/infra")): {
                    "bind": "/executor/infra",
                    "mode": "rw",
                },
                map_workspace_if_azure_devops(network.common_dir): {
                    "bind": "/executor/ccf_network",
                    "mode": "rw",
                },
            },
            publish_all_ports=True,
            auto_remove=True,
        )

        self._node.remote.network.connect(self._container)

    def start(self):
        LOG.debug(f"Starting container {self._name}...")
        # self._thread = threading.Thread(target=self.print_container_logs)
        self._container.start()
        # self._thread.start()
        LOG.info(f"Container {self._name} started")

    # Default timeout is temporarily so high so we can install deps
    def wait_for_registration(self, timeout=30):
        # Endpoint may return 404 for reasons other than that the executor is
        # not yet registered, so check for an exact message that the endpoint
        # path is unknown
        with self._node.client() as client:
            e_verb, e_path = next(e for e in self._supported_endpoints if e[0] == "GET")
            end_time = time.time() + timeout
            while time.time() < end_time:
                r = client.call(http_verb=e_verb, path=e_path)
                body = r.body.json()
                if (
                    r.status_code == 404
                    and "error" in body
                    and body["error"] == f"Unknown path: {e_path}."
                ):
                    time.sleep(1)
                    continue
                else:
                    LOG.success(f"Container successfully {self._name} registered")
                    return
        raise TimeoutError(f"Executor did not register within {timeout} seconds")

    def terminate(self):
        LOG.debug(f"Terminating container {self._name}...")
        self._container.stop()
        # self._thread.join()
        LOG.info(f"Container {self._name} stopped")


@contextmanager
def executor_container(
    executor: str,
    node: Node,
    network: Network,
    supported_endpoints: Set[Tuple[str, str]],
):
    ec = ExecutorContainer(
        executor,
        node,
        network,
        supported_endpoints,
    )
    ec.start()
    ec.wait_for_registration()
    yield
    ec.terminate()
