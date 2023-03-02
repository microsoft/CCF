# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
import os
import threading
import docker
import time
from infra.docker_env import map_workspace_if_azure_devops
from base64 import b64encode
from pathlib import Path

from typing import Set, Tuple
from infra.network import Network
from infra.node import Node

from loguru import logger as LOG


CCF_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..")
)


class ExecutorContainer:
    _executors_count = {}

    def print_container_logs(self):
        with open(os.path.join(self._dir, "out"), "a") as log_file:
            for line in self._container.logs(stream=True):
                log_file.write(f"{str(line)}\n")
                log_file.flush()

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
        self._dir = os.path.join(self._node.remote.remote.root, self._name)

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        self._image_name = executor
        LOG.debug(f"Building image {self._image_name }...")
        self._client.images.build(
            path=os.path.join(CCF_DIR, "tests/external_executor/executors"),
            tag=self._image_name,
            rm=True,
            dockerfile="Dockerfile",
        )
        LOG.info(f"Image {self._image_name } built")

        # Kill container in case it still exists from a previous interrupted run
        for c in self._client.containers.list(all=True, filters={"name": [self._name]}):
            c.stop()
            c.remove()

        service_certificate_bytes = open(
            os.path.join(network.common_dir, "service_cert.pem"), "rb"
        ).read()

        self._container = self._client.containers.create(
            image=self._image_name,
            name=self._name,
            environment={
                "CCF_CORE_NODE_RPC_ADDRESS": node.get_public_rpc_address(),
                "CCF_CORE_SERVICE_CERTIFICATE": b64encode(service_certificate_bytes),
            },
            volumes={},
            publish_all_ports=True,
            auto_remove=True,
        )
        self._node.remote.network.connect(self._container)

        Path(self._dir).mkdir(parents=True, exist_ok=True)

    def start(self):
        LOG.debug(f"Starting container {self._name}...")
        self._thread = threading.Thread(target=self.print_container_logs)
        self._container.start()
        self._thread.start()
        LOG.info(f"Container {self._name} started")

    def wait_for_registration(self, timeout=10):
        # Endpoint may return 404 for reasons other than that the executor is
        # not yet registered, so check for an exact message that the endpoint
        # path is unknown
        with self._node.client() as client:
            e_verb, e_path = next(e for e in self._supported_endpoints if e[0] == "GET")
            end_time = time.time() + timeout
            while time.time() < end_time:
                r = client.call(http_verb=e_verb, path=e_path)
                try:
                    assert (
                        r.body.json()["error"]["message"] == f"Unknown path: {e_path}."
                    )
                except Exception:
                    LOG.success(f"Container successfully {self._name} registered")
                    return
                else:
                    time.sleep(1)
                    continue
        raise TimeoutError(f"Executor did not register within {timeout} seconds")

    def terminate(self):
        LOG.debug(f"Terminating container {self._name}...")
        self._container.stop()
        self._thread.join()
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
