# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
import os
import docker
import time

from typing import Set, Tuple
from infra.network import Network
from infra.node import Node

from loguru import logger as LOG


class ExecutorContainer:
    def __init__(
        self,
        executor: str,
        node: Node,
        network: Network,
        supported_endpoints: Set[Tuple[str, str]],
    ):
        self._client = docker.DockerClient()
        self._node = node
        self._supported_endpoints = supported_endpoints

        image_name = "mcr.microsoft.com/cbl-mariner/base/python:3"
        LOG.info(f"Pulling image {image_name}")
        self._client.images.pull(image_name)

        # Assemble a temporary directory to place code that will be loaded into
        # the container
        ccf_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
        )

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        command = "pip install --upgrade pip &&"
        command += " pip install -r /executor/external_executor/requirements.txt &&"
        command += " python3 /executor/external_executor/run_executor.py"
        command += f' --executor "{executor}"'
        command += f' --node-public-rpc-address "{node.get_public_rpc_address()}"'
        command += ' --network-common-dir "/ccf_network"'
        command += f' --supported-endpoints "{",".join([":".join(e) for e in supported_endpoints])}"'
        LOG.info(f"Creating container with command: {command}")
        self._container = self._client.containers.create(
            image=image_name,
            command=f'bash -exc "{command}"',
            volumes={
                os.path.join(ccf_dir, "tests/external_executor"): {
                    "bind": "/executor/external_executor",
                    "mode": "rw",
                },
                os.path.join(ccf_dir, "tests/infra"): {
                    "bind": "/executor/external_executor/infra",
                    "mode": "rw",
                },
                network.common_dir: {
                    "bind": "/ccf_network",
                    "mode": "rw",
                },
            },
            publish_all_ports=True,
            auto_remove=True,
        )

        LOG.info("Connecting container to network")
        self._node.remote.network.connect(self._container)

    def start(self):
        LOG.info("Starting container...")
        LOG.info(f"{self._container.start()=}")
        time.sleep(40)
        LOG.info(f"Container logs: {self._container.logs()}")
        LOG.info("Done")

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
                try:
                    assert (
                        r.body.json()["error"]["message"] == f"Unknown path: {e_path}."
                    )
                except Exception:
                    LOG.info("Done")
                    LOG.info(f"Container logs: {self._container.logs()}")
                    return
                time.sleep(1)
        LOG.info(f"Container logs: {self._container.logs()}")
        raise TimeoutError(f"Executor did not register within {timeout} seconds")

    def terminate(self):
        LOG.info("Terminating container...")
        self._container.stop()
        LOG.info("Done")


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
