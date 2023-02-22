# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
import os
import shutil
import docker
import tempfile
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
        directory: str,
    ):
        self._client = docker.DockerClient()
        self._node = node
        self._supported_endpoints = supported_endpoints

        image_name = "ccfmsrc.azurecr.io/ccf/ci:14-02-2023-virtual"
        LOG.info(f"Pulling image {image_name}")
        self._client.images.pull(image_name)

        # Assemble a temporary directory to place code that will be loaded into
        # the container
        ccf_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
        )
        for src, dest in [
            ("build/env", "env"),  # TODO: Use local python
            ("tests/external_executor", "external_executor"),
            ("tests/infra", "external_executor/infra"),
        ]:
            src_path = os.path.join(ccf_dir, src)
            dest_path = os.path.join(directory, dest)
            print(f"Copying {src_path} to {dest_path}")
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dest_path)
            else:
                shutil.copyfile(src_path, dest_path)

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        command = "/executor/env/bin/python3"
        command += " /executor/external_executor/run_executor.py"
        command += f' --executor "{executor}"'
        command += f' --node-public-rpc-address "{node.get_public_rpc_address()}"'
        command += f' --network-common-dir "{network.common_dir}"'
        command += f' --supported-endpoints "{",".join([":".join(e) for e in supported_endpoints])}"'
        LOG.info(f"Creating container with command: {command}")
        self._container = self._client.containers.create(
            image=image_name,
            command=command,
            volumes={
                "/workspaces/CCF": {
                    "bind": "/workspaces/CCF",
                    "mode": "rw",
                },
                directory: {
                    "bind": "/executor",
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
        self._container.start()
        LOG.info("Done")

    def wait_for_registration(self, timeout=3):
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
                    return
                time.sleep(0.1)
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
    workspace: str,
):
    with tempfile.TemporaryDirectory(dir=workspace) as tmp_dir:
        ec = ExecutorContainer(
            executor,
            node,
            network,
            supported_endpoints,
            tmp_dir,
        )
        ec.start()
        ec.wait_for_registration()
        yield
        ec.terminate()
