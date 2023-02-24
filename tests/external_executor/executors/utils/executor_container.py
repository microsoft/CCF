# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
import os
import shutil
from tempfile import TemporaryDirectory
import threading
import docker
import time

from typing import Set, Tuple
from infra.network import Network
from infra.node import Node

from loguru import logger as LOG


CCF_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..")
)

IS_AZURE_DEVOPS = "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


class ExecutorContainer:
    def print_container_logs(self):
        for line in self._container.logs(stream=True):
            LOG.info(f"[CONTAINER - {self._container.name}] {line}")

    def __init__(
        self,
        workspace: str,
        executor: str,
        node: Node,
        network: Network,
        supported_endpoints: Set[Tuple[str, str]],
    ):
        self._client = docker.from_env()
        self._node = node
        self._supported_endpoints = supported_endpoints
        self._thread = None

        image_name = "mcr.microsoft.com/cbl-mariner/base/python:3"
        LOG.info(f"Pulling image {image_name}")
        self._client.images.pull(image_name)

        # Create a container with external executor code loaded in a volume and
        # a command to run the executor
        command = "pip install --upgrade pip &&"
        command += " ls -la /executor_mnt &&"
        command += " pip install -r /executor_mnt/requirements.txt &&"
        command += " python3 /executor_mnt/run_executor.py"
        command += f' --executor "{executor}"'
        command += f' --node-public-rpc-address "{node.get_public_rpc_address()}"'
        command += ' --network-common-dir "/executor_mnt/ccf_network"'
        command += f' --supported-endpoints "{",".join([":".join(e) for e in supported_endpoints])}"'
        LOG.info(f"Creating container with command: {command}")

        # Copy the executor code into a temporary directory which can be mounted
        # executor_volume = self._client.volumes.create(name="executor", driver="local")
        # docker.volume.copy
        # docker.volume.copy(
        #     os.path.join(CCF_DIR, "tests/external_executor"), "/executor"
        # )
        # docker.volume.copy(os.path.join(CCF_DIR, "tests/infra"), "/executor/infra")
        # docker.volume.copy(network.common_dir, "/executor/ccf_network")

        self.mount_dir = os.path.join(workspace, "executor/")
        shutil.copytree(
            os.path.join(CCF_DIR, "tests/external_executor"),
            self.mount_dir,
        )
        shutil.copytree(
            os.path.join(CCF_DIR, "tests/infra"),
            os.path.join(self.mount_dir, "infra"),
        )
        shutil.copytree(
            network.common_dir,
            os.path.join(self.mount_dir, "ccf_network"),
        )
        os.chmod(self.mount_dir, 777)
        LOG.info(f"{self.mount_dir=}")
        LOG.info(f"{os.listdir(self.mount_dir)=}")

        self._container = self._client.containers.create(
            image=image_name,
            command=f'bash -exc "{command}"',
            volumes={
                self.mount_dir: {
                    "bind": f"/executor",
                    "mode": "rw",
                },
                # executor_volume: {
                #     "bind": "/executor_vol",
                #     "mode": "rw",
                # },
            },
            mounts=[
                docker.types.Mount(
                    target="/executor_mnt",
                    source=os.path.join(CCF_DIR, "tests/external_executor"),
                    type="bind",
                ),
                docker.types.Mount(
                    target="/executor_mnt/infra",
                    source=os.path.join(CCF_DIR, "tests/infra"),
                    type="bind",
                ),
                docker.types.Mount(
                    target="/executor_mnt/ccf_network",
                    source=network.common_dir,
                    type="bind",
                ),
            ],
            publish_all_ports=True,
            auto_remove=True,
        )

        LOG.info("Connecting container to network")
        self._node.remote.network.connect(self._container)

    def start(self):
        LOG.info("Starting container...")
        self._thread = threading.Thread(target=self.print_container_logs)
        self._container.start()
        self._thread.start()
        LOG.info(f"{self._container.attrs=}")
        LOG.info(f"{self._client.api.volumes()=}")
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
                    return
                time.sleep(1)
        raise TimeoutError(f"Executor did not register within {timeout} seconds")

    def terminate(self):
        LOG.info("Terminating container...")
        self._container.stop()
        self._thread.join()
        LOG.info("Done")


@contextmanager
def executor_container(
    workspace: str,
    executor: str,
    node: Node,
    network: Network,
    supported_endpoints: Set[Tuple[str, str]],
):
    with TemporaryDirectory(
        dir=os.path.expanduser("~/") if IS_AZURE_DEVOPS else workspace
    ) as tmp_dir:
        ec = ExecutorContainer(
            tmp_dir,
            executor,
            node,
            network,
            supported_endpoints,
        )
        ec.start()
        ec.wait_for_registration()
        yield
        ec.terminate()
