# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
import os
import threading
import docker
import time
from base64 import b64encode
from pathlib import Path

from infra.network import Network
from infra.node import Node

from loguru import logger as LOG


CCF_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..")
)


class ScopedContainer:
    """Used to stream the logs of a container to a specific directory"""

    def stream_logs_to_file(self):
        with open(
            os.path.join(self.log_dir, self.log_file), "a", encoding="utf-8"
        ) as log_file:
            for line in self.container.logs(stream=True):
                log_file.write(line.decode())
                log_file.flush()

    def __init__(self, container, log_dir, log_file="out"):
        self.container = container
        self.log_dir = log_dir
        self.log_file = log_file
        self.container.start()
        self.thread = threading.Thread(target=self.stream_logs_to_file)
        self.thread.start()

    def stop(self):
        self.container.stop()
        self.thread.join()


class ExecutorContainer:
    _executors_count = {}

    def _build_image(self, image_name, path):
        LOG.debug(f"Building image {image_name }...")
        self._client.images.build(
            path=path, tag=image_name, dockerfile="Dockerfile", rm=True
        )
        LOG.info(f"Image {image_name} built")

    def _cleanup_container(self, name):
        # Cleanup container in case it is still running (e.g. previous interrupted run)
        for c in self._client.containers.list(all=True, filters={"name": [name]}):
            try:
                c.stop()
                c.remove()
            except docker.errors.NotFound:
                pass
            LOG.trace(f"Cleaned up container {c.name}")

    def __init__(self, executor: str, node: Node, network: Network):
        self._client = docker.from_env()
        self._node = node
        if executor not in self._executors_count:
            self._executors_count[executor] = 0
        else:
            self._executors_count[executor] += 1

        self._name = f"{executor}_{self._executors_count[executor]}"
        self._dir = os.path.join(self._node.remote.remote.root, self._name)
        self.executor_container = None
        self.attestation_container = None

        # Build external executor
        image_name = executor
        self._build_image(
            image_name, os.path.join(CCF_DIR, "tests/external_executor/executors")
        )

        # Build attestation container
        attestation_container_image_name = "attestation_container"
        self._build_image(
            attestation_container_image_name,
            os.path.join(CCF_DIR, "attestation-container"),
        )

        # Create shared volume for attestation container unix domain socket
        self._shared_volume = self._client.volumes.create(name="shared_volume")

        # Create attestation container
        attestation_container_name = f"ac_{self._name}"
        self._cleanup_container(attestation_container_name)
        self._attestation_container = self._client.containers.create(
            image=attestation_container_image_name,
            name=attestation_container_name,
            publish_all_ports=True,
            command="app --insecure-virtual",  # Remove insecure argument when we run this in SNP ACI
            auto_remove=True,
            volumes={self._shared_volume.name: {"bind": "/tmp", "mode": "rw"}},
        )

        # Create external executor container
        # self._cleanup_container(self._name)
        service_certificate_bytes = open(
            os.path.join(network.common_dir, "service_cert.pem"), "rb"
        ).read()
        self._container = self._client.containers.create(
            image=image_name,
            name=self._name,
            environment={
                "CCF_CORE_NODE_RPC_ADDRESS": node.get_public_rpc_address(),
                "CCF_CORE_SERVICE_CERTIFICATE": b64encode(service_certificate_bytes),
            },
            volumes_from=[attestation_container_name],
            publish_all_ports=True,
            auto_remove=True,
        )
        self._node.remote.network.connect(self._container)

        Path(self._dir).mkdir(parents=True, exist_ok=True)

    def start(self):
        LOG.debug(f"Starting container {self._name}...")
        self.executor_container = ScopedContainer(self._container, self._dir)
        self.attestation_container = ScopedContainer(
            self._attestation_container, self._dir, "ac.out"
        )
        LOG.info(f"Container {self._name} started")

    def wait_for_registration(self, timeout=10):
        # Endpoint may return 404 for reasons other than that the executor is
        # not yet registered, so check for an exact message that the endpoint
        # path is unknown
        with self._node.client() as client:
            # Hardcoded for logging app until there is an endpoint to find out which
            # executors are registered
            end_time = time.time() + timeout
            while time.time() < end_time:
                path = "/log/public"
                r = client.get(path)
                try:
                    assert r.body.json()["error"]["message"] == f"Unknown path: {path}."
                except Exception:
                    LOG.success(f"Container successfully {self._name} registered")
                    return
                else:
                    time.sleep(0.1)
                    continue
        raise TimeoutError(f"Executor did not register within {timeout} seconds")

    def terminate(self):
        LOG.debug(f"Terminating container {self._name}...")
        self.executor_container.stop()
        self.attestation_container.stop()
        LOG.info(f"Container {self._name} stopped")


@contextmanager
def executor_container(executor: str, node: Node, network: Network):
    ec = ExecutorContainer(executor, node, network)
    ec.start()
    ec.wait_for_registration()
    yield
    ec.terminate()
