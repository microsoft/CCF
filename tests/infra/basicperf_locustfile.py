# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Locust workload for the "Basic Blocking Locust" benchmark.

Each user issues blocking writes (PUT /records/blocking/{key}) one at a time,
waiting for each response before sending the next. That endpoint only responds
once the transaction has committed, so a single user's rate is bounded by
commit latency, and total throughput is driven by the number of users.

FastHttpUser (geventhttpclient) is used rather than HttpUser (requests),
because the latter cannot drive enough requests per second to saturate the
service.
"""

import hashlib
import random

from locust import constant, events, task
from locust.contrib.fasthttp import FastHttpUser

import infra.locust_benchmark_support

# All requests are reported under a single name, so that locust aggregates them
# into one statistics entry rather than one per key.
REQUEST_NAME = "PUT /records/blocking/{key}"

DEFAULT_KEY_SPACE_SIZE = 1000

EXPECTED_STATUS = 204

# Bodies are fixed per key, so they are built once per process and shared by
# every user in it, rather than rebuilt per user or per request.
_bodies: list[str] = []


def _get_bodies(key_space_size: int) -> list[str]:
    global _bodies
    if len(_bodies) != key_space_size:
        _bodies = [
            hashlib.sha256(f"{i}".encode()).hexdigest() for i in range(key_space_size)
        ]
    return _bodies


@events.init_command_line_parser.add_listener
def init_parser(parser):
    infra.locust_benchmark_support.add_common_arguments(parser)
    parser.add_argument("--cert", help="Path to client certificate", required=True)
    parser.add_argument("--key", help="Path to client private key", required=True)
    parser.add_argument(
        "--key-space-size",
        help="Number of distinct keys written to",
        type=int,
        default=DEFAULT_KEY_SPACE_SIZE,
    )


class BlockingWriter(FastHttpUser):
    # Send the next request as soon as the previous response arrives. Each
    # response already waits for commit, so no additional pacing is wanted.
    wait_time = constant(0)

    # Verify the service certificate, rather than skipping verification as
    # FastHttpUser does by default.
    insecure = False

    def __init__(self, environment):
        super().__init__(environment)
        self.key_space_size = environment.parsed_options.key_space_size
        self.bodies = _get_bodies(self.key_space_size)

    def ssl_context_factory(self):
        opts = self.environment.parsed_options
        return infra.locust_benchmark_support.create_ssl_context(
            opts.ca, cert_path=opts.cert, key_path=opts.key
        )

    @task
    def blocking_write(self):
        index = random.randrange(self.key_space_size)
        with self.client.put(
            f"/records/blocking/{index}",
            data=self.bodies[index],
            headers={"content-type": "text/plain"},
            name=REQUEST_NAME,
            catch_response=True,
        ) as response:
            # Anything other than the expected status is a failure, including
            # the 5xx returned when a transaction is invalidated, and the 0
            # reported when the connection itself failed.
            if response.status_code == EXPECTED_STATUS:
                response.success()
            else:
                response.failure(f"Unexpected status {response.status_code}")


infra.locust_benchmark_support.register_steady_state_listeners(events)
