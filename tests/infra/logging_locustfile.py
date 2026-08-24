# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Certificate- or JWT-authenticated blocking logging writes."""

import hashlib
import json
import os
import random

from locust import constant, events, task
from locust.contrib.fasthttp import FastHttpUser

import infra.locust_benchmark
import infra.locust_benchmark_support

REQUEST_NAME = "POST /app/log/blocking/private"
DEFAULT_KEY_SPACE_SIZE = 1000
EXPECTED_STATUS = 200
AUTHENTICATION_CERTIFICATE = "certificate"
AUTHENTICATION_JWT = "jwt"

_bodies: list[str] = []


def _get_bodies(key_space_size: int) -> list[str]:
    global _bodies
    if len(_bodies) != key_space_size:
        _bodies = [
            json.dumps(
                {
                    "id": record_id,
                    "msg": hashlib.sha256(str(record_id).encode()).hexdigest(),
                },
                separators=(",", ":"),
            )
            for record_id in range(key_space_size)
        ]
    return _bodies


@events.init_command_line_parser.add_listener
def init_parser(parser):
    infra.locust_benchmark_support.add_common_arguments(parser)
    parser.add_argument(
        "--authentication",
        choices=(AUTHENTICATION_CERTIFICATE, AUTHENTICATION_JWT),
        required=True,
    )
    parser.add_argument("--cert", help="Path to client certificate")
    parser.add_argument("--key", help="Path to client private key")
    parser.add_argument(
        "--key-space-size",
        help="Number of distinct logging records written to",
        type=int,
        default=DEFAULT_KEY_SPACE_SIZE,
    )


class BlockingWriter(FastHttpUser):
    wait_time = constant(0)
    insecure = False

    def __init__(self, environment):
        super().__init__(environment)
        opts = environment.parsed_options
        self.headers = {"content-type": "application/json"}
        if opts.authentication == AUTHENTICATION_CERTIFICATE:
            if opts.cert is None or opts.key is None:
                raise RuntimeError(
                    "--cert and --key are required for certificate authentication"
                )
        else:
            if opts.cert is not None or opts.key is not None:
                raise RuntimeError(
                    "--cert and --key must not be supplied with JWT authentication"
                )
            token = os.environ.get(infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE)
            if token is None:
                raise RuntimeError(
                    f"{infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE} is not set"
                )
            self.headers["authorization"] = f"Bearer {token}"

        self.key_space_size = opts.key_space_size
        self.bodies = _get_bodies(self.key_space_size)

    def ssl_context_factory(self):
        opts = self.environment.parsed_options
        if opts.authentication == AUTHENTICATION_CERTIFICATE:
            return infra.locust_benchmark_support.create_ssl_context(
                opts.ca, cert_path=opts.cert, key_path=opts.key
            )
        return infra.locust_benchmark_support.create_ssl_context(opts.ca)

    @task
    def blocking_write(self):
        record_id = random.randrange(self.key_space_size)
        with self.client.post(
            "/app/log/blocking/private",
            data=self.bodies[record_id],
            headers=self.headers,
            name=REQUEST_NAME,
            catch_response=True,
        ) as response:
            if response.status_code == EXPECTED_STATUS:
                response.success()
            else:
                response.failure(f"Unexpected status {response.status_code}")


infra.locust_benchmark_support.register_steady_state_listeners(events)
