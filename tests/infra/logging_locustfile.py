# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Certificate- or JWT-authenticated blocking logging writes."""

import hashlib
import json
import random

from locust import constant, events, task
from locust.contrib.fasthttp import FastHttpUser

import infra.locust_benchmark
import infra.locust_benchmark_support

REQUEST_NAME = "POST /app/log/blocking/private"
DEFAULT_KEY_SPACE_SIZE = 1000
EXPECTED_STATUS = 200

# Shared with the drivers, so that they name the same subcommands.
AUTHENTICATION_CERTIFICATE = infra.locust_benchmark.AUTHENTICATION_CERTIFICATE
AUTHENTICATION_JWT = infra.locust_benchmark.AUTHENTICATION_JWT
JWT_ENVIRONMENT_VARIABLE = infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE

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
        "--key-space-size",
        help="Number of distinct logging records written to",
        type=int,
        default=DEFAULT_KEY_SPACE_SIZE,
    )
    # A subcommand per authentication mode, so that argparse enforces which
    # options each mode accepts. Everything after the subcommand is parsed by
    # the subparser, so it must come last on the command line.
    authentication = parser.add_subparsers(
        dest="authentication",
        required=True,
        metavar=f"{{{AUTHENTICATION_CERTIFICATE},{AUTHENTICATION_JWT}}}",
    )
    certificate = authentication.add_parser(
        AUTHENTICATION_CERTIFICATE,
        help="Authenticate as a user with their certificate",
    )
    certificate.add_argument("--cert", help="Path to client certificate", required=True)
    certificate.add_argument("--key", help="Path to client private key", required=True)
    jwt = authentication.add_parser(
        AUTHENTICATION_JWT,
        help="Authenticate as a user with a bearer token",
    )
    jwt.add_argument(
        "--jwt",
        help=f"Bearer token, taken from ${JWT_ENVIRONMENT_VARIABLE} so that it "
        "does not appear on the command line",
        required=True,
        env_var=JWT_ENVIRONMENT_VARIABLE,
        is_secret=True,
    )


class BlockingWriter(FastHttpUser):
    wait_time = constant(0)
    insecure = False

    def __init__(self, environment):
        super().__init__(environment)
        opts = environment.parsed_options
        self.headers = {"content-type": "application/json"}
        if opts.authentication == AUTHENTICATION_JWT:
            self.headers["authorization"] = f"Bearer {opts.jwt}"

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
