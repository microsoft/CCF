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
import logging
import random
import ssl

import gevent
from locust import constant, events, task
from locust.contrib.fasthttp import FastHttpUser
from locust.runners import WorkerRunner

# All requests are reported under a single name, so that locust aggregates them
# into one statistics entry rather than one per key.
REQUEST_NAME = "PUT /records/blocking/{key}"

DEFAULT_KEY_SPACE_SIZE = 1000

DEFAULT_MEASURE_TIME_S = 20

EXPECTED_STATUS = 204

LOG = logging.getLogger(__name__)

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
    parser.add_argument("--ca", help="Path to service certificate", required=True)
    parser.add_argument("--cert", help="Path to client certificate", required=True)
    parser.add_argument("--key", help="Path to client private key", required=True)
    parser.add_argument(
        "--key-space-size",
        help="Number of distinct keys written to",
        type=int,
        default=DEFAULT_KEY_SPACE_SIZE,
    )
    parser.add_argument(
        "--measure-time-s",
        help="Seconds to keep running once all users have spawned",
        type=int,
        default=DEFAULT_MEASURE_TIME_S,
    )


@events.init.add_listener
def on_init(environment, **_kwargs):
    """Stop the run a fixed time after the last user has spawned.

    Locust's own --run-time starts counting when locust starts, so it includes
    the ramp. --reset-stats discards the statistics gathered during the ramp
    but does not extend the deadline, so the further the ramp is stretched, the
    smaller the steady-state window becomes, until it disappears entirely.
    Timing from spawning_complete instead keeps the measurement window the same
    length whatever the spawn rate is.
    """
    # In distributed mode the master tells the workers to fire this event too,
    # but only the master decides when the run ends.
    if isinstance(environment.runner, WorkerRunner):
        return

    spawning_completed = False

    def stop_after_measurement_window(**_kwargs):
        nonlocal spawning_completed
        spawning_completed = True
        # Statistics are reset by --reset-stats on this same event, so the
        # window measured here is exactly the window reported.
        gevent.spawn_later(
            environment.parsed_options.measure_time_s, environment.runner.quit
        )

    def check_spawning_completed(**_kwargs):
        # Reaching the end without spawning having completed means the run was
        # ended by the --run-time backstop mid-ramp. The statistics then
        # describe a partial ramp, but still look like a plausible result, so
        # say so and exit non-zero rather than reporting them.
        if not spawning_completed:
            LOG.error(
                "Run ended before all users had spawned. "
                "The statistics do not describe steady state."
            )
            environment.process_exit_code = 1

    environment.events.spawning_complete.add_listener(stop_after_measurement_window)
    environment.events.quitting.add_listener(check_spawning_completed)


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
        context = ssl.create_default_context(cafile=opts.ca)
        context.load_cert_chain(certfile=opts.cert, keyfile=opts.key)
        return context

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
