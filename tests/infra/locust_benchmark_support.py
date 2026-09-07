# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Locust-side helpers shared by benchmark workloads."""

import logging
import ssl
from typing import Any

import gevent
from locust.runners import WorkerRunner

DEFAULT_MEASURE_TIME_S = 20
LOG = logging.getLogger(__name__)

# Locust reports each distinct failure message in full, so the body is bounded
# to stop an unexpectedly large one from flooding the report.
MAX_FAILURE_BODY_CHARS = 2000


def describe_unexpected_status(response: Any) -> str:
    """Describe an unexpected response, for use as a Locust failure message.

    The body carries the service's own error message, which is not recorded
    anywhere else on the client side, so it is kept rather than discarded.
    """
    # FastResponse.text is None when the body is absent or cannot be decoded,
    # which includes the connection failures reported as status 0.
    body = (response.text or "").strip()
    if not body:
        return f"Unexpected status {response.status_code}"
    if len(body) > MAX_FAILURE_BODY_CHARS:
        body = f"{body[:MAX_FAILURE_BODY_CHARS]}... [truncated]"
    return f"Unexpected status {response.status_code}: {body}"


def add_common_arguments(parser: Any) -> None:
    parser.add_argument("--ca", help="Path to service certificate", required=True)
    parser.add_argument(
        "--measure-time-s",
        help="Seconds to keep running once all users have spawned",
        type=int,
        default=DEFAULT_MEASURE_TIME_S,
    )


def register_steady_state_listeners(events: Any) -> None:
    @events.init.add_listener
    def on_init(environment: Any, **_kwargs: Any) -> None:
        """Measure for a fixed window after all users have spawned."""
        # Workers receive spawning_complete too, but only the master ends runs.
        if isinstance(environment.runner, WorkerRunner):
            return

        spawning_completed = False

        def stop_after_measurement_window(**_kwargs: Any) -> None:
            nonlocal spawning_completed
            spawning_completed = True
            # --reset-stats runs on this event, so this is the reported window.
            gevent.spawn_later(
                environment.parsed_options.measure_time_s, environment.runner.quit
            )

        def check_spawning_completed(**_kwargs: Any) -> None:
            # A run ended by the backstop mid-ramp has plausible but invalid
            # statistics, so fail rather than reporting them.
            if not spawning_completed:
                LOG.error(
                    "Run ended before all users had spawned. "
                    "The statistics do not describe steady state."
                )
                environment.process_exit_code = 1

        environment.events.spawning_complete.add_listener(stop_after_measurement_window)
        environment.events.quitting.add_listener(check_spawning_completed)


def create_ssl_context(
    ca_path: str, cert_path: str | None = None, key_path: str | None = None
) -> ssl.SSLContext:
    if (cert_path is None) != (key_path is None):
        raise ValueError("Client certificate and key must be supplied together")

    context = ssl.create_default_context(cafile=ca_path)
    if cert_path is not None and key_path is not None:
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context
