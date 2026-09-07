# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Locust workload for public historical range queries."""

import os
import random
import time

import gevent
from locust import constant, events, task
from locust.contrib.fasthttp import FastHttpUser

import infra.jwt_issuer
import infra.locust_benchmark
import infra.locust_benchmark_support

PAGE_REQUEST_NAME = "GET /app/log/public/historical/range (page)"
QUERY_REQUEST_TYPE = "HISTORICAL"
RETRY_DELAY_S = 0.1


@events.init_command_line_parser.add_listener
def init_parser(parser):
    infra.locust_benchmark_support.add_common_arguments(parser)
    parser.add_argument("--query-statistics-name", required=True)
    parser.add_argument(
        "--record",
        action="append",
        nargs=2,
        required=True,
        type=int,
        metavar=("ID", "EXPECTED_ENTRY_COUNT"),
    )


class HistoricalRangeReader(FastHttpUser):
    wait_time = constant(0)
    insecure = False

    def __init__(self, environment):
        super().__init__(environment)
        token = os.environ.get(infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE)
        if token is None:
            raise RuntimeError(
                f"{infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE} is not set"
            )
        self.headers = infra.jwt_issuer.make_bearer_header(token)
        self.query_statistics_name = environment.parsed_options.query_statistics_name
        self.records = environment.parsed_options.record

    def ssl_context_factory(self):
        return infra.locust_benchmark_support.create_ssl_context(
            self.environment.parsed_options.ca
        )

    @task
    def historical_range_query(self):
        record_id, expected_entry_count = random.choice(self.records)
        path = f"/app/log/public/historical/range?id={record_id}"
        entry_count = 0
        start_time = time.perf_counter()

        while path is not None:
            with self.client.get(
                path,
                headers=self.headers,
                name=PAGE_REQUEST_NAME,
                catch_response=True,
            ) as response:
                if response.status_code == 202:
                    response.success()
                    gevent.sleep(RETRY_DELAY_S)
                    continue

                if response.status_code != 200:
                    response.failure(
                        infra.locust_benchmark_support.describe_unexpected_status(
                            response
                        )
                    )
                    return

                try:
                    body = response.json()
                    entries = body["entries"]
                    next_link = body.get("@nextLink")
                    if not isinstance(entries, list):
                        raise TypeError("'entries' is not a list")
                    if next_link is not None and not isinstance(next_link, str):
                        raise TypeError("'@nextLink' is not a string")
                except (KeyError, TypeError, ValueError) as exc:
                    response.failure(f"Invalid response body: {exc}")
                    return

                entry_count += len(entries)
                path = next_link

        response_time_ms = (time.perf_counter() - start_time) * 1000
        exception = None
        if entry_count != expected_entry_count:
            exception = RuntimeError(
                f"Historical range for record {record_id} returned "
                f"{entry_count} entries, expected {expected_entry_count}"
            )

        self.environment.events.request.fire(
            request_type=QUERY_REQUEST_TYPE,
            name=self.query_statistics_name,
            response_time=response_time_ms,
            response_length=entry_count,
            exception=exception,
            context={},
        )


infra.locust_benchmark_support.register_steady_state_listeners(events)
