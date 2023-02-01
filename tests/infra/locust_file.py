# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import locust.stats
from locust import HttpUser, task, events, constant_throughput
import json


# Scope for logging txs so that they do not conflict
# with the txs recorded by the actual tests
LOGGING_TXS_SCOPE = "load"

# Flush csv stats to disk more often than default (10s)
locust.stats.CSV_STATS_FLUSH_INTERVAL_SEC = 1

DEFAULT_REQUEST_RATE_S = 100


@events.init_command_line_parser.add_listener
def init_parser(parser):
    parser.add_argument("--ca", help="Path to server certificate")
    parser.add_argument("--key", help="Path to client private key")
    parser.add_argument("--cert", help="Path to client certificate")
    parser.add_argument(
        "--node-host", help="List of node hosts to target", action="append", default=[]
    )
    parser.add_argument(
        "--rate", help="Request rate", type=int, default=DEFAULT_REQUEST_RATE_S
    )


class Submitter(HttpUser):
    last_msg_id = 0

    # Round-robin between all hosts specified at startup
    hosts = []
    current_host_idx = 0
    rate = 0

    def wait_time(self):
        return constant_throughput(self.rate)(self)

    def on_start(self):
        self.hosts = self.environment.parsed_options.node_host
        self.rate = (
            self.environment.parsed_options.rate
            / self.environment.parsed_options.num_users
        )

    @task()
    def submit(self):
        opts = self.environment.parsed_options
        headers = {"content-type": "application/json"}
        body_json = {
            "id": self.last_msg_id,
            "msg": f"Private message: {self.last_msg_id}",
        }
        host = self.hosts[self.current_host_idx]
        self.client.post(
            f"{host}/app/log/private?scope={LOGGING_TXS_SCOPE}",
            data=json.dumps(body_json).encode(),
            headers=headers,
            cert=(opts.cert, opts.key),
            verify=opts.ca,
        )
        self.last_msg_id += 1
        self.current_host_idx = (self.current_host_idx + 1) % len(self.hosts)
