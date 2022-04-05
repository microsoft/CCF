from locust.env import Environment
import locust.stats
from locust import HttpUser, task, tag, between, events
import json

from loguru import logger as LOG

# Scope for logging txs so that they do not conflict
# with the txs recorded by the actual tests
LOGGING_TXS_SCOPE = "load"

# Flush csv stats to disk more often than default (10s)
locust.stats.CSV_STATS_FLUSH_INTERVAL_SEC = 1


@events.init_command_line_parser.add_listener
def init_parser(parser):
    parser.add_argument("--ca", help="Path to server certificate")
    parser.add_argument("--key", help="Path to client private key")
    parser.add_argument("--cert", help="Path to client certificate")
    parser.add_argument(
        "--node-host", help="List of node hosts to target", action="append", default=[]
    )


class Submitter(HttpUser):

    user_auth = None
    server_ca = None
    last_msg_id = 0

    @task()
    def submit(self):
        opts = self.environment.parsed_options
        headers = {"content-type": "application/json"}
        body_json = {
            "id": self.last_msg_id,
            "msg": f"Private message: {self.last_msg_id}",
        }

        # TODO: Handle multiple nodes
        # LOG.error(opts.node_host)
        self.client.post(
            f"{opts.node_host[0]}/app/log/private?scope={LOGGING_TXS_SCOPE}",
            data=json.dumps(body_json).encode(),
            headers=headers,
            cert=(opts.cert, opts.key),
            verify=opts.ca,
        )
        self.last_msg_id += 1
