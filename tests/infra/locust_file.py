from locust.env import Environment
from locust import HttpUser, task, tag, between, events
import json

from loguru import logger as LOG

# Scope for logging txs so that they do not conflict
# with the txs recorded by the actual tests
LOGGING_TXS_SCOPE = "load"


@events.init_command_line_parser.add_listener
def init_parser(parser):
    parser.add_argument("--ca", help="Path to server certificate")
    parser.add_argument("--key", help="Path to client private key")
    parser.add_argument("--cert", help="Path to client certificate")
    parser.add_argument(
        "--node-hosts", help="List of node hosts to target", action="append", default=[]
    )


class Submitter(HttpUser):

    user_auth = None
    server_ca = None
    msg_id = 0

    between(1, 1)

    @task()
    def submit(self):
        opts = self.environment.parsed_options
        headers = {"content-type": "application/json"}
        body_json = {"id": self.msg_id, "msg": f"Private message: {self.msg_id}"}
        self.msg_id += 1
        self.client.post(
            f"{opts.node_hosts[0]}/app/log/private?scope={LOGGING_TXS_SCOPE}",
            data=json.dumps(body_json).encode(),
            headers=headers,
            cert=(opts.cert, opts.key),
            verify=opts.ca,
        )


# class Reader(HttpUser):

#     user_auth = None
#     server_ca = None

#     @task()
#     def query(self):
#         self.client.get(
#             f"/app/log/private?scope={LOGGING_TXS_SCOPE}&id={0}",  # TODO: Use different key?
#             cert=self.user_auth,
#             verify=self.server_ca,
#         )
