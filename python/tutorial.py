# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import http
import json
import os
from loguru import logger as LOG

# Change default log format
LOG.remove()
LOG.add(
    sys.stdout,
    format="<green>[{time:HH:mm:ss.SSS}]</green> {message}",
)

# SNIPPET: import_clients
import ccf.clients

# Load client info file.
if len(sys.argv) < 2:
    print("Error: Common directory should be specified as first argument")
    sys.exit(1)

common_dir = sys.argv[1]

# Assumes sandbox started with at least one node
host = "127.0.0.1"
port = 8000
ca = os.path.join(common_dir, "networkcert.pem")
cert = os.path.join(common_dir, "user0_cert.pem")
key = os.path.join(common_dir, "user0_privk.pem")
# User client info loaded.

member_cert = os.path.join(common_dir, "member0_cert.pem")
member_key = os.path.join(common_dir, "member0_privk.pem")
# Member client info loaded.

# Tutorial starts below.

# SNIPPET: anonymous_client
anonymous_client = ccf.clients.CCFClient(host, port, ca)

# SNIPPET_START: anonymous_requests
r = anonymous_client.get("/node/state")
assert r.status_code == http.HTTPStatus.OK
r = anonymous_client.get("/node/network")
assert r.status_code == http.HTTPStatus.OK
# SNIPPET_END: anonymous_requests

# SNIPPET_START: session_authenticated_client
user_client = ccf.clients.CCFClient(
    host, port, ca, session_auth=ccf.clients.Identity(key, cert, "session client")
)
# SNIPPET_END: session_authenticated_client

# SNIPPET_START: authenticated_post_requests
r = user_client.post("/app/log/private", body={"id": 0, "msg": "Private message"})
assert r.status_code == http.HTTPStatus.OK
r = user_client.post("/app/log/public", body={"id": 0, "msg": "Public message"})
assert r.status_code == http.HTTPStatus.OK
# SNIPPET_END: authenticated_post_requests

# SNIPPET: wait_for_commit
user_client.wait_for_commit(r)

# SNIPPET: any_client_can_wait
anonymous_client.wait_for_commit(r)

# SNIPPET_START: authenticated_get_requests
r = user_client.get("/app/log/private?id=0")
assert r.status_code == http.HTTPStatus.OK
assert r.body.json() == {"msg": "Private message"}
r = user_client.get("/app/log/public?id=0")
assert r.status_code == http.HTTPStatus.OK
assert r.body.json() == {"msg": "Public message"}
# SNIPPET_END: authenticated_get_requests

# SNIPPET_START: signature_authenticated_client
member_client = ccf.clients.CCFClient(
    host,
    port,
    ca,
    session_auth=None,
    signing_auth=ccf.clients.Identity(member_key, member_cert, "sign member client"),
)
# SNIPPET_END: signature_authenticated_client

# SNIPPET_START: signed_request
r = member_client.post("/gov/ack/update_state_digest")
assert r.status_code == http.HTTPStatus.OK
# SNIPPET_END: signed_request

# SNIPPET: import_proposal_generator
import ccf.proposal_generator

# SNIPPET_START: dict_proposal
proposal, vote = ccf.proposal_generator.open_network()
# >>> proposal
# {'script': {'text': 'return Calls:call("open_network")'}}

member_client = ccf.clients.CCFClient(
    host,
    port,
    ca,
    session_auth=ccf.clients.Identity(member_key, member_cert, "member"),
    signing_auth=ccf.clients.Identity(member_key, member_cert, "member"),
)
response = member_client.post(
    "/gov/proposals",
    body=proposal,
)
# SNIPPET_END: dict_proposal

# SNIPPET_START: json_proposal_with_file
with open("my_open_network_proposal.json", "w") as f:
    f.write(json.dumps(proposal, indent=2))

# The contents of `my_open_network_proposal.json` are submitted as the request body.
response = member_client.post(
    "/gov/proposals",
    body="@my_open_network_proposal.json",
)
# SNIPPET_END: json_proposal_with_file
