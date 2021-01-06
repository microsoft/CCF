# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import http
import json
import os

# SNIPPET: import_clients
import ccf.clients

# Load client info file.
if len(sys.argv) < 3:
    print(
        "Error: Ledger directory and common directory should be specified as first and second arguments, respectively"
    )
    sys.exit(1)

ledger_dir = sys.argv[1]
common_dir = sys.argv[2]

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

# SNIPPET: authenticated_client
user_client = ccf.clients.CCFClient(
    host, port, ca, ccf.clients.Identity(key, cert, "client")
)

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

# SNIPPET: import_ledger
import ccf.ledger

# SNIPPET: create_ledger
ledger = ccf.ledger.Ledger(ledger_dir)

# SNIPPET: target_table
target_table = "public:ccf.gov.nodes"

# SNIPPET_START: iterate_over_ledger
target_table_changes = 0  # Simple counter

for chunk in ledger:
    for transaction in chunk:
        # Retrieve all public tables changed in transaction
        public_tables = transaction.get_public_domain().get_tables()

        # If target_table was changed, count the number of keys changed
        if target_table in public_tables:
            for key, value in public_tables[target_table].items():
                target_table_changes += 1  # A key was changed
# SNIPPET_END: iterate_over_ledger

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
