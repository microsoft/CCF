# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import http
import json
import os

# SNIPPET: import_clients
import ccf.clients

# Load client info file.
if len(sys.argv) < 2:
    print("Client info file should be specified as first argument")
    sys.exit(1)

client_info_file = sys.argv[1]

client_info = {}
with open(sys.argv[1]) as client_info_file:
    client_info = json.load(client_info_file)

host = client_info["host"]
port = client_info["port"]
common_dir = client_info["common_dir"]
ca = os.path.join(common_dir, "networkcert.pem")
cert = os.path.join(common_dir, "user0_cert.pem")
key = os.path.join(common_dir, "user0_privk.pem")
# Client info loaded. Tutorial starts below.


# SNIPPET: anonymous_client
anonymous_client = ccf.clients.CCFClient(host, port, ca)

# SNIPPET_START: anonymous_requests
r = anonymous_client.get("/node/state")
assert r.status_code == http.HTTPStatus.OK
r = anonymous_client.get("/node/network")
assert r.status_code == http.HTTPStatus.OK
# SNIPPET_END: anonymous_requests

# SNIPPET: authenticated_client
user_client = ccf.clients.CCFClient(host, port, ca, cert, key)

# SNIPPET_START: authenticated_post_requests
r = user_client.post("/app/log/private", params={"id": 0, "msg": "Private message"})
assert r.status_code == http.HTTPStatus.OK
r = user_client.post("/app/log/public", params={"id": 0, "msg": "Public message"})
assert r.status_code == http.HTTPStatus.OK
# SNIPPET_END: authenticated_post_requests

# SNIPPET: wait_for_commit
user_client.wait_for_commit(r)

# SNIPPET: any_client_can_wait
anonymous_client.wait_for_commit(r)

# SNIPPET_START: authenticated_get_requests
r = user_client.get("/app/log/private?id=0")
assert r.status_code == http.HTTPStatus.OK
assert r.body == {"msg": "Private message"}
r = user_client.get("/app/log/public?id=0")
assert r.status_code == http.HTTPStatus.OK
assert r.body == {"msg": "Public message"}
# SNIPPET_END: authenticated_get_requests
