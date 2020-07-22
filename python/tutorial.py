# SNIPPET: import_clients
import ccf.clients

# SNIPPET: import_checker
import ccf.checker

import http

host = "127.159.75.34"
port = 42099
common_dir = "/datadrive/git/CCF/build/workspace/test_network_common/"
ca = f"{common_dir}/networkcert.pem"
cert = f"{common_dir}/user0_cert.pem"
key = f"{common_dir}/user0_privk.pem"


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

# SNIPPET_START: authenticated_get_requests
r = user_client.get("/app/log/private", params={"id": 0})
assert r.status_code == http.HTTPStatus.OK
assert r.body == {"msg": "Private message"}
r = user_client.get("/app/log/public", params={"id": 0})
assert r.status_code == http.HTTPStatus.OK
assert r.body == {"msg": "Public message"}
# SNIPPET_END: authenticated_post_requests

# SNIPPET: wait_for_commit
# user_client.wait_for_commit(r)

# SNIPPED: any_client_can_wait
anonymous_client.wait_for_commit(r)
