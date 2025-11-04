# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args
from infra.tx_status import TxStatus
import infra.checker
import infra.jwt_issuer
import infra.proc
import http
from http.client import HTTPResponse
import ssl
import socket
import os
from collections import defaultdict
import time
import json
import hashlib
import infra.clients
from infra.log_capture import flush_info
import ccf.receipt
from ccf.tx_id import TxID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ObjectIdentifier
import urllib.parse
import random
import re
import infra.crypto
from infra.runner import ConcurrentRunner
from hashlib import sha256
from infra.member import AckException
from types import MappingProxyType
import threading
import copy
import programmability
import e2e_common_endpoints
import subprocess
import base64

from loguru import logger as LOG


def verify_receipt(
    receipt,
    service_cert,
    claims=None,
    generic=True,
    skip_endorsement_check=False,
    is_signature_tx=False,
    skip_cert_chain_checks=False,
):
    """
    Raises an exception on failure
    """

    node_cert = load_pem_x509_certificate(receipt["cert"].encode(), default_backend())

    service_endorsements = []
    if "service_endorsements" in receipt:
        service_endorsements = [
            load_pem_x509_certificate(endorsement.encode(), default_backend())
            for endorsement in receipt["service_endorsements"]
        ]

    if not skip_endorsement_check:
        ccf.receipt.check_endorsements(
            node_cert,
            service_cert,
            service_endorsements,
        )

    if not skip_cert_chain_checks:
        ccf.receipt.check_cert_chain(
            node_cert,
            service_cert,
            service_endorsements,
        )

    if claims is not None:
        assert "leaf_components" in receipt
        assert "commit_evidence" in receipt["leaf_components"]
        commit_evidence_digest = sha256(
            receipt["leaf_components"]["commit_evidence"].encode()
        ).digest()
        if not generic:
            assert "claims_digest" not in receipt["leaf_components"]
        claims_digest = sha256(claims).digest()

        leaf = (
            sha256(
                bytes.fromhex(receipt["leaf_components"]["write_set_digest"])
                + commit_evidence_digest
                + claims_digest
            )
            .digest()
            .hex()
        )
    elif not is_signature_tx:
        assert "leaf_components" in receipt, receipt
        assert "write_set_digest" in receipt["leaf_components"]
        write_set_digest = bytes.fromhex(receipt["leaf_components"]["write_set_digest"])
        assert "commit_evidence" in receipt["leaf_components"]
        commit_evidence_digest = sha256(
            receipt["leaf_components"]["commit_evidence"].encode()
        ).digest()
        claims_digest = (
            bytes.fromhex(receipt["leaf_components"]["claims_digest"])
            if "claims_digest" in receipt["leaf_components"]
            else b""
        )
        leaf = (
            sha256(write_set_digest + commit_evidence_digest + claims_digest)
            .digest()
            .hex()
        )
    else:
        assert is_signature_tx
        leaf = receipt["leaf"]

    root = ccf.receipt.root(leaf, receipt["proof"])
    ccf.receipt.verify(root, receipt["signature"], node_cert)


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("/app/log/private", "/app/log/public")
@reqs.at_least_n_nodes(2)
@app.scoped_txs(verify=False)
def test(network, args):
    network.txs.issue(
        network=network,
        number_txs=1,
    )
    # HTTP2 doesn't support forwarding
    if not args.http2:
        network.txs.issue(
            network=network,
            number_txs=1,
            on_backup=True,
        )
    network.txs.verify()

    return network


@reqs.description("Protocol-illegal traffic")
@reqs.supports_methods("/app/log/private", "/app/log/public")
@reqs.at_least_n_nodes(2)
def test_illegal(network, args):
    primary, _ = network.find_primary()

    cafile = os.path.join(network.common_dir, "service_cert.pem")
    context = ssl.create_default_context(cafile=cafile)
    context.load_cert_chain(
        certfile=os.path.join(network.common_dir, "user0_cert.pem"),
        keyfile=os.path.join(network.common_dir, "user0_privk.pem"),
    )

    def get_main_interface_metrics():
        with primary.client() as c:
            return c.get("/node/metrics").body.json()["sessions"]["interfaces"][
                infra.interfaces.PRIMARY_RPC_INTERFACE
            ]

    def send_raw_content(content):
        # Send malformed HTTP traffic and check the connection is closed
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = context.wrap_socket(
            sock, server_side=False, server_hostname=primary.get_public_rpc_host()
        )
        conn.connect((primary.get_public_rpc_host(), primary.get_public_rpc_port()))
        LOG.info(f"Sending: {content}")
        conn.sendall(content)
        response = HTTPResponse(conn)
        response.begin()
        return response

    additional_parsing_errors = 0

    def send_bad_raw_content(content):
        nonlocal additional_parsing_errors
        try:
            response = send_raw_content(content)
        except http.client.RemoteDisconnected:
            assert args.http2, "HTTP/2 interface should close session without error"
            additional_parsing_errors += 1
            return
        else:
            assert not args.http2, "HTTP/1.1 interface should return valid error"

        response_body = response.read()
        LOG.warning(response_body)
        # If request parsing error, the interface metrics should report it
        if response_body.startswith(b"Unable to parse data as a HTTP request."):
            additional_parsing_errors += 1
        if response.status == http.HTTPStatus.BAD_REQUEST:
            assert content in response_body, response_body
        else:
            assert response.status in {http.HTTPStatus.NOT_FOUND}, (
                response.status,
                response_body,
            )

    initial_parsing_errors = get_main_interface_metrics()["errors"]["parsing"]
    send_bad_raw_content(b"\x01")
    send_bad_raw_content(b"\x01\x02\x03\x04")
    send_bad_raw_content(b"NOTAVERB ")
    send_bad_raw_content(b"POST / HTTP/42.42")
    send_bad_raw_content(json.dumps({"hello": "world"}).encode())
    # Tests non-UTF8 encoding in OData
    send_bad_raw_content(b"POST /node/\xff HTTP/2.0\r\n\r\n")

    for _ in range(40):
        content = bytes(random.randint(0, 255) for _ in range(random.randrange(1, 2)))
        # If we've accidentally produced something that might look like a valid HTTP request prefix, mangle it further
        first_byte = content[0]
        if (
            first_byte >= ord("A")
            and first_byte <= ord("Z")
            or first_byte == ord("\r")
            or first_byte == ord("\n")
        ):
            content = b"\00" + content
        send_bad_raw_content(content)

    def send_corrupt_variations(content):
        for i in range(len(content) - 1):
            for replacement in (b"\x00", b"\x01", bytes([(content[i] + 128) % 256])):
                corrupt_content = content[:i] + replacement + content[i + 1 :]
                send_bad_raw_content(corrupt_content)

    assert (
        get_main_interface_metrics()["errors"]["parsing"]
        == initial_parsing_errors + additional_parsing_errors
    )

    if not args.http2:
        good_content = b"GET /node/state HTTP/1.1\r\n\r\n"
        response = send_raw_content(good_content)
        assert response.status == http.HTTPStatus.OK, (response.status, response.read())
        send_corrupt_variations(good_content)

    # Valid transactions are still accepted
    network.txs.issue(
        network=network,
        number_txs=1,
    )

    # HTTP/2 does not support forwarding
    if not args.http2:
        network.txs.issue(
            network=network,
            number_txs=1,
            on_backup=True,
        )
        network.txs.verify()

    return network


@reqs.description("Test invalid transactions ids in /tx endpoint")
def test_invalid_txids(network, args):
    primary, _ = network.find_primary()

    # These are not valid transactions IDs at all, one cannot ask about their status
    invalid_params = ["a.b", "-1.-1", "0.0", "1.0", "0.1", "2.0"]

    with primary.client() as c:
        for txid in invalid_params:
            r = c.get(f"/tx?transaction_id={txid}")
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
            assert (
                r.body.json()["error"]["code"] == "InvalidQueryParameterValue"
            ), r.body.json()

    # These are valid transaction IDs, but cannot happen in CCF because views start
    # at 2, so while it is ok to ask about them, their consensus status is always Invalid,
    # meaning that they are not, and can never be committed.
    invalid_txs = ["1.1", "1.2"]

    with primary.client() as c:
        for txid in invalid_txs:
            r = c.get(f"/tx?transaction_id={txid}")
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            assert r.body.json()["status"] == "Invalid", r.body.json()

    return network


@reqs.description("Alternative protocols")
@reqs.supports_methods("/log/private", "/log/public")
@reqs.at_least_n_nodes(2)
def test_protocols(network, args):
    primary, _ = network.find_primary()

    primary_root = (
        f"https://{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}"
    )
    url = f"{primary_root}/node/state"
    ca_path = os.path.join(network.common_dir, "service_cert.pem")

    common_options = [
        url,
        "-sS",
        "--cacert",
        ca_path,
        "-w",
        "\\n%{http_code}\\n%{http_version}",
    ]

    def parse_result_out(r):
        assert r.returncode == 0, r.returncode
        body = r.stdout.decode()
        return body.rsplit("\n", 2)

    # Call without any extra args to get golden response
    res = infra.proc.ccall(
        "curl",
        *common_options,
    )
    expected_response_body, status_code, http_version = parse_result_out(res)
    assert status_code == "200", status_code
    assert http_version == "2" if args.http2 else "1.1", http_version

    protocols = {
        # WebSockets upgrade request is ignored
        "websockets": {
            "extra_args": [
                "-H",
                "Upgrade: websocket",
                "-H",
                "Connection: Upgrade",
            ],
        },
        # HTTP3 is not supported by curl _or_ CCF
        "--http3": {
            "errors": [
                "the installed libcurl version doesn't support this",
                "the installed libcurl version does not support this",
                "option --http3: is unknown",
            ]
        },
    }
    if args.http2:
        protocols.update(
            {
                # HTTP/1.x requests fail with closed connection, as HTTP/2
                "--http1.0": {"errors": ["Empty reply from server"]},
                "--http1.1": {"errors": ["Empty reply from server"]},
                # TLS handshake negotiates HTTP/2
                "--http2": {},
                "--http2-prior-knowledge": {},
            }
        )
    else:  # HTTP/1.1
        protocols.update(
            {
                # HTTP/1.x requests succeed, as HTTP/1.1
                "--http1.0": {},
                "--http1.1": {},
                # TLS handshake negotiates HTTP/1.1
                "--http2": {},
                # This is disabled because the behaviour of curl differs from version 8.10, so we do not get consistent results across platforms
                # "--http2-prior-knowledge": {},
            }
        )

    # Test additional protocols with curl
    for protocol, expected_result in protocols.items():
        LOG.debug(protocol)
        cmd = ["curl", *common_options]
        if "extra_args" in expected_result:
            cmd.extend(expected_result["extra_args"])
        else:
            cmd.append(protocol)
        res = infra.proc.ccall(*cmd)
        if "errors" not in expected_result:
            response_body, status_code, http_version = parse_result_out(res)
            assert (
                response_body == expected_response_body
            ), f"{response_body}\n !=\n{expected_response_body}"
            assert status_code == "200", status_code
            assert http_version == "2" if args.http2 else "1.1", http_version
        else:
            assert res.returncode != 0, res.returncode
            err = res.stderr.decode()
            expected_errors = expected_result["errors"]
            assert any(expected_error in err for expected_error in expected_errors), err

    # Valid transactions are still accepted
    network.txs.issue(
        network=network,
        number_txs=1,
    )
    # HTTP/2 does not support forwarding
    if not args.http2:
        network.txs.issue(
            network=network,
            number_txs=1,
            on_backup=True,
        )
        network.txs.verify()

    return network


@reqs.description("Write/Read/Delete messages on primary")
@reqs.supports_methods("/app/log/private")
def test_remove(network, args):
    check = infra.checker.Checker()

    for priv in [True, False]:
        txid = network.txs.issue(network, send_public=not priv, send_private=priv)
        _, log_id = network.txs.get_log_id(txid)
        network.txs.delete(log_id, priv=priv)
        r = network.txs.request(log_id, priv=priv)
        check(
            r,
            error=lambda status, msg: status == http.HTTPStatus.NOT_FOUND.value
            and msg.json()["error"]["code"] == "ResourceNotFound",
        )

    return network


@reqs.description("Write/Read/Clear messages on primary")
@reqs.supports_methods("/app/log/private/all", "/app/log/public/all")
@app.scoped_txs()
def test_clear(network, args):
    primary, _ = network.find_primary()

    with primary.client() as nc:
        check_commit = infra.checker.Checker(nc)
        check = infra.checker.Checker()

        start_log_id = 7
        with primary.client("user0") as c:
            log_ids = list(range(start_log_id, start_log_id + 10))
            msg = "Will be deleted"

            for table in ["private", "public"]:
                resource = f"/app/log/{table}"
                for log_id in log_ids:
                    check_commit(
                        c.post(resource, {"id": log_id, "msg": msg}),
                        result=True,
                    )
                    check(c.get(f"{resource}?id={log_id}"), result={"msg": msg})
                check(
                    c.delete(f"{resource}/all"),
                    result=None,
                )
                for log_id in log_ids:
                    get_r = c.get(f"{resource}?id={log_id}")
                    check(
                        get_r,
                        error=lambda status, msg: status
                        == http.HTTPStatus.NOT_FOUND.value,
                    )

    # Make sure no-one else is still looking for these
    network.txs.clear()
    return network


@reqs.description("Count messages on primary")
@reqs.supports_methods("/app/log/private/count", "/app/log/public/count")
@app.scoped_txs()
def test_record_count(network, args):
    primary, _ = network.find_primary()

    with primary.client() as nc:
        check_commit = infra.checker.Checker(nc)
        check = infra.checker.Checker()

        with primary.client("user0") as c:
            msg = "Will be deleted"

            def get_count(resource):
                r_get = c.get(f"{resource}/count")
                assert r_get.status_code == http.HTTPStatus.OK
                return int(r_get.body.json())

            for table in ["private", "public"]:
                resource = f"/app/log/{table}"

                count = get_count(resource)

                # Add several new IDs
                start_log_id = 7
                for i in range(10):
                    log_id = start_log_id + i
                    check_commit(
                        c.post(resource, {"id": log_id, "msg": msg}),
                        result=True,
                    )
                    new_count = get_count(resource)
                    assert (
                        new_count == count + 1
                    ), f"Added one ID after {count}, but found {new_count} resulting IDs"
                    count = new_count

                # Clear all IDs
                check(
                    c.delete(f"{resource}/all"),
                    result=None,
                )
                new_count = get_count(resource)
                assert new_count == 0, f"Found {new_count} remaining IDs after clear"

    # Make sure no-one else is still looking for these
    network.txs.clear()
    return network


@reqs.description("Write/Read with cert prefix")
@reqs.supports_methods("/app/log/private/prefix_cert", "/app/log/private")
def test_cert_prefix(network, args):
    msg = "This message will be prefixed"
    log_id = 7
    for user in network.users:
        network.txs.issue(
            network,
            idx=log_id,
            msg=msg,
            send_public=False,
            url_suffix="prefix_cert",
            user=user.local_id,
        )
        r = network.txs.request(log_id, priv=True, user=user.local_id)
        prefixed_msg = f"{user.service_id}: {msg}"
        network.txs.priv[log_id][-1]["msg"] = prefixed_msg
        assert prefixed_msg in r.body.json()["msg"], r

    return network


@reqs.description("Write as anonymous caller")
@reqs.supports_methods("/app/log/private/anonymous", "/app/log/private")
@app.scoped_txs()
def test_anonymous_caller(network, args):
    # Create a new user but do not record its identity
    network.create_user("user5", args.participants_curve, record=False)

    log_id = 7
    msg = "This message is anonymous"

    network.txs.issue(
        network,
        1,
        idx=log_id,
        send_public=False,
        msg=msg,
        user="user5",
        url_suffix="anonymous",
    )
    prefixed_msg = f"Anonymous: {msg}"
    network.txs.priv[log_id][-1]["msg"] = prefixed_msg

    r = network.txs.request(log_id, priv=True, user="user5")
    assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r

    r = network.txs.request(log_id, priv=True)
    assert msg in r.body.json()["msg"], r

    return network


@reqs.description("Use multiple auth types on the same endpoint")
@reqs.supports_methods("/app/multi_auth")
def test_multi_auth(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]
    member = network.consortium.members[0]

    with primary.client(user.local_id) as c:
        response_bodies = set()

        def require_new_response(r):
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code
            r_body = r.body.text()
            assert (
                "undefined" not in r_body
            ), f"Looks like you misnamed a field?\n{r_body}"
            assert r_body not in response_bodies, r_body
            response_bodies.add(r_body)

        LOG.info("Anonymous, no auth")
        with primary.client() as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("Unauthenticated"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate as a user, via TLS cert")
        with primary.client(user.local_id) as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("User TLS cert"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate as same user, now with user data")
        network.consortium.set_user_data(
            primary, user.service_id, {"some": ["interesting", "data", 42]}
        )
        with primary.client(user.local_id) as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("User TLS cert"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate as a different user, via TLS cert")
        with primary.client("user1") as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("User TLS cert"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate as a member, via TLS cert")
        with primary.client(member.local_id) as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("Member TLS cert"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate as same member, now with user data")
        network.consortium.set_member_data(
            primary, member.service_id, {"distinct": {"arbitrary": ["data"]}}
        )
        with primary.client(member.local_id) as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("Member TLS cert"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate as a different member, via TLS cert")
        with primary.client("member1") as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("Member TLS cert"), r.body.text()
            require_new_response(r)

        # Create a keypair that is not a user
        network.create_user("not_a_user", args.participants_curve, record=False)
        with primary.client("not_a_user") as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("Any TLS cert"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate via JWT token")
        jwt_issuer = infra.jwt_issuer.JwtIssuer()
        jwt_issuer.register(network)
        jwt = jwt_issuer.issue_jwt(claims={"user": "Alice"})

        with primary.client() as c:
            r = c.post("/app/multi_auth", headers={"authorization": "Bearer " + jwt})
            assert r.body.text().startswith("JWT"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate via second JWT token")
        jwt2 = jwt_issuer.issue_jwt(claims={"user": "Bob"})

        with primary.client(common_headers={"authorization": "Bearer " + jwt2}) as c:
            r = c.post("/app/multi_auth")
            assert r.body.text().startswith("JWT"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate via COSE Sign1 payload")
        with primary.client(None, None, "user1") as c:
            r = c.post("/app/multi_auth", body={"some": "content"})
            assert r.body.text().startswith("User COSE Sign1"), r.body.text()
            require_new_response(r)

        LOG.info("Authenticate via user cert AND JWT token AND COSE Sign1 payload")
        with primary.client(
            user.local_id,
            None,
            "user1",
            common_headers={"authorization": "Bearer " + jwt2},
        ) as c:
            r = c.post("/app/multi_auth", body={"some": "content"})
            assert r.body.text().startswith("Conjoined auth policy"), r.body.text()
            require_new_response(r)

    return network


@reqs.description("Call an endpoint with a custom auth policy")
@reqs.supports_methods("/app/custom_auth")
def test_custom_auth(network, args):
    primary, other = network.find_primary_and_any_backup()

    nodes = (primary, other)

    if args.http2:
        # HTTP2 doesn't support forwarding
        nodes = (primary,)

    for node in nodes:
        with node.client() as c:
            LOG.info("Request without custom headers is refused")
            r = c.get("/app/custom_auth")
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r.status_code

            name_header = "x-custom-auth-name"
            age_header = "x-custom-auth-age"

            LOG.info("Requests with partial headers are refused")
            r = c.get("/app/custom_auth", headers={name_header: "Bob"})
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r.status_code
            r = c.get("/app/custom_auth", headers={age_header: "42"})
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r.status_code

            LOG.info("Requests with unacceptable header contents are refused")
            r = c.get("/app/custom_auth", headers={name_header: "", age_header: "42"})
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r.status_code
            r = c.get(
                "/app/custom_auth", headers={name_header: "Bob", age_header: "12"}
            )
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r.status_code

            LOG.info("Request which meets all requirements is accepted")
            r = c.get(
                "/app/custom_auth", headers={name_header: "Alice", age_header: "42"}
            )
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code
            response = r.body.json()
            assert response["name"] == "Alice", response
            assert response["age"] == 42, response

    return network


@reqs.description("Call an endpoint with a custom auth policy which throws")
@reqs.supports_methods("/app/custom_auth")
def test_custom_auth_safety(network, args):
    primary, other = network.find_primary_and_any_backup()

    nodes = (primary, other)

    if args.http2:
        # HTTP2 doesn't support forwarding
        nodes = (primary,)

    for node in nodes:
        with node.client() as c:
            r = c.get(
                "/app/custom_auth",
                headers={"x-custom-auth-explode": "Boom goes the dynamite"},
            )
            assert (
                r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value
            ), r.status_code

    return network


def get_metrics(r, path, method, default=None):
    try:
        return next(
            v
            for v in r.body.json()["metrics"]
            if v["path"] == path and v["method"] == method
        )
    except StopIteration:
        return default


@reqs.description("Write non-JSON body")
@reqs.supports_methods("/app/log/private/raw_text/{id}", "/app/log/private")
@app.scoped_txs()
def test_raw_text(network, args):
    log_id = 7
    msg = "This message is not in JSON"

    r = network.txs.post_raw_text(log_id, msg)
    assert r.status_code == http.HTTPStatus.OK.value
    r = network.txs.request(log_id, priv=True)
    assert msg in r.body.json()["msg"], r

    return network


@reqs.description("Read historical state")
@reqs.supports_methods("/app/log/private", "/app/log/private/historical")
@app.scoped_txs()
def test_historical_query(network, args):
    network.txs.issue(network, number_txs=2)
    network.txs.issue(network, number_txs=2, repeat=True)
    network.txs.verify()

    primary, _ = network.find_nodes()
    with primary.client("user0") as c:
        r = c.get(
            "/app/log/private/historical",
            headers={infra.clients.CCF_TX_ID_HEADER: "99999.1"},
        )
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r
        assert r.body.json()["error"]["code"] == "TransactionInvalid", r

    primary, _ = network.find_nodes()
    with primary.client("user0") as c:
        r = c.get(
            "/app/log/private/historical",
            headers={infra.clients.CCF_TX_ID_HEADER: "99999.999999"},
        )
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r
        assert r.body.json()["error"]["code"] == "TransactionPendingOrUnknown", r

    return network


@reqs.description("Read historical receipts")
@reqs.supports_methods("/app/log/private", "/app/log/private/historical_receipt")
def test_historical_receipts(network, args):
    primary, backups = network.find_nodes()
    TXS_COUNT = 5
    start_idx = network.txs.idx + 1
    network.txs.issue(network, number_txs=TXS_COUNT)
    for idx in range(start_idx, TXS_COUNT + start_idx):
        for node in [primary, backups[0]]:
            first_msg = network.txs.priv[idx][0]
            first_receipt = network.txs.get_receipt(
                node, idx, first_msg["seqno"], first_msg["view"]
            )
            r = first_receipt.json()["receipt"]
            verify_receipt(r, network.cert)

    # receipt.verify() and ccf.receipt.check_endorsement() raise if they fail, but do not return anything
    verified = True
    try:
        ccf.receipt.verify(
            hashlib.sha256(b"").hexdigest(), r["signature"], network.cert
        )
    except InvalidSignature:
        verified = False
    assert not verified

    return network


@reqs.description("Read historical receipts with claims")
@reqs.supports_methods("/app/log/public", "/app/log/public/historical_receipt")
def test_historical_receipts_with_claims(network, args):
    primary, backups = network.find_nodes()
    TXS_COUNT = 5
    start_idx = network.txs.idx + 1
    network.txs.issue(network, number_txs=TXS_COUNT, record_claim=True)
    for idx in range(start_idx, TXS_COUNT + start_idx):
        for node in [primary, backups[0]]:
            first_msg = network.txs.pub[idx][0]
            first_receipt = network.txs.get_receipt(
                node, idx, first_msg["seqno"], first_msg["view"], domain="public"
            )
            r = first_receipt.json()["receipt"]
            verify_receipt(r, network.cert, first_receipt.json()["msg"].encode())

    # receipt.verify() and ccf.receipt.check_endorsement() raise if they fail, but do not return anything
    verified = True
    try:
        ccf.receipt.verify(
            hashlib.sha256(b"").hexdigest(), r["signature"], network.cert
        )
    except InvalidSignature:
        verified = False
    assert not verified

    return network


@reqs.description("Read genesis receipt")
def test_genesis_receipt(network, args):
    primary, _ = network.find_nodes()

    genesis_receipt = primary.get_receipt(2, 1)
    verify_receipt(genesis_receipt.json(), network.cert, generic=True)
    claims_digest = genesis_receipt.json()["leaf_components"]["claims_digest"]

    with primary.client() as client:
        constitution = client.get(
            "/gov/service/constitution?api-version=2023-06-01-preview"
        ).body.text()

    if args.package == "samples/apps/logging/logging":
        # Only the logging app sets a claim on the genesis
        assert claims_digest == sha256(constitution.encode()).hexdigest()
    else:
        assert (
            claims_digest
            == "0000000000000000000000000000000000000000000000000000000000000000"
        )

    return network


@reqs.description("Read CBOR Merkle Proof")
def test_cbor_merkle_proof(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as client:
        r = client.get("/commit")
        assert r.status_code == http.HTTPStatus.OK
        last_txid = TxID.from_str(r.body.json()["transaction_id"])

        for seqno in range(last_txid.seqno, last_txid.seqno - 10, -1):
            txid = f"{last_txid.view}.{seqno}"
            LOG.debug(f"Trying to get CBOR Merkle proof for txid {txid}")
            max_retries = 10
            found_proof = False
            for _ in range(max_retries):
                r = client.get(
                    "/log/public/cbor_merkle_proof",
                    headers={infra.clients.CCF_TX_ID_HEADER: txid},
                    log_capture=[],  # Do not emit raw binary to stdout
                )
                if r.status_code == http.HTTPStatus.OK:
                    cbor_proof = r.body.data()
                    cbor_proof_filename = os.path.join(
                        network.common_dir, f"proof_{txid}.cbor"
                    )
                    with open(cbor_proof_filename, "wb") as f:
                        f.write(cbor_proof)
                    subprocess.run(
                        ["cddl", "../cddl/ccf-tree-alg.cddl", "v", cbor_proof_filename],
                        check=True,
                    )
                    found_proof = True
                    LOG.debug(f"Checked CBOR Merkle proof for txid {txid}")
                    break
                elif r.status_code == http.HTTPStatus.ACCEPTED:
                    LOG.debug(f"Transaction {txid} accepted, retrying")
                    time.sleep(0.1)
                elif r.status_code == http.HTTPStatus.NOT_FOUND:
                    LOG.debug(f"Transaction {txid} is a signature")
                    break
            else:
                assert (
                    False
                ), f"Failed to get receipt for txid {txid} after {max_retries} retries"
            if found_proof:
                break
        else:
            assert False, "Failed to find a non-signature in the last 10 transactions"

    return network


@reqs.description("Check COSE signature CDDL model")
def test_cose_signature_schema(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as client:
        r = client.get("/commit")
        assert r.status_code == http.HTTPStatus.OK
        txid = TxID.from_str(r.body.json()["transaction_id"])
        max_retries = 10
        for _ in range(max_retries):
            response = client.get(
                "/log/public/cose_signature",
                headers={infra.clients.CCF_TX_ID_HEADER: f"{txid.view}.{txid.seqno}"},
            )

            if response.status_code == http.HTTPStatus.OK:
                signature = response.body.json()["cose_signature"]
                signature = base64.b64decode(signature)
                signature_filename = os.path.join(
                    network.common_dir, f"cose_signature_{txid}.cose"
                )
                with open(signature_filename, "wb") as f:
                    f.write(signature)
                subprocess.run(
                    [
                        "cddl",
                        "../cddl/ccf-merkle-tree-cose-signature.cddl",
                        "v",
                        signature_filename,
                    ],
                    check=True,
                )
                LOG.debug(f"Checked COSE signature schema for txid {txid}")
                break
            elif response.status_code == http.HTTPStatus.ACCEPTED:
                LOG.debug(f"Transaction {txid} accepted, retrying")
                time.sleep(0.1)
            else:
                LOG.error(f"Failed to get COSE signature for txid {txid}")
                break
        else:
            assert (
                False
            ), f"Failed to get receipt for txid {txid} after {max_retries} retries"

    return network


@reqs.description("Check COSE receipt CDDL schema")
def test_cose_receipt_schema(network, args):
    primary, _ = network.find_nodes()

    # Make sure the last transaction does not contain application claims
    member = network.consortium.get_any_active_member()
    r = member.update_ack_state_digest(primary)
    with primary.client() as client:
        client.wait_for_commit(r)

    txid = r.headers[infra.clients.CCF_TX_ID_HEADER]

    service_cert_path = os.path.join(network.common_dir, "service_cert.pem")
    service_cert = load_pem_x509_certificate(
        open(service_cert_path, "rb").read(), default_backend()
    )
    service_key = service_cert.public_key()

    with primary.client("user0") as client:
        LOG.debug(f"Trying to get COSE receipt for txid {txid}")
        max_retries = 10
        for _ in range(max_retries):
            r = client.get(
                "/log/public/cose_receipt",
                headers={infra.clients.CCF_TX_ID_HEADER: txid},
                log_capture=[],  # Do not emit raw binary to stdout
            )

            if r.status_code == http.HTTPStatus.OK:
                cbor_proof = r.body.data()
                receipt_phdr = ccf.cose.verify_receipt(
                    cbor_proof, service_key, b"\0" * 32
                )
                assert receipt_phdr[15][1] == "service.example.com"
                assert receipt_phdr[15][2] == "ledger.signature"
                cbor_proof_filename = os.path.join(
                    network.common_dir, f"receipt_{txid}.cose"
                )
                with open(cbor_proof_filename, "wb") as f:
                    f.write(cbor_proof)
                subprocess.run(
                    ["cddl", "../cddl/ccf-receipt.cddl", "v", cbor_proof_filename],
                    check=True,
                )
                LOG.debug(f"Checked COSE receipt for txid {txid}")
                break
            elif r.status_code == http.HTTPStatus.ACCEPTED:
                LOG.debug(f"Transaction {txid} accepted, retrying")
                time.sleep(0.1)
            else:
                assert False, r
        else:
            assert (
                False
            ), f"Failed to get receipt for txid {txid} after {max_retries} retries"

    return network


@reqs.description("Read range of historical state")
@reqs.supports_methods("/app/log/public", "/app/log/public/historical/range")
def test_historical_query_range(network, args):
    id_a = 142
    id_b = 143
    id_c = 144

    first_seqno = None
    last_seqno = None

    primary, _ = network.find_primary()
    with primary.client("user0") as c:
        # Submit many transactions, overwriting the same IDs
        # Need to submit through network.txs so these can be verified at shutdown, but also need to submit one at a
        # time to retrieve the submitted transactions
        msgs = {}
        n_entries = 100

        def id_for(i):
            if i == n_entries // 2:
                return id_c
            else:
                return id_b if i % 3 == 0 else id_a

        for i in range(n_entries):
            idx = id_for(i)

            network.txs.issue(
                network,
                repeat=True,
                idx=idx,
                wait_for_sync=False,
                log_capture=[],
            )
            _, tx = network.txs.get_last_tx(idx=idx, priv=False)
            msg = tx["msg"]
            seqno = tx["seqno"]
            view = tx["view"]
            msgs[seqno] = msg

            if first_seqno is None:
                first_seqno = seqno

            last_seqno = seqno

        infra.commit.wait_for_commit(c, seqno=last_seqno, view=view, timeout=3)

        LOG.info("Checking error responses")
        # Reversed range is illegal
        r = c.get(
            f"/app/log/public/historical/range?from_seqno={last_seqno}&to_seqno=1&id={id_a}"
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST
        assert r.body.json()["error"]["code"] == "InvalidInput"
        r = c.get(
            f"/app/log/public/historical/range?from_seqno={last_seqno}&to_seqno={last_seqno-1}&id={id_a}"
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST
        assert r.body.json()["error"]["code"] == "InvalidInput"

        # Asking for future seqnos gives a clear error
        # - First find latest valid seqno
        r = c.get("/node/commit")
        assert r.status_code == http.HTTPStatus.OK
        last_valid_seqno = TxID.from_str(r.body.json()["transaction_id"]).seqno

        # - Try a very invalid seqno
        r = c.get(
            f"/app/log/public/historical/range?to_seqno={last_valid_seqno*2}&id={id_a}"
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST
        assert r.body.json()["error"]["code"] == "InvalidInput"

        # - Try the first invalid seqno.
        # !! If implicit TX occurs during this time, fetch last TX id and retry.
        attemtps = 5
        for _ in range(0, attemtps):
            r = c.get(
                f"/app/log/public/historical/range?to_seqno={last_valid_seqno+1}&id={id_a}"
            )
            if r.status_code == http.HTTPStatus.BAD_REQUEST:
                break

            r = c.get("/node/commit")
            assert r.status_code == http.HTTPStatus.OK
            last_valid_seqno = TxID.from_str(r.body.json()["transaction_id"]).seqno

        assert r.status_code == http.HTTPStatus.BAD_REQUEST
        assert r.body.json()["error"]["code"] == "InvalidInput"

        LOG.info("Verifying historical ranges")
        entries_a, _ = network.txs.verify_range_for_idx(id_a, node=primary)
        entries_b, _ = network.txs.verify_range_for_idx(id_b, node=primary)
        entries_c, _ = network.txs.verify_range_for_idx(id_c, node=primary)

        # Fetching A and B should take a similar amount of time, C (which was only written to in a brief window in the history) should be much faster
        # NB: With larger page size, this is not necessarily true! Small range means _all_ responses fit in a single response page
        # assert duration_c < duration_a
        # assert duration_c < duration_b

        # Confirm that we can retrieve these with more specific queries, and we end up with the same result
        alt_a, _ = network.txs.verify_range_for_idx(
            id_a, node=primary, from_seqno=first_seqno
        )
        assert alt_a == entries_a
        alt_a, _ = network.txs.verify_range_for_idx(
            id_a, node=primary, to_seqno=last_seqno
        )
        assert alt_a == entries_a
        alt_a, _ = network.txs.verify_range_for_idx(
            id_a, node=primary, from_seqno=first_seqno, to_seqno=last_seqno
        )
        assert alt_a == entries_a

        actual_len = len(entries_a) + len(entries_b) + len(entries_c)
        assert (
            n_entries == actual_len
        ), f"Expected {n_entries} total entries, got {actual_len}"

        # Iterate through both lists, by i, checking retrieved entries match expectations
        for i in range(n_entries):
            expected_id = id_for(i)
            entries = (
                entries_a
                if expected_id == id_a
                else (entries_b if expected_id == id_b else entries_c)
            )
            entry = entries.pop(0)
            assert entry["id"] == expected_id
            assert entry["msg"] == msgs[entry["seqno"]]

        # Make sure this has checked every entry
        assert len(entries_a) == 0
        assert len(entries_b) == 0
        assert len(entries_c) == 0

    return network


@reqs.description("Read state at multiple distinct historical points")
@reqs.supports_methods("/app/log/private", "/app/log/private/historical/sparse")
def test_historical_query_sparse(network, args):
    idx = 142

    seqnos = []

    primary, _ = network.find_primary()
    with primary.client("user0") as c:
        # Submit many transactions, overwriting the same ID
        # Need to submit through network.txs so these can be verified at shutdown, but also need to submit one at a
        # time to retrieve the submitted transactions
        msgs = {}
        n_entries = 100

        for _ in range(n_entries):
            network.txs.issue(
                network,
                repeat=True,
                idx=idx,
                wait_for_sync=False,
                log_capture=[],
                send_public=False,
            )
            _, tx = network.txs.get_last_tx(idx=idx)
            msg = tx["msg"]
            seqno = tx["seqno"]
            view = tx["view"]
            msgs[seqno] = msg

            seqnos.append(seqno)

        infra.commit.wait_for_commit(c, seqno=seqnos[-1], view=view, timeout=3)

        def get_sparse(client, target_id, seqnos, timeout=3):
            seqnos_s = ",".join(str(n) for n in seqnos)
            LOG.info(f"Getting historical entries: {seqnos_s}")
            logs = []

            start_time = time.time()
            end_time = start_time + timeout
            entries = {}
            path = (
                f"/app/log/private/historical/sparse?id={target_id}&seqnos={seqnos_s}"
            )
            while time.time() < end_time:
                r = client.get(path, log_capture=logs)
                if r.status_code == http.HTTPStatus.OK:
                    j_body = r.body.json()
                    for entry in j_body["entries"]:
                        assert entry["id"] == target_id, entry
                        entries[entry["seqno"]] = entry["msg"]
                    duration = time.time() - start_time
                    LOG.info(
                        f"Done! Fetched {len(entries)} entries in {duration:0.2f}s"
                    )
                    return entries, duration
                elif r.status_code == http.HTTPStatus.ACCEPTED:
                    # Ignore retry-after header, retry soon
                    time.sleep(0.1)
                    continue
                else:
                    LOG.error("Printing historical/sparse logs on unexpected status")
                    flush_info(logs, None)
                    raise ValueError(
                        f"Unexpected status code from historical sparse query: {r.status_code}"
                    )

            LOG.error("Printing historical/sparse logs on timeout")
            flush_info(logs, None)
            raise TimeoutError(
                f"Historical sparse query not available after {timeout}s"
            )

        entries_all, _ = get_sparse(c, idx, seqnos)

        seqnos_a = [s for s in seqnos if random.random() < 0.7]
        entries_a, _ = get_sparse(c, idx, seqnos_a)
        seqnos_b = [s for s in seqnos if random.random() < 0.5]
        entries_b, _ = get_sparse(c, idx, seqnos_b)
        small_range = len(seqnos) // 20
        seqnos_c = seqnos[:small_range] + seqnos[-small_range:]
        entries_c, _ = get_sparse(c, idx, seqnos_c)

        def check_presence(expected, entries, seqno):
            if seqno in expected:
                assert seqno in entries, f"Missing result for {seqno}"
                assert (
                    entries[seqno] == msgs[seqno]
                ), f"{entries[seqno]} != {msgs[seqno]}"

        for seqno in seqnos:
            check_presence(seqnos, entries_all, seqno)
            check_presence(seqnos_a, entries_a, seqno)
            check_presence(seqnos_b, entries_b, seqno)
            check_presence(seqnos_c, entries_c, seqno)

    return network


def escaped_query_tests(c, endpoint):
    samples = [
        {"this": "that"},
        {"this": "that", "other": "with spaces"},
        {"this with spaces": "with spaces"},
        {"arg": 'This has many@many many \\% " AWKWARD :;-=?!& characters %20%20'},
    ]
    for query in samples:
        unescaped_query = "&".join([f"{k}={v}" for k, v in query.items()])
        query_to_send = unescaped_query
        if os.getenv("CURL_CLIENT"):
            query_to_send = urllib.parse.urlencode(query)
        r = c.get(f"/app/log/{endpoint}?{query_to_send}")
        assert r.body.text() == unescaped_query, (
            r.body.text(),
            unescaped_query,
        )

    all_chars = list(range(0, 255))
    max_args = 50
    for ichars in [
        all_chars[i : i + max_args] for i in range(0, len(all_chars), max_args)
    ]:
        encoded, raw = [], []
        for ichar in ichars:
            char = chr(ichar)
            encoded.append(urllib.parse.urlencode({"arg": char}))
            raw.append(f"arg={char}")

        r = c.get(f"/app/log/{endpoint}?{'&'.join(encoded)}")
        assert r.body.data() == "&".join(raw).encode(), r.body.data()

        encoded, raw = [], []
        for ichar in ichars:
            char = chr(ichar)
            encoded.append(urllib.parse.urlencode({f"arg{char}": "value"}))
            raw.append(f"arg{char}=value")

        r = c.get(f"/app/log/{endpoint}?{'&'.join(encoded)}")
        assert r.body.data() == "&".join(raw).encode(), r.body.data()


@reqs.description("Testing forwarding on member and user frontends")
@reqs.supports_methods("/app/log/private")
@reqs.at_least_n_nodes(2)
@reqs.no_http2()
@app.scoped_txs()
def test_forwarding_frontends(network, args):
    backup = network.find_any_backup()

    try:
        with backup.client() as c:
            check_commit = infra.checker.Checker(c)
            ack = network.consortium.get_any_active_member().ack(backup)
            check_commit(ack)
    except AckException as e:
        assert args.http2 is True
        assert e.response.status_code == http.HTTPStatus.NOT_IMPLEMENTED
        r = e.response.body.json()
        assert (
            r["error"]["message"]
            == "Request cannot be forwarded to primary on HTTP/2 interface."
        ), r
    else:
        assert args.http2 is False

    try:
        msg = "forwarded_msg"
        log_id = 7
        network.txs.issue(
            network,
            number_txs=1,
            on_backup=True,
            idx=log_id,
            send_public=False,
            msg=msg,
        )
    except infra.logging_app.LoggingTxsIssueException as e:
        assert args.http2 is True
        assert e.response.status_code == http.HTTPStatus.NOT_IMPLEMENTED
        r = e.response.body.json()
        assert (
            r["error"]["message"]
            == "Request cannot be forwarded to primary on HTTP/2 interface."
        ), r
    else:
        assert args.http2 is False

    if args.package == "samples/apps/logging/logging" and not args.http2:
        with backup.client("user0") as c:
            escaped_query_tests(c, "request_query")

    return network


@reqs.description("Testing forwarding on user frontends without actor app prefix")
@reqs.at_least_n_nodes(2)
@reqs.no_http2()
def test_forwarding_frontends_without_app_prefix(network, args):
    msg = "forwarded_msg"
    log_id = 7
    network.txs.issue(
        network,
        number_txs=1,
        on_backup=True,
        idx=log_id,
        send_public=False,
        msg=msg,
        private_url="/log/private",
    )

    return network


@reqs.description("Testing forwarding on long-lived connection")
@reqs.supports_methods("/app/log/private")
@reqs.at_least_n_nodes(2)
@reqs.no_http2()
def test_long_lived_forwarding(network, args):
    primary, _ = network.find_primary()

    # Create a new node
    new_node = network.create_node("local://localhost")

    # Message limit must be high enough that the hard limit will not be reached
    # by the combined work of all threads. Note that each thread produces multiple
    # node-to-node messages - a forwarded write and response, Raft AEs. If these
    # arrive too fast, they will trigger the hard cap and the node-to-node keys
    # will be reset, potentially invalidating in-flight messages and causing client
    # requests to time out.
    n_threads = 5
    message_limit = 30

    new_node_args = copy.deepcopy(args)
    new_node_args.node_to_node_message_limit = message_limit
    network.join_node(new_node, args.package, new_node_args)
    network.trust_node(new_node, new_node_args)

    # Send many messages to new node over long-lived connections,
    # to confirm that forwarding continues to work during
    # node-to-node channel key rotations
    def fn(worker_id, request_count, should_log):
        with new_node.client("user0") as c:
            msg = "Will be forwarded"
            log_id = 42
            for i in range(request_count):
                logs = []
                if should_log and i % 10 == 0:
                    LOG.info(f"Sending {i} / {request_count}")
                    logs = None
                r = c.post(
                    f"/app/log/private?scope=long-lived-forwarding-{worker_id}",
                    {"id": log_id, "msg": msg},
                    log_capture=logs,
                )
                assert r.status_code == http.HTTPStatus.OK, r

    threads = []
    current_thread_name = threading.current_thread().name
    for i in range(n_threads):
        threads.append(
            threading.Thread(
                target=fn,
                args=(i, 3 * message_limit, i == 0),
                name=f"{current_thread_name}:worker-{i}",
            )
        )

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    # Remove temporary new node
    network.retire_node(primary, new_node)
    new_node.stop()

    return network


@reqs.description("Test user-data used for access permissions")
@reqs.supports_methods("/app/log/private/admin_only")
def test_user_data_ACL(network, args):
    primary, _ = network.find_primary()

    user = network.users[0]

    def by_set_user_data(user_data):
        network.consortium.set_user_data(primary, user.service_id, user_data=user_data)

    def by_set_user(user_data):
        network.consortium.add_user(primary, user.local_id, user_data=user_data)

    for set_user_data in (by_set_user_data, by_set_user):
        # Give isAdmin permissions to a single user
        set_user_data(user_data={"isAdmin": True})

        log_id = network.txs.find_max_log_id() + 1

        # Confirm that user can now use this endpoint
        with primary.client(user.local_id) as c:
            r = c.post(
                "/app/log/private/admin_only", {"id": log_id, "msg": "hello world"}
            )
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code

        # Remove permission
        set_user_data(user_data={"isAdmin": False})

        # Confirm that user is now forbidden on this endpoint
        with primary.client(user.local_id) as c:
            r = c.post(
                "/app/log/private/admin_only", {"id": log_id, "msg": "hello world"}
            )
            assert r.status_code == http.HTTPStatus.FORBIDDEN.value, r.status_code

    return network


@reqs.description("Check for commit of every prior transaction")
def test_view_history(network, args):
    check = infra.checker.Checker()

    previous_node = None
    previous_tx_ids = ""
    for node in network.get_joined_nodes():
        with node.client("user0") as c:
            r = c.get("/node/commit")
            check(c)

            commit_tx_id = TxID.from_str(r.body.json()["transaction_id"])

            # Retrieve status for all possible Tx IDs
            seqno_to_views = {}
            for seqno in range(1, commit_tx_id.seqno + 1):
                views = []
                for view in range(2, commit_tx_id.view + 1):
                    r = c.get(f"/node/tx?transaction_id={view}.{seqno}", log_capture=[])
                    check(r)
                    status = TxStatus(r.body.json()["status"])
                    if status == TxStatus.Committed:
                        views.append(view)
                seqno_to_views[seqno] = views

            # Check we have exactly one Tx ID for each seqno
            txs_ok = True
            for seqno, views in seqno_to_views.items():
                if len(views) != 1:
                    txs_ok = False
                    LOG.error(
                        f"Node {node.node_id}: Found {len(views)} committed Tx IDs for seqno {seqno}"
                    )

            tx_ids_condensed = ", ".join(
                " OR ".join(f"{view}.{seqno}" for view in views or ["UNKNOWN"])
                for seqno, views in seqno_to_views.items()
            )

            if txs_ok:
                LOG.success(
                    f"Node {node.node_id}: Found a valid sequence of Tx IDs:\n{tx_ids_condensed}"
                )
            else:
                LOG.error(
                    f"Node {node.node_id}: Invalid sequence of Tx IDs:\n{tx_ids_condensed}"
                )
                raise RuntimeError(
                    f"Node {node.node_id}: Incomplete or inconsistent view history"
                )

            # Compare view history between nodes
            if previous_tx_ids:
                # Some nodes may have a slightly longer view history so only compare the common prefix
                min_tx_ids_len = min(len(previous_tx_ids), len(tx_ids_condensed))
                assert (
                    tx_ids_condensed[:min_tx_ids_len]
                    == previous_tx_ids[:min_tx_ids_len]
                ), f"Tx IDs don't match between node {node.node_id} and node {previous_node.node_id}: {tx_ids_condensed[:min_tx_ids_len]} and {previous_tx_ids[:min_tx_ids_len]}"

            previous_tx_ids = tx_ids_condensed
            previous_node = node

    return network


class SentTxs:
    # view -> seqno -> status
    txs = defaultdict(lambda: defaultdict(lambda: TxStatus.Unknown))

    @staticmethod
    def update_status(view, seqno, status=None):
        current_status = SentTxs.txs[view][seqno]
        if status is None:
            # If you don't know the current status, we exit here. Since we have
            # accessed the value in the defaultdict, we have recorded this tx id
            # so it will be returned by future calls to get_all_tx_ids()
            return

        if status != current_status:
            valid = False
            # Only valid transitions from Unknown to any, or Pending to Committed/Invalid
            if current_status == TxStatus.Unknown:
                valid = True
            elif current_status == TxStatus.Pending and (
                status == TxStatus.Committed or status == TxStatus.Invalid
            ):
                valid = True

            if valid:
                SentTxs.txs[view][seqno] = status
            else:
                raise ValueError(
                    f"Transaction {view}.{seqno} making invalid transition from {current_status} to {status}"
                )

    @staticmethod
    def get_all_tx_ids():
        return [
            (view, seqno)
            for view, view_txs in SentTxs.txs.items()
            for seqno, status in view_txs.items()
        ]


@reqs.description("Build a list of Tx IDs, check they transition states as expected")
@reqs.supports_methods("/app/log/private")
@app.scoped_txs()
def test_tx_statuses(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        check = infra.checker.Checker()
        r = network.txs.issue(network, 1, idx=0, send_public=False, msg="Ignored")
        # Until this tx is committed, poll for the status of this and some other
        # related transactions around it (and also any historical transactions we're tracking)
        target_view = r.view
        target_seqno = r.seqno
        SentTxs.update_status(target_view, target_seqno)
        SentTxs.update_status(target_view, target_seqno + 1)
        SentTxs.update_status(target_view - 1, target_seqno)

        end_time = time.time() + 10
        while True:
            if time.time() > end_time:
                raise TimeoutError(
                    f"Took too long waiting for commit of {target_view}.{target_seqno}"
                )

            done = False
            for view, seqno in SentTxs.get_all_tx_ids():
                r = c.get(f"/node/tx?transaction_id={view}.{seqno}")
                check(r)
                status = TxStatus(r.body.json()["status"])
                SentTxs.update_status(view, seqno, status)
                if (
                    status == TxStatus.Committed
                    and target_view == view
                    and target_seqno == seqno
                ):
                    done = True

            if done:
                break
            time.sleep(0.1)

    return network


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("/app/receipt", "/app/log/private")
@reqs.at_least_n_nodes(2)
@app.scoped_txs()
def test_receipts(network, args):
    primary, _ = network.find_primary_and_any_backup()
    msg = "Hello world"

    LOG.info("Write/Read on primary")
    with primary.client("user0") as c:
        for j in range(10):
            idx = j + 10000
            r = network.txs.issue(network, 1, idx=idx, send_public=False, msg=msg)
            start_time = time.time()
            while time.time() < (start_time + 3.0):
                rc = c.get(f"/app/receipt?transaction_id={r.view}.{r.seqno}")
                if rc.status_code == http.HTTPStatus.OK:
                    receipt = rc.body.json()
                    verify_receipt(receipt, network.cert)
                    break
                elif rc.status_code == http.HTTPStatus.ACCEPTED:
                    time.sleep(0.5)
                else:
                    assert False, rc

    return network


@reqs.description("Validate random receipts")
@reqs.supports_methods("/app/receipt", "/app/log/private")
@reqs.at_least_n_nodes(2)
def test_random_receipts(
    network,
    args,
    lts=True,
    additional_seqnos=MappingProxyType({}),
    node=None,
    log_capture=None,
):
    if node is None:
        node, _ = network.find_primary_and_any_backup()

    common = os.listdir(network.common_dir)
    cert_paths = [
        os.path.join(network.common_dir, path)
        for path in common
        if re.compile(r"^\d+\.pem$").match(path)
    ]
    certs = {}
    for path in cert_paths:
        with open(path, encoding="utf-8") as c:
            cert = c.read()
        certs[infra.crypto.compute_public_key_der_hash_hex_from_pem(cert)] = cert

    with node.client("user0") as c:
        r = c.get("/app/commit")
        max_view, max_seqno = [
            int(e) for e in r.body.json()["transaction_id"].split(".")
        ]
        view = 2
        genesis_seqno = 1
        likely_first_sig_seqno = 2
        last_sig_seqno = max_seqno
        interesting_prefix = [genesis_seqno, likely_first_sig_seqno]
        seqnos = range(len(interesting_prefix) + 1, max_seqno)
        random_sample_count = 20 if lts else 50
        for s in (
            interesting_prefix
            + sorted(
                random.sample(seqnos, min(random_sample_count, len(seqnos)))
                + list(additional_seqnos.keys())
            )
            + [last_sig_seqno]
        ):
            start_time = time.time()
            while time.time() < (start_time + 3.0):
                rc = c.get(
                    f"/app/receipt?transaction_id={view}.{s}", log_capture=log_capture
                )
                if rc.status_code == http.HTTPStatus.OK:
                    receipt = rc.body.json()
                    if "leaf" in receipt:
                        if not lts:
                            assert "proof" in receipt, receipt
                            assert len(receipt["proof"]) == 0, receipt
                        # Legacy signature receipt
                        LOG.warning(
                            f"Skipping verification of signature receipt at {view}.{s}"
                        )
                    else:
                        if lts and not receipt.get("cert"):
                            receipt["cert"] = certs[receipt["node_id"]]
                        verify_receipt(
                            receipt,
                            network.cert,
                            claims=additional_seqnos.get(s),
                            generic=True,
                            skip_cert_chain_checks=lts,
                        )
                    break
                elif rc.status_code == http.HTTPStatus.ACCEPTED:
                    time.sleep(0.1)
                else:
                    view += 1
                    if view > max_view:
                        assert False, rc

    return network


@reqs.description("Test basic app liveness")
@reqs.at_least_n_nodes(1)
@app.scoped_txs()
def test_liveness(network, args):
    network.txs.issue(
        network=network,
        number_txs=3,
    )
    network.txs.verify()
    return network


@reqs.description("Rekey the ledger once")
@reqs.at_least_n_nodes(1)
def test_rekey(network, args):
    primary, _ = network.find_primary()
    network.consortium.trigger_ledger_rekey(primary)
    return network


@reqs.description("Test empty URI behaviour")
def test_empty_path(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/")
        assert r.status_code == http.HTTPStatus.NOT_FOUND
        r = c.post("/")
        assert r.status_code == http.HTTPStatus.NOT_FOUND


@reqs.description("Test UDP echo endpoint")
@reqs.at_least_n_nodes(1)
def test_udp_echo(network, args):
    # For now, only test UDP on primary
    primary, _ = network.find_primary()
    udp_interface = primary.host.rpc_interfaces["udp_interface"]
    host = udp_interface.public_host
    port = udp_interface.public_port
    LOG.info(f"Testing UDP echo server at {host}:{port}")

    server_address = (host, port)
    buffer_size = 1024
    test_string = b"Some random text"
    attempts = 10
    attempt = 1

    while attempt <= attempts:
        LOG.info(f"Testing UDP echo server sending '{test_string}'")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(test_string, server_address)
            recv = s.recvfrom(buffer_size)
        text = recv[0]
        LOG.info(f"Testing UDP echo server received '{text}'")
        assert text == test_string
        attempt = attempt + 1


@reqs.description("Check post-local-commit failure handling")
@reqs.supports_methods("/app/log/private/anonymous/v2")
def test_post_local_commit_failure(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.post(
            "/app/log/private/anonymous/v2?fail=false", {"id": 100, "msg": "hello"}
        )
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["success"] is True
        TxID.from_str(r.body.json()["tx_id"])

        r = c.post(
            "/app/log/private/anonymous/v2?fail=true", {"id": 101, "msg": "world"}
        )
        assert (
            r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value
        ), r.status_code
        txid_header_key = "x-ms-ccf-transaction-id"
        # check we can parse the txid from the header
        # this gets set since the post-commit handler threw
        TxID.from_str(r.headers[txid_header_key])
        assert r.body.json() == {
            "error": {
                "code": "InternalError",
                "message": "Failed to execute local commit handler func: didn't set user_data!",
            }
        }, r.body.json()


@reqs.description(
    "Check that the committed index gets populated with creates and deletes"
)
@reqs.supports_methods("/app/log/private/committed", "/app/log/private")
def test_committed_index(network, args, timeout=5):
    def get_strategies(client):
        # Also test /node/index/strategies here, since this test already adds and
        # removes indexing strategies
        res = client.get("/node/index/strategies")
        assert res.status_code == http.HTTPStatus.OK
        # Dictify here for easy lookup
        return {o["name"]: o for o in res.body.json()}

    remote_node, _ = network.find_primary()
    strategy_name = "CommittedRecords records"
    with remote_node.client() as c:
        strategies = get_strategies(c)
        assert strategy_name not in strategies

        res = c.post("/app/log/private/install_committed_index")
        assert res.status_code == http.HTTPStatus.OK

        strategies = get_strategies(c)
        assert strategy_name in strategies

    txid = network.txs.issue(network, number_txs=1, send_public=False)

    _, log_id = network.txs.get_log_id(txid)

    start_time = time.time()
    end_time = start_time + timeout
    while time.time() < end_time:
        r = network.txs.request(log_id, priv=True, url_suffix="committed")
        if r.status_code == http.HTTPStatus.OK.value:
            break

        current_tx_id = TxID.from_str(r.body.json()["error"]["current_txid"])

        LOG.info(f"Current Tx ID ({current_tx_id}) - Tx ID ({txid})")
        if current_tx_id >= txid:
            break

        LOG.warning("Current Tx ID is behind, retrying...")
        time.sleep(1)

    assert r.status_code == http.HTTPStatus.OK.value, r.status_code
    assert r.body.json() == {"msg": f"Private message at idx {log_id} [0]"}

    network.txs.delete(log_id, priv=True)

    r = network.txs.request(log_id, priv=True)
    assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code
    assert r.body.json()["error"]["message"] == f"No such record: {log_id}."
    assert r.body.json()["error"]["code"] == "ResourceNotFound"

    r = network.txs.request(log_id, priv=True, url_suffix="committed")
    assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
    assert r.body.json()["error"]["message"] == f"No such record: {log_id}."
    assert r.body.json()["error"]["code"] == "ResourceNotFound"

    # Uninstall index before proceeding
    with remote_node.client() as c:
        res = c.post("/app/log/private/uninstall_committed_index")
        assert res.status_code == http.HTTPStatus.OK

        strategies = get_strategies(c)
        assert strategy_name not in strategies


@reqs.description(
    "Check BasicConstraints are set correctly on network and node certificates"
)
def test_basic_constraints(network, args):
    primary, _ = network.find_primary()

    ca_path = os.path.join(network.common_dir, "service_cert.pem")
    with open(ca_path, encoding="utf-8") as ca:
        ca_pem = ca.read()
    ca_cert = load_pem_x509_certificate(ca_pem.encode(), default_backend())
    basic_constraints = ca_cert.extensions.get_extension_for_oid(
        ObjectIdentifier("2.5.29.19")
    )
    assert basic_constraints.critical is True
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 1

    node_pem = primary.get_tls_certificate_pem()
    node_cert = load_pem_x509_certificate(node_pem.encode(), default_backend())
    basic_constraints = node_cert.extensions.get_extension_for_oid(
        ObjectIdentifier("2.5.29.19")
    )
    assert basic_constraints.critical is True
    assert basic_constraints.value.ca is False


def test_etags(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        doc = {"id": 999999, "msg": "hello world"}
        etag = sha256(doc["msg"].encode()).hexdigest()

        # POST ETag matches value
        r = c.post("/app/log/public", doc)
        assert r.status_code == http.HTTPStatus.OK
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # GET ETag matches value
        r = c.get(f"/app/log/public?id={doc['id']}")
        assert r.status_code == http.HTTPStatus.OK
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # GET If-Match: * for missing resource still returns 404
        r = c.get("/app/log/public?id=999998", headers={"If-Match": "*"})
        assert r.status_code == http.HTTPStatus.NOT_FOUND

        # GET If-Match: * for existing resource returns 200
        r = c.get(f"/app/log/public?id={doc['id']}", headers={"If-Match": "*"})
        assert r.status_code == http.HTTPStatus.OK
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # GET If-Match: mismatching ETag returns 412
        r = c.get(f"/app/log/public?id={doc['id']}", headers={"If-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.PRECONDITION_FAILED
        assert r.body.json()["error"]["code"] == "PreconditionFailed"

        # GET If-Match: matching ETag returns 200
        r = c.get(f"/app/log/public?id={doc['id']}", headers={"If-Match": f'"{etag}"'})
        assert r.status_code == http.HTTPStatus.OK
        assert r.body.json() == {"msg": doc["msg"]}

        # GET If-Match: multiple ETags including matching returns 200
        r = c.get(
            f"/app/log/public?id={doc['id']}", headers={"If-Match": f'"{etag}", "abc"'}
        )
        assert r.status_code == http.HTTPStatus.OK
        assert r.body.json() == {"msg": doc["msg"]}

        doc = {"id": 999999, "msg": "saluton mondo"}

        # POST If-Match: mismatching ETag returns 412
        r = c.post("/app/log/public", doc, headers={"If-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.PRECONDITION_FAILED

        # POST If-Match: matching ETag returns 200
        r = c.post("/app/log/public", doc, headers={"If-Match": f'"{etag}"'})
        assert r.status_code == http.HTTPStatus.OK
        etag = sha256(doc["msg"].encode()).hexdigest()
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # POST If-Match: mutiple ETags, first one matching returns 200
        r = c.post("/app/log/public", doc, headers={"If-Match": f'"{etag}", "abc"'})
        assert r.status_code == http.HTTPStatus.OK
        etag = sha256(doc["msg"].encode()).hexdigest()
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # POST If-Match: mutiple ETags, one, not the first, matching returns 200
        r = c.post("/app/log/public", doc, headers={"If-Match": f'"abc", "{etag}"'})
        assert r.status_code == http.HTTPStatus.OK
        etag = sha256(doc["msg"].encode()).hexdigest()
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # POST If-Match: multiple, none matching, returns 412
        r = c.post("/app/log/public", doc, headers={"If-Match": '"abc", "def"'})
        assert r.status_code == http.HTTPStatus.PRECONDITION_FAILED

        # POST If-None-Match: * on existing resource returns 412
        r = c.post("/app/log/public", doc, headers={"If-None-Match": "*"})
        assert r.status_code == http.HTTPStatus.PRECONDITION_FAILED
        etag = sha256(doc["msg"].encode()).hexdigest()

        # POST If-None-Match: matching ETag on existing resource returns 412
        r = c.post("/app/log/public", doc, headers={"If-None-Match": "*"})
        assert r.status_code == http.HTTPStatus.PRECONDITION_FAILED
        etag = sha256(doc["msg"].encode()).hexdigest()

        # DELETE If-Match: mismatching ETag returns 412
        r = c.delete(f"/app/log/public?id={doc['id']}", headers={"If-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.PRECONDITION_FAILED

        # DELETE If-Match: matching ETag returns 200
        r = c.delete(
            f"/app/log/public?id={doc['id']}", headers={"If-Match": f'"{etag}"'}
        )
        assert r.status_code == http.HTTPStatus.OK

        # DELETE If-Match: missing resource still returns 200
        r = c.delete(
            f"/app/log/public?id={doc['id']}", headers={"If-Match": f'"{etag}"'}
        )
        assert r.status_code == http.HTTPStatus.OK

        # DELETE If-Match: mismatching ETag for missing resouce still returns 200
        r = c.delete(f"/app/log/public?id={doc['id']}", headers={"If-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.OK

        # Restore resource
        r = c.post("/app/log/public", doc)
        assert r.status_code == http.HTTPStatus.OK
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # GET If-None-Match: * for existing resource returns 304
        r = c.get("/app/log/public?id=999999", headers={"If-None-Match": "*"})
        assert r.status_code == http.HTTPStatus.NOT_MODIFIED

        # GET If-None-Match: matching ETag for existing resource returns 304
        r = c.get("/app/log/public?id=999999", headers={"If-None-Match": f'"{etag}"'})
        assert r.status_code == http.HTTPStatus.NOT_MODIFIED

        # GET If-None-Match: mismatching ETag for existing resource returns 200
        r = c.get("/app/log/public?id=999999", headers={"If-None-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.OK
        assert r.body.json() == {"msg": doc["msg"]}
        assert r.headers["ETag"] == etag, r.headers["ETag"]

        # DELETE If-None-Match: * on missing resource returns 304
        r = c.delete("/app/log/public?id=999998", headers={"If-None-Match": "*"})
        assert r.status_code == http.HTTPStatus.OK

        # DELETE If-None-Match: on mismatching ETag for missing resource 200
        r = c.delete("/app/log/public?id=999998", headers={"If-None-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.OK

        # DELETE If-None-Match: * on existing resource is 304
        r = c.delete(f"/app/log/public?id={doc['id']}", headers={"If-None-Match": "*"})
        assert r.status_code == http.HTTPStatus.NOT_MODIFIED
        r = c.get(f"/app/log/public?id={doc['id']}")
        assert r.status_code == http.HTTPStatus.OK

        # DELETE If-None-Match: matching ETag on existing resource is 304
        r = c.delete(
            f"/app/log/public?id={doc['id']}", headers={"If-None-Match": f'"{etag}"'}
        )
        assert r.status_code == http.HTTPStatus.NOT_MODIFIED
        r = c.get(f"/app/log/public?id={doc['id']}")
        assert r.status_code == http.HTTPStatus.OK

        # DELETE If-None-Match: mismatching ETag on existing resource is 200
        r = c.delete(
            f"/app/log/public?id={doc['id']}", headers={"If-None-Match": '"abc"'}
        )
        assert r.status_code == http.HTTPStatus.OK
        r = c.get(f"/app/log/public?id={doc['id']}")
        assert r.status_code == http.HTTPStatus.NOT_FOUND

        # POST If-None-Match: * on deleted returns 200
        r = c.post("/app/log/public", doc, headers={"If-None-Match": "*"})
        assert r.status_code == http.HTTPStatus.OK
        etag = sha256(doc["msg"].encode()).hexdigest()

        r = c.get(f"/app/log/public?id={doc['id']}")
        assert r.status_code == http.HTTPStatus.OK

        # POST If-None-Match: mismatching ETag returns 200
        r = c.post("/app/log/public", doc, headers={"If-None-Match": '"abc"'})
        assert r.status_code == http.HTTPStatus.OK
        etag = sha256(doc["msg"].encode()).hexdigest()

    return network


def run_udp_tests(args):
    # Register secondary interface as an UDP socket on all nodes
    udp_interface = infra.interfaces.make_secondary_interface("udp", "udp_interface")
    udp_interface["udp_interface"].app_protocol = "QUIC"
    for node in args.nodes:
        node.rpc_interfaces.update(udp_interface)

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start(args)

        test_udp_echo(network, args)


def run(args):
    # Listen on two additional RPC interfaces for each node
    def additional_interfaces(local_node_id):
        return {
            "first_interface": f"127.{local_node_id}.0.1",
            "second_interface": f"127.{local_node_id}.0.2",
        }

    for local_node_id, node_host in enumerate(args.nodes):
        for interface_name, host in additional_interfaces(local_node_id).items():
            node_host.rpc_interfaces[interface_name] = infra.interfaces.RPCInterface(
                host=host,
                app_protocol="HTTP2" if args.http2 else "HTTP1",
            )

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        run_main_tests(network, args)


def run_app_space_js(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        # Make user0 admin, so it can install custom endpoints
        primary, _ = network.find_nodes()
        user = network.users[0]
        network.consortium.set_user_data(
            primary, user.service_id, user_data={"isAdmin": True}
        )

        with primary.client() as c:
            parent_dir = os.path.normpath(
                os.path.join(os.path.dirname(__file__), os.path.pardir)
            )
            logging_js_dir = os.path.join(
                parent_dir,
                "samples",
                "apps",
                "logging",
                "js",
            )
            bundle = network.consortium.read_bundle_from_dir(logging_js_dir)
            signed_bundle = programmability.sign_payload(
                network.identity(user.local_id), "custom_endpoints", bundle
            )
            r = c.put(
                "/app/custom_endpoints",
                body=signed_bundle,
                headers={"Content-Type": "application/cose"},
            )

            assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

            # Also modify the runtime options to log and return errors, to aid debugging
            options = {"log_exception_details": True, "return_exception_details": True}
            signed_options = programmability.sign_payload(
                network.identity(user.local_id), "runtime_options", options
            )
            r = c.patch(
                "/app/custom_endpoints/runtime_options",
                signed_options,
                headers={"Content-Type": "application/cose"},
            )
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code

        run_main_tests(network, args)


def test_cose_config(network, args):

    configs = set()

    for node in network.get_joined_nodes():
        with node.client("user0") as c:
            r = c.get("/cose_signatures_config")
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code
            configs.add(r.body.text())

    assert len(configs) == 1, configs
    assert (
        configs.pop() == '{"issuer":"service.example.com","subject":"ledger.signature"}'
    ), configs
    return network


def run_main_tests(network, args):
    test_basic_constraints(network, args)
    test(network, args)
    test_remove(network, args)
    test_clear(network, args)
    test_record_count(network, args)
    if args.package == "samples/apps/logging/logging":
        test_cbor_merkle_proof(network, args)
        test_cose_signature_schema(network, args)
        test_cose_receipt_schema(network, args)

    # HTTP2 doesn't support forwarding
    if not args.http2:
        test_forwarding_frontends(network, args)
        test_forwarding_frontends_without_app_prefix(network, args)
        if not os.getenv("TSAN_OPTIONS"):
            test_long_lived_forwarding(network, args)
    test_user_data_ACL(network, args)
    test_cert_prefix(network, args)
    test_anonymous_caller(network, args)
    test_multi_auth(network, args)
    test_custom_auth(network, args)
    test_custom_auth_safety(network, args)
    test_raw_text(network, args)
    test_historical_query(network, args)
    test_historical_query_range(network, args)
    test_view_history(network, args)
    test_empty_path(network, args)
    if args.package == "samples/apps/logging/logging":
        # Local-commit lambda is currently only supported in C++
        test_post_local_commit_failure(network, args)
        # Custom indexers currently only supported in C++
        test_committed_index(network, args)
    test_liveness(network, args)
    test_rekey(network, args)
    test_liveness(network, args)
    test_random_receipts(network, args, False)
    if args.package == "samples/apps/logging/logging":
        test_receipts(network, args)
        test_historical_query_sparse(network, args)
    test_historical_receipts(network, args)
    test_historical_receipts_with_claims(network, args)
    test_genesis_receipt(network, args)
    if args.package == "samples/apps/logging/logging":
        test_etags(network, args)
        test_cose_config(network, args)


def run_parsing_errors(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        test_illegal(network, args)
        test_protocols(network, args)
        test_invalid_txids(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    # cr.add(
    #     "js",
    #     run,
    #     package="js_generic",
    #     nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    #     initial_user_count=4,
    #     initial_member_count=2,
    # )

    # cr.add(
    #     "app_space_js",
    #     run_app_space_js,
    #     package="samples/apps/programmability/programmability",
    #     nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    #     initial_user_count=4,
    #     initial_member_count=2,
    # )

    # cr.add(
    #     "cpp",
    #     run,
    #     package="samples/apps/logging/logging",
    #     js_app_bundle=None,
    #     nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    #     initial_user_count=4,
    #     initial_member_count=2,
    # )

    cr.add(
        "common",
        e2e_common_endpoints.run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    # # Run illegal traffic tests in separate runners, to reduce total serial runtime
    # cr.add(
    #     "js_illegal",
    #     run_parsing_errors,
    #     package="js_generic",
    #     nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    # )

    # cr.add(
    #     "cpp_illegal",
    #     run_parsing_errors,
    #     package="samples/apps/logging/logging",
    #     nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    # )

    # # This is just for the UDP echo test for now
    # cr.add(
    #     "udp",
    #     run_udp_tests,
    #     package="samples/apps/logging/logging",
    #     nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    # )

    cr.run()
