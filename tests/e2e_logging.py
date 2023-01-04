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
import urllib.parse
import random
import re
import infra.crypto
from infra.runner import ConcurrentRunner
from hashlib import sha256
from infra.member import AckException
import e2e_common_endpoints
from types import MappingProxyType


from loguru import logger as LOG


def show_cert(name, cert):
    from OpenSSL.crypto import dump_certificate, FILETYPE_TEXT

    dc = dump_certificate(FILETYPE_TEXT, cert).decode("unicode_escape")
    LOG.info(f"{name} cert: {dc}")


def verify_endorsements_openssl(service_cert, receipt):
    from OpenSSL.crypto import (
        load_certificate,
        FILETYPE_PEM,
        X509,
        X509Store,
        X509StoreContext,
    )

    store = X509Store()

    # pyopenssl does not support X509_V_FLAG_NO_CHECK_TIME. For recovery of expired
    # services and historical receipt, we want to ignore the validity time. 0x200000
    # is the bitmask for this option in more recent versions of OpenSSL.
    X509_V_FLAG_NO_CHECK_TIME = 0x200000
    store.set_flags(X509_V_FLAG_NO_CHECK_TIME)

    store.add_cert(X509.from_cryptography(service_cert))
    chain = None
    if "service_endorsements" in receipt:
        chain = []
        for endo in receipt["service_endorsements"]:
            chain.append(load_certificate(FILETYPE_PEM, endo.encode()))
    node_cert_pem = receipt["cert"].encode()
    ctx = X509StoreContext(store, load_certificate(FILETYPE_PEM, node_cert_pem), chain)
    ctx.verify_certificate()  # (throws on error)


def verify_receipt(
    receipt, service_cert, claims=None, generic=True, skip_endorsement_check=False
):
    """
    Raises an exception on failure
    """

    node_cert = load_pem_x509_certificate(receipt["cert"].encode(), default_backend())

    if not skip_endorsement_check:
        service_endorsements = []
        if "service_endorsements" in receipt:
            service_endorsements = [
                load_pem_x509_certificate(endo.encode(), default_backend())
                for endo in receipt["service_endorsements"]
            ]
        ccf.receipt.check_endorsements(node_cert, service_cert, service_endorsements)

        verify_endorsements_openssl(service_cert, receipt)

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
    else:
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
    root = ccf.receipt.root(leaf, receipt["proof"])
    ccf.receipt.verify(root, receipt["signature"], node_cert)


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("/app/log/private", "/app/log/public")
@reqs.at_least_n_nodes(2)
@reqs.no_http2()
@app.scoped_txs(verify=False)
def test(network, args):
    network.txs.issue(
        network=network,
        number_txs=1,
    )
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
            "http_status": "200",
            "http_version": "1.1",
        },
        # HTTP3 is not supported by curl _or_ CCF
        "--http3": {
            "errors": [
                "the installed libcurl version doesn't support this",
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
                "--http2": {"http_status": "200", "http_version": "1.1"},
                "--http2-prior-knowledge": {
                    "http_status": "200",
                    "http_version": "1.1",
                },
            }
        )
    else:  # HTTP/1.1
        protocols.update(
            {
                # HTTP/1.x requests succeed, as HTTP/1.1
                "--http1.0": {"http_status": "200", "http_version": "1.1"},
                "--http1.1": {"http_status": "200", "http_version": "1.1"},
                # TLS handshake negotiates HTTP/1.1
                "--http2": {"http_status": "200", "http_version": "1.1"},
                "--http2-prior-knowledge": {
                    "http_status": "200",
                    "http_version": "1.1",
                },
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
        if args.package in ["libjs_generic"]:
            check(r, result={"error": "No such key"})
        else:
            check(
                r,
                error=lambda status, msg: status == http.HTTPStatus.BAD_REQUEST.value
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
                    if args.package in ["libjs_generic"]:
                        check(
                            get_r,
                            result={"error": "No such key"},
                        )
                    else:
                        check(
                            get_r,
                            error=lambda status, msg: status
                            == http.HTTPStatus.BAD_REQUEST.value,
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
        prefixed_msg = f"CN={user.local_id}: {msg}"
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
            assert r_body not in response_bodies, r_body
            response_bodies.add(r_body)

        LOG.info("Anonymous, no auth")
        with primary.client() as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as a user, via TLS cert")
        with primary.client(user.local_id) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as same user, now with user data")
        network.consortium.set_user_data(
            primary, user.service_id, {"some": ["interesting", "data", 42]}
        )
        with primary.client(user.local_id) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as a different user, via TLS cert")
        with primary.client("user1") as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as a member, via TLS cert")
        with primary.client(member.local_id) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as same member, now with user data")
        network.consortium.set_member_data(
            primary, member.service_id, {"distinct": {"arbitrary": ["data"]}}
        )
        with primary.client(member.local_id) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as a different member, via TLS cert")
        with primary.client("member1") as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as a user, via HTTP signature")
        with primary.client(None, user.local_id) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as a member, via HTTP signature")
        with primary.client(None, member.local_id) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate as user2 but sign as user1")
        with primary.client("user2", "user1") as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        network.create_user("user5", args.participants_curve, record=False)

        LOG.info("Authenticate as invalid user5 but sign as valid user3")
        with primary.client("user5", "user3") as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

        LOG.info("Authenticate via JWT token")
        jwt_issuer = infra.jwt_issuer.JwtIssuer()
        jwt_issuer.register(network)
        jwt = jwt_issuer.issue_jwt(claims={"user": "Alice"})

        with primary.client() as c:
            r = c.get("/app/multi_auth", headers={"authorization": "Bearer " + jwt})
            require_new_response(r)

        LOG.info("Authenticate via second JWT token")
        jwt2 = jwt_issuer.issue_jwt(claims={"user": "Bob"})

        with primary.client(common_headers={"authorization": "Bearer " + jwt2}) as c:
            r = c.get("/app/multi_auth")
            require_new_response(r)

    return network


@reqs.description("Call an endpoint with a custom auth policy")
@reqs.supports_methods("/app/custom_auth")
@reqs.no_http2()
def test_custom_auth(network, args):
    primary, other = network.find_primary_and_any_backup()

    for node in (primary, other):
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
@reqs.no_http2()
def test_custom_auth_safety(network, args):
    primary, other = network.find_primary_and_any_backup()

    for node in (primary, other):
        with node.client() as c:
            r = c.get(
                "/app/custom_auth",
                headers={"x-custom-auth-explode": "Boom goes the dynamite"},
            )
            assert (
                r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value
            ), r.status_code

    return network


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


@reqs.description("Read metrics")
@reqs.supports_methods("/app/api/metrics")
def test_metrics(network, args):
    primary, _ = network.find_primary()

    def get_metrics(r, path, method, default=None):
        try:
            return next(
                v
                for v in r.body.json()["metrics"]
                if v["path"] == path and v["method"] == method
            )
        except StopIteration:
            if default is None:
                LOG.error(f"Found no metrics for {method} {path}")
                raise
            else:
                return default

    calls = 0
    errors = 0
    with primary.client("user0") as c:
        r = c.get("/app/api/metrics")
        m = get_metrics(r, "api/metrics", "GET")
        calls = m["calls"]
        errors = m["errors"]

    with primary.client("user0") as c:
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "api/metrics", "GET")["calls"] == calls + 1
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "api/metrics", "GET")["calls"] == calls + 2

    with primary.client() as c:
        r = c.get("/app/api/metrics", headers={"accept": "nonsense"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value

    with primary.client() as c:
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "api/metrics", "GET")["errors"] == errors + 1

    calls = 0
    with primary.client("user0") as c:
        r = c.get("/app/api/metrics")
        calls = get_metrics(r, "log/public", "POST", {"calls": 0})["calls"]

    network.txs.issue(
        network=network,
        number_txs=1,
    )

    with primary.client("user0") as c:
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "log/public", "POST")["calls"] == calls + 1

    return network


@reqs.description("Read historical state")
@reqs.supports_methods("/app/log/private", "/app/log/private/historical")
@reqs.no_http2()
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


def get_all_entries(
    client, target_id, from_seqno=None, to_seqno=None, timeout=50, log_on_success=False
):
    LOG.info(
        f"Getting historical entries{f' from {from_seqno}' if from_seqno is not None else ''}{f' to {to_seqno}' if to_seqno is not None else ''} for id {target_id}"
    )
    logs = None if log_on_success else []

    start_time = time.time()
    end_time = start_time + timeout
    entries = []
    path = f"/app/log/public/historical/range?id={target_id}"
    if from_seqno is not None:
        path += f"&from_seqno={from_seqno}"
    if to_seqno is not None:
        path += f"&to_seqno={to_seqno}"
    while time.time() < end_time:
        r = client.get(path, log_capture=logs)
        if r.status_code == http.HTTPStatus.OK:
            j_body = r.body.json()
            entries += j_body["entries"]
            if "@nextLink" in j_body:
                path = j_body["@nextLink"]
                continue
            else:
                # No @nextLink means we've reached end of range
                duration = time.time() - start_time
                LOG.info(f"Done! Fetched {len(entries)} entries in {duration:0.2f}s")
                return entries, duration
        elif r.status_code == http.HTTPStatus.ACCEPTED:
            # Ignore retry-after header, retry soon
            time.sleep(0.1)
            continue
        else:
            LOG.error("Printing historical/range logs on unexpected status")
            flush_info(logs, None)
            raise ValueError(
                f"""
                Unexpected status code from historical range query: {r.status_code}

                {r.body}
                """
            )

    LOG.error("Printing historical/range logs on timeout")
    flush_info(logs, None)
    raise TimeoutError(f"Historical range not available after {timeout}s")


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
                network, repeat=True, idx=idx, wait_for_sync=False, log_capture=[]
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

        entries_a, _ = get_all_entries(c, id_a)
        entries_b, _ = get_all_entries(c, id_b)
        entries_c, _ = get_all_entries(c, id_c)

        # Fetching A and B should take a similar amount of time, C (which was only written to in a brief window in the history) should be much faster
        # NB: With larger page size, this is not necessarily true! Small range means _all_ responses fit in a single response page
        # assert duration_c < duration_a
        # assert duration_c < duration_b

        # Confirm that we can retrieve these with more specific queries, and we end up with the same result
        alt_a, _ = get_all_entries(c, id_a, from_seqno=first_seqno)
        assert alt_a == entries_a
        alt_a, _ = get_all_entries(c, id_a, to_seqno=last_seqno)
        assert alt_a == entries_a
        alt_a, _ = get_all_entries(c, id_a, from_seqno=first_seqno, to_seqno=last_seqno)
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
@app.scoped_txs()
def test_forwarding_frontends(network, args):
    backup = network.find_any_backup()

    try:
        with backup.client() as c:
            check_commit = infra.checker.Checker(c)
            ack = network.consortium.get_any_active_member().ack(backup)
            check_commit(ack)
    except AckException as e:
        assert args.http2 == True
        assert e.response.status_code == http.HTTPStatus.NOT_IMPLEMENTED
        r = e.response.body.json()
        assert (
            r["error"]["message"]
            == "Request cannot be forwarded to primary on HTTP/2 interface."
        ), r
    else:
        assert args.http2 == False

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
        assert args.http2 == True
        assert e.response.status_code == http.HTTPStatus.NOT_IMPLEMENTED
        r = e.response.body.json()
        assert (
            r["error"]["message"]
            == "Request cannot be forwarded to primary on HTTP/2 interface."
        ), r
    else:
        assert args.http2 == False

    if args.package == "samples/apps/logging/liblogging" and not args.http2:
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


@reqs.description("Testing signed queries with escaped queries")
@reqs.installed_package("samples/apps/logging/liblogging")
@reqs.at_least_n_nodes(2)
@reqs.no_http2()
def test_signed_escapes(network, args):
    node = network.find_node_by_role()
    with node.client("user0", "user0") as c:
        escaped_query_tests(c, "signed_request_query")
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
                for view in range(1, commit_tx_id.view + 1):
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
    network, args, lts=True, additional_seqnos=MappingProxyType({}), node=None
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
                rc = c.get(f"/app/receipt?transaction_id={view}.{s}")
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
                            skip_endorsement_check=lts,
                        )
                    break
                elif rc.status_code == http.HTTPStatus.ACCEPTED:
                    time.sleep(0.5)
                else:
                    view += 1
                    if view > max_view:
                        assert False, rc

    return network


@reqs.description("Test basic app liveness")
@reqs.at_least_n_nodes(1)
@reqs.no_http2()
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
        assert r.body.json()["success"] == True
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
def test_committed_index(network, args):
    remote_node, _ = network.find_primary()
    with remote_node.client() as c:
        res = c.post("/app/log/private/install_committed_index")
        assert res.status_code == http.HTTPStatus.OK

    txid = network.txs.issue(network, number_txs=1, send_public=False)

    _, log_id = network.txs.get_log_id(txid)

    remaining_retries = 10
    while remaining_retries > 0:
        r = network.txs.request(log_id, priv=True, url_suffix="committed")
        if r.status_code == http.HTTPStatus.OK.value:
            break

        current_tx_id = TxID.from_str(
            re.search(
                r"Current Tx ID: ([0-9]+.[0-9]+)",
                r.body.json()["error"]["message"],
            ).group(1)
        )

        LOG.info(f"Current Tx ID ({current_tx_id}) - Tx ID ({txid})")
        if current_tx_id >= txid:
            break

        LOG.warning(f"Retrying with {remaining_retries} retries left...")
        time.sleep(1)

        remaining_retries -= 1

    assert r.status_code == http.HTTPStatus.OK.value, r.status_code
    assert r.body.json() == {"msg": f"Private message at idx {log_id} [0]"}

    network.txs.delete(log_id, priv=True)

    r = network.txs.request(log_id, priv=True)
    assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
    assert r.body.json()["error"]["message"].startswith(f"No such record: {log_id}")

    r = network.txs.request(log_id, priv=True, url_suffix="committed")
    assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
    assert r.body.json()["error"]["message"].startswith(f"No such record: {log_id}")


def run_udp_tests(args):
    # Register secondary interface as an UDP socket on all nodes
    udp_interface = infra.interfaces.make_secondary_interface("udp", "udp_interface")
    for node in args.nodes:
        node.rpc_interfaces.update(udp_interface)

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
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
                app_protocol=infra.interfaces.AppProtocol.HTTP2
                if args.http2
                else infra.interfaces.AppProtocol.HTTP1,
            )

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        test(network, args)
        test_remove(network, args)
        test_clear(network, args)
        test_record_count(network, args)
        test_forwarding_frontends(network, args)
        test_forwarding_frontends_without_app_prefix(network, args)
        test_signed_escapes(network, args)
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
        test_metrics(network, args)
        test_empty_path(network, args)
        test_post_local_commit_failure(network, args)
        test_committed_index(network, args)
        test_liveness(network, args)
        test_rekey(network, args)
        test_liveness(network, args)
        test_random_receipts(network, args, False)
        if args.package == "samples/apps/logging/liblogging":
            test_receipts(network, args)
            test_historical_query_sparse(network, args)
        test_historical_receipts(network, args)
        test_historical_receipts_with_claims(network, args)


def run_parsing_errors(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        test_illegal(network, args)
        test_protocols(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "js",
        run,
        package="libjs_generic",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=4,
        initial_member_count=2,
    )

    cr.add(
        "cpp",
        run,
        package="samples/apps/logging/liblogging",
        js_app_bundle=None,
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=4,
        initial_member_count=2,
    )

    cr.add(
        "common",
        e2e_common_endpoints.run,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    # Run illegal traffic tests in separate runners, to reduce total serial runtime
    cr.add(
        "js_illegal",
        run_parsing_errors,
        package="libjs_generic",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.add(
        "cpp_illegal",
        run_parsing_errors,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    # This is just for the UDP echo test for now
    cr.add(
        "udp",
        run_udp_tests,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run()
