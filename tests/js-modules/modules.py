# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import base64
import tempfile
import http
import subprocess
import os
import json
import shutil
from base64 import b64encode
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import infra.crypto
import suite.test_requirements as reqs
import openapi_spec_validator

from loguru import logger as LOG

THIS_DIR = os.path.dirname(__file__)
PARENT_DIR = os.path.normpath(os.path.join(THIS_DIR, os.path.pardir))


def validate_openapi(client):
    api_response = client.get("/app/api")
    assert api_response.status_code == http.HTTPStatus.OK, api_response.status_code
    openapi_doc = api_response.body.json()
    try:
        openapi_spec_validator.validate_spec(openapi_doc)
    except Exception as e:
        filename = "./bad_schema.json"
        with open(filename, "w") as f:
            json.dump(openapi_doc, f, indent=2)
        LOG.error(f"Document written to {filename}")
        raise e


@reqs.description("Test module import")
def test_module_import(network, args):
    primary, _ = network.find_nodes()

    # Update JS app, deploying modules _and_ app script that imports module
    bundle_dir = os.path.join(THIS_DIR, "basic-module-import")
    network.consortium.set_js_app(primary, bundle_dir)

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    return network


@reqs.description("Test js app bundle")
def test_app_bundle(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Deploying js app bundle archive")
    # Testing the bundle archive support of the Python client here.
    # Plain bundle folders are tested in the npm-based app tests.
    bundle_dir = os.path.join(PARENT_DIR, "js-app-bundle")
    raw_module_name = "/math.js".encode()
    with tempfile.TemporaryDirectory(prefix="ccf") as tmp_dir:
        bundle_path = shutil.make_archive(
            os.path.join(tmp_dir, "bundle"), "zip", bundle_dir
        )
        set_js_proposal = network.consortium.set_js_app(primary, bundle_path)

        assert (
            raw_module_name
            in network.get_ledger_public_state_at(set_js_proposal.completed_seqno)[
                "public:ccf.gov.modules"
            ]
        ), "Module was not added"

    LOG.info("Verifying that app was deployed")

    with primary.client("user0") as c:
        valid_body = {"op": "sub", "left": 82, "right": 40}
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == {"result": 42}, r.body

        invalid_body = {"op": "add", "left": "1", "right": 2}
        r = c.post("/app/compute", invalid_body)
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == {"error": "invalid operand type"}, r.body

        validate_openapi(c)

    LOG.info("Removing js app")
    remove_js_proposal = network.consortium.remove_js_app(primary)

    LOG.info("Verifying that modules and endpoints were removed")
    with primary.client("user0") as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

    assert (
        network.get_ledger_public_state_at(remove_js_proposal.completed_seqno)[
            "public:ccf.gov.modules"
        ][raw_module_name]
        is None
    ), "Module was not removed"

    return network


@reqs.description("Test dynamically installed endpoint properties")
def test_dynamic_endpoints(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(PARENT_DIR, "js-app-bundle")

    LOG.info("Deploying initial js app bundle archive")
    network.consortium.set_js_app(primary, bundle_dir)

    valid_body = {"op": "sub", "left": 82, "right": 40}
    expected_response = {"result": 42}

    LOG.info("Checking initial endpoint is accessible")
    with primary.client("user0") as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == expected_response, r.body

    LOG.info("Checking initial endpoint is inaccessible without auth")
    with primary.client() as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code

    LOG.info("Checking templated endpoint is accessible")
    with primary.client("user0") as c:
        r = c.get("/app/compute2/mul/5/7")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json()["result"] == 35, r.body.json()

    LOG.info("Deploying modified js app bundle")
    with tempfile.TemporaryDirectory(prefix="ccf") as tmp_dir:
        modified_bundle_dir = shutil.copytree(bundle_dir, tmp_dir, dirs_exist_ok=True)
        metadata_path = os.path.join(modified_bundle_dir, "app.json")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        # Modifying a single entry
        metadata["endpoints"]["/compute"]["post"]["authn_policies"] = []
        # Adding new paths with ambiguous conflicting templates
        metadata["endpoints"]["/dispatch_test/{bar}"] = metadata["endpoints"][
            "/compute"
        ]
        metadata["endpoints"]["/dispatch_test/{baz}"] = metadata["endpoints"][
            "/compute"
        ]
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        network.consortium.set_js_app(primary, modified_bundle_dir)

    LOG.info("Checking modified endpoint is accessible without auth")
    with primary.client() as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == expected_response, r.body

    LOG.info("Checking ambiguous templates cause a dispatch error")
    with primary.client("user0") as c:
        r = c.post("/app/dispatch_test/foo")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        msg = body["error"]["message"]
        assert "/foo" in msg, body
        assert "/{bar}" in msg, body
        assert "/{baz}" in msg, body

    return network


@reqs.description("Test basic Node.js/npm app")
def test_npm_app(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Building ccf-app npm package (dependency)")
    ccf_pkg_dir = os.path.join(PARENT_DIR, "..", "js", "ccf-app")
    subprocess.run(["npm", "install", "--no-package-lock"], cwd=ccf_pkg_dir, check=True)

    LOG.info("Building npm app")
    app_dir = os.path.join(PARENT_DIR, "npm-app")
    subprocess.run(["npm", "install"], cwd=app_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=app_dir, check=True)

    LOG.info("Deploying npm app")
    bundle_dir = os.path.join(app_dir, "dist")
    network.consortium.set_js_app(primary, bundle_dir)

    LOG.info("Calling npm app endpoints")
    with primary.client("user0") as c:
        body = [1, 2, 3, 4]
        r = c.post("/app/partition", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json() == [[1, 3], [2, 4]], r.body

        r = c.post("/app/proto", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/x-protobuf"
        # We could now decode the protobuf message but given all the machinery
        # involved to make it happen (code generation with protoc) we'll leave it at that.
        assert len(r.body) == 14, len(r.body)

        r = c.get("/app/crypto")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["available"], r.body

        key_size = 256
        r = c.post("/app/generateAesKey", {"size": key_size})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert len(r.body.data()) == key_size // 8
        assert r.body.data() != b"\x00" * (key_size // 8)

        r = c.post("/app/generateRsaKeyPair", {"size": 2048})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert infra.crypto.check_key_pair_pem(
            r.body.json()["privateKey"], r.body.json()["publicKey"]
        )

        aes_key_to_wrap = infra.crypto.generate_aes_key(256)
        wrapping_key_priv_pem, wrapping_key_pub_pem = infra.crypto.generate_rsa_keypair(
            2048
        )
        label = "label42"
        r = c.post(
            "/app/wrapKey",
            {
                "key": b64encode(aes_key_to_wrap).decode(),
                "wrappingKey": b64encode(bytes(wrapping_key_pub_pem, "ascii")).decode(),
                "wrapAlgo": {
                    "name": "RSA-OAEP",
                    "label": b64encode(bytes(label, "ascii")).decode(),
                },
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        unwrapped = infra.crypto.unwrap_key_rsa_oaep(
            r.body.data(), wrapping_key_priv_pem, label.encode("ascii")
        )
        assert unwrapped == aes_key_to_wrap

        aes_wrapping_key = infra.crypto.generate_aes_key(256)
        r = c.post(
            "/app/wrapKey",
            {
                "key": b64encode(aes_key_to_wrap).decode(),
                "wrappingKey": b64encode(aes_wrapping_key).decode(),
                "wrapAlgo": {"name": "AES-KWP"},
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        unwrapped = infra.crypto.unwrap_key_aes_pad(r.body.data(), aes_wrapping_key)
        assert unwrapped == aes_key_to_wrap

        wrapping_key_priv_pem, wrapping_key_pub_pem = infra.crypto.generate_rsa_keypair(
            2048
        )
        label = "label44"
        r = c.post(
            "/app/wrapKey",
            {
                "key": b64encode(aes_key_to_wrap).decode(),
                "wrappingKey": b64encode(bytes(wrapping_key_pub_pem, "ascii")).decode(),
                "wrapAlgo": {
                    "name": "RSA-OAEP-AES-KWP",
                    "aesKeySize": 256,
                    "label": b64encode(bytes(label, "ascii")).decode(),
                },
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        unwrapped = infra.crypto.unwrap_key_rsa_oaep_aes_pad(
            r.body.data(), wrapping_key_priv_pem, label.encode("ascii")
        )
        assert unwrapped == aes_key_to_wrap

        r = c.post(
            "/app/digest",
            {
                "algorithm": "SHA-256",
                "data": b64encode(bytes("Hello world!", "ascii")).decode(),
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert (
            r.body.text()
            == "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
        ), r.body

        r = c.get("/app/log?id=42")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/log?id=42", {"msg": "Hello!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.get("/app/log?id=42")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        assert body["msg"] == "Hello!", r.body

        r = c.post("/app/log?id=42", {"msg": "Saluton!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        r = c.post("/app/log?id=43", {"msg": "Bonjour!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.get("/app/log/all")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        # Response is list in undefined order
        assert len(body) == 2, body
        assert {"id": 42, "msg": "Saluton!"} in body, body
        assert {"id": 43, "msg": "Bonjour!"} in body, body

        r = c.post("/app/rpc/apply_writes")
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        val = network.get_ledger_public_state_at(r.seqno)["public:apply_writes"][
            "foo".encode()
        ]
        assert val == b"bar", val

        r = c.get("/app/jwt")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        body = r.body.json()
        assert body["msg"] == "authorization header missing", r.body

        r = c.get("/app/jwt", headers={"authorization": "Bearer not-a-jwt"})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        body = r.body.json()
        assert body["msg"].startswith("malformed jwt:"), r.body

        jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
        jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)

        jwt_kid = "my_key_id"
        jwt = infra.crypto.create_jwt({}, jwt_key_priv_pem, jwt_kid)
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        body = r.body.json()
        assert body["msg"].startswith("token signing key not found"), r.body

        priv_key_pem, _ = infra.crypto.generate_rsa_keypair(2048)
        pem = infra.crypto.generate_cert(priv_key_pem, cn='1')
        r = c.post("/app/isValidX509CertBundle", pem)
        assert r.body.json(), r.body
        r = c.post("/app/isValidX509CertBundle", pem + "\n" + pem)
        assert r.body.json(), r.body
        r = c.post("/app/isValidX509CertBundle", "garbage")
        assert not r.body.json(), r.body

        priv_key_pem2, _ = infra.crypto.generate_rsa_keypair(2048)
        pem2 = infra.crypto.generate_cert(priv_key_pem2, cn='2',
            issuer_priv_key_pem=priv_key_pem,
            issuer_cn='1'
            )
        priv_key_pem3, _ = infra.crypto.generate_rsa_keypair(2048)
        pem3 = infra.crypto.generate_cert(priv_key_pem3, cn='3',
            issuer_priv_key_pem=priv_key_pem2,
            issuer_cn='2')
        # validates chains with target being trusted directly
        r = c.post("/app/isValidX509CertChain", {"chain": pem, "trusted": pem})
        assert r.body.json(), r.body
        # validates chains without intermediates
        r = c.post("/app/isValidX509CertChain", {"chain": pem2, "trusted": pem})
        assert r.body.json(), r.body
        # validates chains with intermediates
        r = c.post("/app/isValidX509CertChain", {"chain": pem3 + "\n" + pem2, "trusted": pem})
        assert r.body.json(), r.body
        # validates partial chains (pem2 is an intermediate)
        r = c.post("/app/isValidX509CertChain", {"chain": pem3, "trusted": pem2})
        assert r.body.json(), r.body
        # fails to reach trust anchor
        r = c.post("/app/isValidX509CertChain", {"chain": pem3, "trusted": pem})
        assert not r.body.json(), r.body

        r = c.get("/node/quotes/self")
        primary_quote_info = r.body.json()
        if not primary_quote_info["raw"]:
            LOG.info("Skipping /app/verifyOpenEnclaveEvidence test, virtual mode")
        else:
            # See /opt/openenclave/include/openenclave/attestation/sgx/evidence.h
            OE_FORMAT_UUID_SGX_ECDSA = "a3a21e87-1b4d-4014-b70a-a125d2fbcd8c"
            r = c.post(
                "/app/verifyOpenEnclaveEvidence",
                {
                    "format": OE_FORMAT_UUID_SGX_ECDSA,
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            body = r.body.json()
            assert body["claims"]["unique_id"] == primary_quote_info["mrenclave"], body
            assert "sgx_report_data" in body["customClaims"], body

            # again but without endorsements
            r = c.post(
                "/app/verifyOpenEnclaveEvidence",
                {
                    "format": OE_FORMAT_UUID_SGX_ECDSA,
                    "evidence": primary_quote_info["raw"],
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            body = r.body.json()
            assert body["claims"]["unique_id"] == primary_quote_info["mrenclave"], body
            assert "sgx_report_data" in body["customClaims"], body

        validate_openapi(c)

    LOG.info("Store JWT signing keys")

    issuer = "https://example.issuer"
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        jwt_cert_der = infra.crypto.cert_pem_to_der(jwt_cert_pem)
        der_b64 = base64.b64encode(jwt_cert_der).decode("ascii")
        data = {
            "issuer": issuer,
            "jwks": {"keys": [{"kty": "RSA", "kid": jwt_kid, "x5c": [der_b64]}]},
        }
        json.dump(data, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Calling jwt endpoint after storing keys")
    with primary.client("user0") as c:
        jwt_mismatching_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
        jwt = infra.crypto.create_jwt({}, jwt_mismatching_key_priv_pem, jwt_kid)
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        body = r.body.json()
        assert body["msg"] == "jwt validation failed", r.body

        jwt = infra.crypto.create_jwt({}, jwt_key_priv_pem, jwt_kid)
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        body = r.body.json()
        assert body["msg"] == "jwt invalid, sub claim missing", r.body

        user_id = "user0"
        jwt = infra.crypto.create_jwt({"sub": user_id}, jwt_key_priv_pem, jwt_kid)
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        assert body["userId"] == user_id, r.body

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        #network = test_module_import(network, args)
        #network = test_app_bundle(network, args)
        #network = test_dynamic_endpoints(network, args)
        network = test_npm_app(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
