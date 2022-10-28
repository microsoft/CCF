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
from jwcrypto import jwk
from cryptography.hazmat.primitives.asymmetric import ec

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
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(openapi_doc, f, indent=2)
        LOG.error(f"Document written to {filename}")
        raise e


def generate_and_verify_jwk(client):
    LOG.info("Generate JWK from raw public key PEM")
    r = client.post("/app/pubPemToJwk", body={"pem": "invalid_pem"})
    assert r.status_code != http.HTTPStatus.OK

    # Elliptic curve
    curves = [ec.SECP256R1, ec.SECP256K1, ec.SECP384R1]
    for curve in curves:
        priv_pem, pub_pem = infra.crypto.generate_ec_keypair(curve)
        # Private
        ref_priv_jwk = jwk.JWK.from_pem(priv_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/pemToJwk", body={"pem": priv_pem, "kid": ref_priv_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "EC"
        assert body == ref_priv_jwk, f"{body} != {ref_priv_jwk}"

        # Public
        ref_pub_jwk = jwk.JWK.from_pem(pub_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/pubPemToJwk", body={"pem": pub_pem, "kid": ref_pub_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "EC"
        assert body == ref_pub_jwk, f"{body} != {ref_pub_jwk}"

    # RSA
    key_sizes = [1024, 2048, 4096]
    for key_size in key_sizes:
        priv_pem, pub_pem = infra.crypto.generate_rsa_keypair(key_size)

        # Private
        ref_priv_jwk = jwk.JWK.from_pem(priv_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/rsaPemToJwk", body={"pem": priv_pem, "kid": ref_priv_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "RSA"
        assert body == ref_priv_jwk, f"{body} != {ref_priv_jwk}"

        # Public
        ref_pub_jwk = jwk.JWK.from_pem(pub_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/pubRsaPemToJwk", body={"pem": pub_pem, "kid": ref_pub_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "RSA"
        assert body == ref_pub_jwk, f"{body} != {ref_pub_jwk}"


@reqs.description("Test module import")
def test_module_import(network, args):
    primary, _ = network.find_nodes()

    # Update JS app, deploying modules _and_ app script that imports module
    bundle_dir = os.path.join(THIS_DIR, "basic-module-import")
    network.consortium.set_js_app_from_dir(primary, bundle_dir)

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    return network


@reqs.description("Test module bytecode caching")
@reqs.installed_package("libjs_generic")
def test_bytecode_cache(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(THIS_DIR, "basic-module-import")

    LOG.info("Verifying that app works without bytecode cache")
    network.consortium.set_js_app_from_dir(
        primary, bundle_dir, disable_bytecode_cache=True
    )

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] == 0, "Module bytecode exists but should not"
        assert not body["bytecode_used"], body

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    LOG.info("Verifying that app works with bytecode cache")
    network.consortium.set_js_app_from_dir(
        primary, bundle_dir, disable_bytecode_cache=False
    )

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] > 0, "Module bytecode is missing"
        assert body["bytecode_used"], body

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    LOG.info("Verifying that redeploying app cleans bytecode cache")
    network.consortium.set_js_app_from_dir(
        primary, bundle_dir, disable_bytecode_cache=True
    )

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] == 0, "Module bytecode exists but should not"
        assert not body["bytecode_used"], body

    LOG.info(
        "Verifying that bytecode cache can be enabled/refreshed without app re-deploy"
    )
    network.consortium.refresh_js_app_bytecode_cache(primary)

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] > 0, "Module bytecode is missing"
        assert body["bytecode_used"], body

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    return network


@reqs.description("Test js runtime options")
def test_set_js_runtime(network, args):
    primary, _ = network.find_nodes()
    # set js run time options
    network.consortium.set_js_runtime_options(
        primary,
        max_heap_bytes=50 * 1024 * 1024,
        max_stack_bytes=1024 * 512,
        max_execution_time=500,
    )
    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["max_heap_size"] == 50 * 1024 * 1024
        assert body["max_stack_size"] == 1024 * 512
        assert body["max_execution_time"] == 500
    # reset the heap and stack sizes to default values
    network.consortium.set_js_runtime_options(
        primary,
        max_heap_bytes=100 * 1024 * 1024,
        max_stack_bytes=1024 * 1024,
        max_execution_time=1000,
    )
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
        set_js_proposal = network.consortium.set_js_app_from_dir(primary, bundle_path)

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


def test_apply_writes(c):
    ### Default behaviour
    # Writes are applied for 2xx response codes
    r = c.post("/app/rpc/apply_writes", {"val": "aaa", "statusCode": 200})
    assert r.status_code == 200
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "aaa"

    r = c.post("/app/rpc/apply_writes", {"val": "bbb", "statusCode": 202})
    assert r.status_code == 202
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "bbb"

    # Writes are not applied for other response codes
    r = c.post("/app/rpc/apply_writes", {"val": "ccc", "statusCode": 404})
    assert r.status_code == 404
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "bbb"

    r = c.post("/app/rpc/apply_writes", {"val": "ddd", "statusCode": 500})
    assert r.status_code == 500
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "bbb"

    ### setApplyWrites overrides behaviour
    # Writes can be unapplied despite 2xx response codes
    r = c.post(
        "/app/rpc/apply_writes",
        {"val": "eee", "statusCode": 200, "setApplyWrites": False},
    )
    assert r.status_code == 200
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "bbb"

    r = c.post(
        "/app/rpc/apply_writes",
        {"val": "fff", "statusCode": 202, "setApplyWrites": False},
    )
    assert r.status_code == 202
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "bbb"

    # Writes can be applied despite other response codes
    r = c.post(
        "/app/rpc/apply_writes",
        {"val": "ggg", "statusCode": 404, "setApplyWrites": True},
    )
    assert r.status_code == 404
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "ggg"

    r = c.post(
        "/app/rpc/apply_writes",
        {"val": "hhh", "statusCode": 500, "setApplyWrites": True},
    )
    assert r.status_code == 500
    r = c.get("/app/rpc/apply_writes")
    assert r.status_code == 200
    assert r.body.text() == "hhh"


@reqs.description("Test dynamically installed endpoint properties")
def test_dynamic_endpoints(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(PARENT_DIR, "js-app-bundle")

    LOG.info("Deploying initial js app bundle archive")
    network.consortium.set_js_app_from_dir(primary, bundle_dir)

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
        with open(metadata_path, "r", encoding="utf-8") as f:
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
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        network.consortium.set_js_app_from_dir(primary, modified_bundle_dir)

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

    LOG.info("Running ccf-app unit tests")
    subprocess.run(["npm", "test"], cwd=ccf_pkg_dir, check=True)

    LOG.info("Building npm app")
    app_dir = os.path.join(PARENT_DIR, "npm-app")
    assert infra.proc.ccall("npm", "install", path=app_dir).returncode == 0
    assert (
        infra.proc.ccall("npm", "run", "build", "--verbose", path=app_dir).returncode
        == 0
    )

    LOG.info("Deploying npm app")
    bundle_path = os.path.join(
        app_dir, "dist", "bundle.json"
    )  # Produced by build step of test npm-app
    network.consortium.set_js_app_from_json(primary, bundle_path)

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

        r = c.post("/app/generateEcdsaKeyPair", {"curve": "secp256r1"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert infra.crypto.check_key_pair_pem(
            r.body.json()["privateKey"], r.body.json()["publicKey"]
        )

        r = c.post("/app/generateEcdsaKeyPair", {"curve": "secp256k1"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert infra.crypto.check_key_pair_pem(
            r.body.json()["privateKey"], r.body.json()["publicKey"]
        )

        r = c.post("/app/generateEcdsaKeyPair", {"curve": "secp384r1"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert infra.crypto.check_key_pair_pem(
            r.body.json()["privateKey"], r.body.json()["publicKey"]
        )

        r = c.post("/app/generateEddsaKeyPair", {"curve": "curve25519"})
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

        key_priv_pem, key_pub_pem = infra.crypto.generate_rsa_keypair(2048)
        algorithm = {"name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256"}
        data = "foo".encode()
        signature = infra.crypto.sign(algorithm, key_priv_pem, data)
        r = c.post(
            "/app/verifySignature",
            {
                "algorithm": algorithm,
                "key": key_pub_pem,
                "signature": b64encode(signature).decode(),
                "data": b64encode(data).decode(),
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json() == True, r.body

        r = c.post(
            "/app/verifySignature",
            {
                "algorithm": algorithm,
                "key": key_pub_pem,
                "signature": b64encode(signature).decode(),
                "data": b64encode("bar".encode()).decode(),
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json() == False, r.body

        curves = [ec.SECP256R1, ec.SECP256K1]
        for curve in curves:
            key_priv_pem, key_pub_pem = infra.crypto.generate_ec_keypair(curve)
            algorithm = {"name": "ECDSA", "hash": "SHA-256"}
            data = "foo".encode()
            signature = infra.crypto.sign(algorithm, key_priv_pem, data)
            r = c.post(
                "/app/verifySignature",
                {
                    "algorithm": algorithm,
                    "key": key_pub_pem,
                    "signature": b64encode(signature).decode(),
                    "data": b64encode(data).decode(),
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            assert r.body.json() == True, r.body

        key_priv_pem, key_pub_pem = infra.crypto.generate_eddsa_keypair()
        algorithm = {"name": "EdDSA"}
        data = "foo".encode()
        signature = infra.crypto.sign(algorithm, key_priv_pem, data)
        r = c.post(
            "/app/verifySignature",
            {
                "algorithm": algorithm,
                "key": key_pub_pem,
                "signature": b64encode(signature).decode(),
                "data": b64encode(data).decode(),
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json() == True, r.body

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

        test_apply_writes(c)

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
        pem = infra.crypto.generate_cert(priv_key_pem)
        r = c.post("/app/isValidX509CertBundle", pem)
        assert r.body.json(), r.body
        r = c.post("/app/isValidX509CertBundle", pem + "\n" + pem)
        assert r.body.json(), r.body
        r = c.post("/app/isValidX509CertBundle", "garbage")
        assert not r.body.json(), r.body

        priv_key_pem1, _ = infra.crypto.generate_rsa_keypair(2048)
        pem1 = infra.crypto.generate_cert(priv_key_pem1, cn="1", ca=True)
        priv_key_pem2, _ = infra.crypto.generate_rsa_keypair(2048)
        pem2 = infra.crypto.generate_cert(
            priv_key_pem2,
            cn="2",
            ca=True,
            issuer_priv_key_pem=priv_key_pem1,
            issuer_cn="1",
        )
        priv_key_pem3, _ = infra.crypto.generate_rsa_keypair(2048)
        pem3 = infra.crypto.generate_cert(
            priv_key_pem3, cn="3", issuer_priv_key_pem=priv_key_pem2, issuer_cn="2"
        )
        # validates chains with target being trusted directly
        r = c.post("/app/isValidX509CertChain", {"chain": pem3, "trusted": pem3})
        assert r.body.json(), r.body
        # validates chains without intermediates
        r = c.post("/app/isValidX509CertChain", {"chain": pem2, "trusted": pem1})
        assert r.body.json(), r.body
        # validates chains with intermediates
        r = c.post(
            "/app/isValidX509CertChain", {"chain": pem3 + "\n" + pem2, "trusted": pem1}
        )
        assert r.body.json(), r.body
        # validates partial chains (pem2 is an intermediate)
        r = c.post("/app/isValidX509CertChain", {"chain": pem3, "trusted": pem2})
        assert r.body.json(), r.body
        # fails to reach trust anchor
        r = c.post("/app/isValidX509CertChain", {"chain": pem3, "trusted": pem1})
        assert not r.body.json(), r.body

        r = c.get("/node/quotes/self")
        primary_quote_info = r.body.json()
        if args.enclave_type not in ("release", "debug"):
            LOG.info("Skipping /app/verifyOpenEnclaveEvidence test, non-sgx node")
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
        generate_and_verify_jwk(c)

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


@reqs.description("Test JS execution time out with npm app endpoint")
def test_js_execution_time(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Deploying npm app")
    app_dir = os.path.join(PARENT_DIR, "npm-app")
    bundle_path = os.path.join(
        app_dir, "dist", "bundle.json"
    )  # Produced by build step of test npm-app in the previous test_npm_app
    network.consortium.set_js_app_from_json(primary, bundle_path)

    LOG.info("Store JWT signing keys")
    jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)
    jwt_kid = "my_key_id"
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
        user_id = "user0"
        jwt = infra.crypto.create_jwt({"sub": user_id}, jwt_key_priv_pem, jwt_kid)

        # set JS execution time to a lower value which will timeout this
        # endpoint execution
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=50 * 1024 * 1024,
            max_stack_bytes=1024 * 512,
            max_execution_time=0.5,
        )
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["message"] == "Operation took too long to complete."

        # reset the execution time
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=50 * 1024 * 1024,
            max_stack_bytes=1024 * 512,
            max_execution_time=1000,
        )
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        assert body["userId"] == user_id, r.body

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_module_import(network, args)
        network = test_bytecode_cache(network, args)
        network = test_app_bundle(network, args)
        network = test_dynamic_endpoints(network, args)
        network = test_set_js_runtime(network, args)
        network = test_npm_app(network, args)
        network = test_js_execution_time(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
