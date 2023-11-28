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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import hmac
import random

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

        r = client.post("/app/jwkToPem", body={"jwk": body})
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["pem"] == priv_pem

        # Public
        ref_pub_jwk = jwk.JWK.from_pem(pub_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/pubPemToJwk", body={"pem": pub_pem, "kid": ref_pub_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "EC"
        assert body == ref_pub_jwk, f"{body} != {ref_pub_jwk}"

        r = client.post("/app/pubJwkToPem", body={"jwk": body})
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["pem"] == pub_pem

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

        r = client.post("/app/rsaJwkToPem", body={"jwk": body})
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["pem"] == priv_pem

        # Public
        ref_pub_jwk = jwk.JWK.from_pem(pub_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/pubRsaPemToJwk", body={"pem": pub_pem, "kid": ref_pub_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "RSA"
        assert body == ref_pub_jwk, f"{body} != {ref_pub_jwk}"

        r = client.post("/app/pubRsaJwkToPem", body={"jwk": body})
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["pem"] == pub_pem

    # EdDSA
    # Note: x25519 is not supported by jwcrypto just yet
    for curve in ["curve25519"]:
        priv_pem, pub_pem = infra.crypto.generate_eddsa_keypair(curve)
        # Private
        ref_priv_jwk = jwk.JWK.from_pem(priv_pem.encode()).export_private(as_dict=True)
        r = client.post(
            "/app/eddsaPemToJwk", body={"pem": priv_pem, "kid": ref_priv_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "OKP"
        assert body == ref_priv_jwk, f"{body} != {ref_priv_jwk}"

        r = client.post("/app/eddsaJwkToPem", body={"jwk": body})
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["pem"] == priv_pem

        # Public
        ref_pub_jwk = jwk.JWK.from_pem(pub_pem.encode()).export(as_dict=True)
        r = client.post(
            "/app/pubEddsaPemToJwk", body={"pem": pub_pem, "kid": ref_pub_jwk["kid"]}
        )
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["kty"] == "OKP"
        assert body == ref_pub_jwk, f"{body} != {ref_pub_jwk}"

        r = client.post("/app/pubEddsaJwkToPem", body={"jwk": body})
        body = r.body.json()
        assert r.status_code == http.HTTPStatus.OK
        assert body["pem"] == pub_pem


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
        max_execution_time_ms=500,
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
        max_execution_time_ms=1000,
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


def rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


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
    bundle = infra.consortium.slurp_json(bundle_path)
    network.consortium.set_js_app_from_bundle(primary, bundle)

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

        private_key = load_pem_private_key(r.body.json()["privateKey"].encode(), None)
        assert isinstance(private_key, Ed25519PrivateKey)

        r = c.post("/app/generateEddsaKeyPair", {"curve": "x25519"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert infra.crypto.check_key_pair_pem(
            r.body.json()["privateKey"], r.body.json()["publicKey"]
        )

        private_key = load_pem_private_key(r.body.json()["privateKey"].encode(), None)
        assert isinstance(private_key, X25519PrivateKey)

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
        wrappedKey = r.body.data()
        assert wrappedKey is not None
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.post(
            "/app/unwrapKey",
            {
                "key": b64encode(wrappedKey).decode(),
                "unwrappingKey": b64encode(
                    bytes(wrapping_key_priv_pem, "ascii")
                ).decode(),
                "wrapAlgo": {
                    "name": "RSA-OAEP",
                    "label": b64encode(bytes(label, "ascii")).decode(),
                },
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        unwrapped = r.body.data()
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
        wrappedKey = r.body.data()
        assert wrappedKey is not None
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.post(
            "/app/unwrapKey",
            {
                "key": b64encode(wrappedKey).decode(),
                "unwrappingKey": b64encode(aes_wrapping_key).decode(),
                "wrapAlgo": {"name": "AES-KWP"},
            },
        )

        assert r.status_code == http.HTTPStatus.OK, r.status_code
        wrappedKey = r.body.data()
        assert wrappedKey == aes_key_to_wrap

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
        wrappedKey = r.body.data()
        assert wrappedKey is not None

        r = c.post(
            "/app/unwrapKey",
            {
                "key": b64encode(wrappedKey).decode(),
                "unwrappingKey": b64encode(
                    bytes(wrapping_key_priv_pem, "ascii")
                ).decode(),
                "wrapAlgo": {
                    "name": "RSA-OAEP-AES-KWP",
                    "aesKeySize": 256,
                    "label": b64encode(bytes(label, "ascii")).decode(),
                },
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        unwrapped = r.body.data()
        assert unwrapped == aes_key_to_wrap

        # Test RSA signing + verification
        key_priv_pem, key_pub_pem = infra.crypto.generate_rsa_keypair(2048)
        algorithm = {"name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256"}
        data = rand_bytes(random.randint(2, 50))
        r = c.post(
            "/app/sign",
            {
                "algorithm": algorithm,
                "key": key_priv_pem,
                "data": b64encode(data).decode(),
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        signature = r.body.data()
        infra.crypto.verify_signature(algorithm, signature, data, key_pub_pem)

        # Also verify with the JS API
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
        assert r.body.json() is True, r.body

        try:
            infra.crypto.verify_signature(
                algorithm, signature, "bar".encode(), key_pub_pem
            )
            assert False, "verify_signature() should throw"
        except InvalidSignature:
            pass

        # Test ECDSA signing + verification
        curves = [ec.SECP256R1, ec.SECP256K1, ec.SECP384R1]
        for curve in curves:
            key_priv_pem, key_pub_pem = infra.crypto.generate_ec_keypair(curve)
            algorithm = {"name": "ECDSA", "hash": "SHA-256"}
            r = c.post(
                "/app/sign",
                {
                    "algorithm": algorithm,
                    "key": key_priv_pem,
                    "data": b64encode(data).decode(),
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code

            signature = r.body.data()
            infra.crypto.verify_signature(algorithm, signature, data, key_pub_pem)

            # Also verify with the JS API
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
            assert r.body.json() is True, r.body

            try:
                infra.crypto.verify_signature(
                    algorithm, signature, "bar".encode(), key_pub_pem
                )
                assert False, "verify_signature() should throw"
            except InvalidSignature:
                pass

        # Test EDDSA signing + verification
        key_priv_pem, key_pub_pem = infra.crypto.generate_eddsa_keypair("curve25519")
        algorithm = {"name": "EdDSA"}
        r = c.post(
            "/app/sign",
            {
                "algorithm": algorithm,
                "key": key_priv_pem,
                "data": b64encode(data).decode(),
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        signature = r.body.data()
        infra.crypto.verify_signature(algorithm, signature, data, key_pub_pem)

        # Also verify with the JS API
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
        assert r.body.json() is True, r.body

        try:
            infra.crypto.verify_signature(
                algorithm, signature, "bar".encode(), key_pub_pem
            )
            assert False, "verify_signature() should throw"
        except InvalidSignature:
            pass

        key_priv_pem, key_pub_pem = infra.crypto.generate_rsa_keypair(2048)
        algorithm = {"name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256"}
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
        assert r.body.json() is True, r.body

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
        assert r.body.json() is False, r.body

        curves = [ec.SECP256R1, ec.SECP256K1, ec.SECP384R1]
        for curve in curves:
            key_priv_pem, key_pub_pem = infra.crypto.generate_ec_keypair(curve)
            algorithm = {"name": "ECDSA", "hash": "SHA-256"}
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
            assert r.body.json() is True, r.body

        key_priv_pem, key_pub_pem = infra.crypto.generate_eddsa_keypair("curve25519")
        algorithm = {"name": "EdDSA"}
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
        assert r.body.json() is True, r.body

        # Test HMAC
        key = "super secret"
        for ccf_hash, py_hash in [
            ("SHA-256", "sha256"),
            ("SHA-384", "sha384"),
            ("SHA-512", "sha512"),
        ]:
            algorithm = {"name": "HMAC", "hash": ccf_hash}
            r = c.post(
                "/app/sign",
                {
                    "algorithm": algorithm,
                    "key": key,
                    "data": b64encode(data).decode(),
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            hmac_py = hmac.digest(key.encode(), data, py_hash)
            assert hmac_py == r.body.data(), f"{hmac_py} != {r.body.data()}"

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

        r = c.get("/app/log/version?id=42")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/log?id=42", {"msg": "Hello!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.get("/app/log?id=42")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        assert body["id"] == 42, r.body
        assert body["msg"] == "Hello!", r.body

        r = c.get("/app/log/version?id=42")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        v0 = r.body.json()["version"]

        r = c.post("/app/log?id=42", {"msg": "Saluton!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.get("/app/log/version?id=42")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        v1 = r.body.json()["version"]
        assert v1 > v0

        r = c.get("/app/log/version?id=43")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/log?id=43", {"msg": "Bonjour!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.get("/app/log/version?id=43")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        v2 = r.body.json()["version"]
        assert v2 > v1

        r = c.get("/app/log/all")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        # Response is list in undefined order
        assert len(body) == 2, body
        assert {"id": 42, "msg": "Saluton!"} in body, body
        assert {"id": 43, "msg": "Bonjour!"} in body, body

        r = c.get("/app/log/version?id=42")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        v3 = r.body.json()["version"]
        assert v3 == v1

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
        if args.enclave_platform == "sgx":
            LOG.info("SGX: Test verifyOpenEnclaveEvidence")
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
        elif args.enclave_platform == "snp":
            LOG.info("SNP: Test verifySnpAttestation")

            def corrupt_value(value: str):
                return value[len(value) // 2 :] + value[: len(value) // 2]

            # Test without UVM endorsements
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            assert "uvm_endorsements" not in r.body.json()
            for key, value in r.body.json().items():
                LOG.info(f"{key} : {value}")
            report_json = r.body.json()["attestation"]
            assert report_json["report_data"] == primary_quote_info["node_id"] + (
                "0" * 32 * 2
            )

            # Test with UVM endorsements
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            assert "uvm_endorsements" in r.body.json()
            for key, value in r.body.json().items():
                LOG.info(f"{key} : {value}")

            # Test endorsed TCB too small
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                    "endorsed_tcb": "0000000000000000",
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
            assert "does not match reported TCB" in r.body.json()["error"]["message"]

            # Test too short a quote
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"][:-10],
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
            assert (
                "attestation report is not of expected size"
                in r.body.json()["error"]["message"]
            )

            # Test too long a quote
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"] + "1",
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
            assert (
                "attestation report is not of expected size"
                in r.body.json()["error"]["message"]
            )

            # Test corrupted quote
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": corrupt_value(primary_quote_info["raw"]),
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

            # Test too short an endorsement
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"][:-10],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
            assert (
                "Expected 3 endorsement certificates but got 2"
                in r.body.json()["error"]["message"]
            )

            # Test too long an endorsement
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"] + "1",
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

            # Test corrupted endorsements
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": corrupt_value(primary_quote_info["endorsements"]),
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

            # Test too short a uvm endorsement
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"][:-10],
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

            # Test too long a uvm endorsement
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": primary_quote_info["uvm_endorsements"] + "1",
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

            # Test corrupted uvm endorsements
            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": primary_quote_info["raw"],
                    "endorsements": primary_quote_info["endorsements"],
                    "uvm_endorsements": corrupt_value(
                        primary_quote_info["uvm_endorsements"]
                    ),
                },
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        else:
            LOG.info(
                "Virtual: Test verifySnpAttestation with a static attestation report"
            )
            reference_quote = {
                "endorsements": """
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZURENDQXZ1Z0F3SUJBZ0lCQURCR0Jna3Foa2lHOXcwQkFRb3dPYUFQTUEwR0NXQ0dTQUZsQXdRQ0FnVUEKb1J3d0dnWUpLb1pJaHZjTkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVENqQXdJQkFUQjdNUlF3RWdZRApWUVFMREF0RmJtZHBibVZsY21sdVp6RUxNQWtHQTFVRUJoTUNWVk14RkRBU0JnTlZCQWNNQzFOaGJuUmhJRU5zCllYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqWldRZ1RXbGpjbThnUkdWMmFXTmwKY3pFU01CQUdBMVVFQXd3SlUwVldMVTFwYkdGdU1CNFhEVEl5TVRFeU9UQXdNREF6TVZvWERUSTVNVEV5T1RBdwpNREF6TVZvd2VqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4Q3pBSkJnTlZCQVlUQWxWVE1SUXdFZ1lEClZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhIekFkQmdOVkJBb01Ga0ZrZG1GdVkyVmsKSUUxcFkzSnZJRVJsZG1salpYTXhFVEFQQmdOVkJBTU1DRk5GVmkxV1EwVkxNSFl3RUFZSEtvWkl6ajBDQVFZRgpLNEVFQUNJRFlnQUUwMjhLTjdsWXlhc0ZJa2NsY255d2c0TC9oZmVVenFkeTVRdGlXZFNHTGRlK3FrcHJHZXBNCk5DMzhyNEFya3Jlb3lLaWVyWlRQVk02NTc5Qk9sRFZURldlaE9WMklkbUlzc3V1TTdoOENwL01NcmhRWU1DZ2cKRzdaVjI1UXpnV0JVbzRJQkZqQ0NBUkl3RUFZSkt3WUJCQUdjZUFFQkJBTUNBUUF3RndZSkt3WUJCQUdjZUFFQwpCQW9XQ0UxcGJHRnVMVUl3TUJFR0Npc0dBUVFCbkhnQkF3RUVBd0lCQXpBUkJnb3JCZ0VFQVp4NEFRTUNCQU1DCkFRQXdFUVlLS3dZQkJBR2NlQUVEQkFRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdVRUF3SUJBREFSQmdvckJnRUUKQVp4NEFRTUdCQU1DQVFBd0VRWUtLd1lCQkFHY2VBRURCd1FEQWdFQU1CRUdDaXNHQVFRQm5IZ0JBd01FQXdJQgpDREFSQmdvckJnRUVBWng0QVFNSUJBTUNBWE13VFFZSkt3WUJCQUdjZUFFRUJFQTlsc212ZnE4eXpranZNbVJwCmppTisxWXhXTzNkamRCZkFsckxtZ1AyZGpKbHcya1BvSTJQTVFQRWNUcVQ3cEV3V0dDaTJ4VExMaTFVSHdsb3EKMlYrUE1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQgpBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDTUdkMVZmL0pBeEhvUFo3V3FwOTZLClpGQUY0NFBKMStIMG52Zmg1UlhHeVIwRGZYbmh4N05PZ2pkVWtjRU1OcDdVdzlNSlpRSVZNQnNnVER5c0gxVi8KWWFLbkhSMENjWVE5L3l6MWhMSjBvNStKMVlha0RIVktrbEJyWWgyazkwN3B4d3hVb3FVWWZuWVhmN3hQRDYycApUT0k5WndBbzlYdDM5K2JuUXVkajg4d1JoOThkaWFNeTVBTVcwYnR2ZHI3azhSSmp4MmpTalN5Qnp1ZnhyamxZCmdnNy9iVjNVMHJtTkFXTiswUy92cFAvMk1SZmhvMkxCbVJ1R0l4YllNeWZneWRjLzRPK2dlMzk0a01QeEIySVgKOFpSRGNiZEV1eGFqMGpDWndkeFJURDErbmhXQWZCR3M0VDNVSFFtK0dX
OHpFWm5QOEpIQmNjZHR3blEvUDB1QgpHeURLeU5PL0xjQ212TVRQdUw4SFAvSFN1Y0laSlZmckYzM0VMSE5PbllHdDBMVXRXMmp4M05JVmtMaktnekFFCm1sYkhENktMalFPRkJnVE5INXlhUWpQRjhKemY4eDhlNFFXQ3hoSEZPbS9HeWJGblM0dXZMNVNxd0YvSW1qVlcKWU1uMnJMV2RUb0hrTjhTdXVia3V3aGtBSHo3dGYxRjhTYk5FQlZjUHJuTEZJdHFxc2Fpb1JXNnU5ZzJ6Y3JUUgpXYmg2UGNKR3l5bVV1NkpncWxmZWRFVENxcWlVWVRya2dKM2VwbzkyNDZuSng1ZE9aMFFYbEN6SmdwMFR0ZWtlCkIrZFAveFRkZ2MrTnFhVlpDRlRHUnlNYzlrN245K3I1Q1pNS0dPNkJnRk14aG9FNFJvejFMdG5OeWU1N2h6VmQKVWxRUjlEcTcxWDFtaDNFZG11ZFRtQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdpVENDQkRpZ0F3SUJBZ0lEQVFBQk1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNOTWpBeE1ESXlNVGd5TkRJd1doY05ORFV4TURJeQpNVGd5TkRJd1dqQjdNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldRZ1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKVTBWV0xVMXBiR0Z1TUlJQ0lqQU5CZ2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBblUyZHJyTlRmYmhOUUlsbGYrVzJ5K1JPQ2JTeklkMWFLWmZ0CjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05UY0IwVllYdDNKeFpTek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXcKS1pYMEptUUV1WWptK1dLa3NMdHhnZExwOUU3RVpOd05EcVYxcjBxUlA1dEI4T1dreVFiSWRMZXU0YUN6N2ovUwpsMUZrQnl0ZXY5c2JGR3p0N2N3bmp6aTltN25vcXNrK3VSVkJwMytJbjM1UVBkY2o4WWZsRW1uSEJOdnVVREpoCkxDSk1XOEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pUTThLc05iVXgzQThlazVFVkwKalpXSDFwdDlFM1RmcFI2WHlmUUtuWTZrbDVhRUlQd2RXM2VGWWFxQ0ZQcklvOXBRVDZXdURTUDRKQ1lKYlpuZQpLS0liWmp6WGtKdDNOUUczMkV1a1lJbUJiOVNDa205K2ZTNUxaRmc5b2p6dWJNWDMrTmtCb1NYSTdPUHZuSE14Cmp1cDltdzVzZTZRVVY3R3FwQ0EyVE55cG9sbXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGwKQWxKdzVEMENUUlRDMVk1WVdGREJDckEvdkdubVRucUc4
QytqalVBUzdjampSOHE0T1BoeURtSlJQbmFDL1pHNQp1UDBLMHo2R29PLzN1ZW45d3FzaEN1SGVnTFRwT2VIRUpSS3JRRnI0UFZJd1ZPQjArZWJPNUZnb3lPdzQzbnlGCkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FSSXMxRW9xRWptRjhVdHJtUVdWMmhVand6cXd2SEYKZWk4clB4TUNBd0VBQWFPQm96Q0JvREFkQmdOVkhRNEVGZ1FVTzhadUdDckQvVDFpWkVpYjQ3ZEhMTFQ4di9ndwpId1lEVlIwakJCZ3dGb0FVaGF3YTBVUDN5S3hWMU1VZFFVaXIxWGhLMUZNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCCi93SUJBREFPQmdOVkhROEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIwY0hNNkx5OXIKWkhOcGJuUm1MbUZ0WkM1amIyMHZkbU5sYXk5Mk1TOU5hV3hoYmk5amNtd3dSZ1lKS29aSWh2Y05BUUVLTURtZwpEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTkJnbGdoa2dCWlFNRUFnSUZBS0lECkFnRXdvd01DQVFFRGdnSUJBSWdlVVFTY0FmM2xEWXFnV1UxVnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEUKUEkxamgzZ0piTHhMNmdmM0s4anhjdHpPV25rWWNiZGZNT09yMjhLVDM1SWFBUjIwcmVrS1JGcHRUSGhlK0RGcgozQUZ6WkxERDdjV0syOS9HcFBpdFBKREtDdkk3QTRVZzA2cms3SjB6QmUxZnovcWU0aTIvRjEycnZmd0NHWWhjClJ4UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpNa3Q3REZ2S1JoKzJ6Sys1cGxWR0cKRnNqREp0TXoydWQ5eTBwdk9FNGozZEg1SVc5akd4YVNHU3RxTnJhYm5ucEYyMzZFVHIxL2E0M2I4RkZLTDVRTgptdDhWcjl4blhScHpucUNSdnFqcitrVnJiNmRsZnVUbGxpWGVRVE1sQm9SV0ZKT1JMOEFjQkp4R1o0SzJtWGZ0CmwxalU1VExlaDVLWEw5Tlc3YS9xQU9JVXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnIKRWc2emt4bXZNdWFiWk9zZEtmUmtXZmhIMlpLY1RsRGZtSDFIMHpxMFEyYkczdXZhVmRpQ3RGWTFMbFd5QjM4SgpTMmZOc1IvUHk2dDVickVKQ0ZOdnphRGt5NktlQzRpb24vY1ZnVWFpN3p6UzNiR1FXektES1UzNVNxTlUyV2tQCkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBlMDF6RDBOOGF0RnhtV2lTbmZKbDY5MEI5ckpwTlIvZkkKYWp4Q1czU2Vpd3M2cjFabSt0Q3VWYk1pTnRwUzlUaGpOWDR1dmU1dGh5ZkUyRGdveFJGdlkxQ3NvRjVNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdZekNDQkJLZ0F3SUJBZ0lEQVFBQU1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpDQk5h
V055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNOTWpBeE1ESXlNVGN5TXpBMVdoY05ORFV4TURJeQpNVGN5TXpBMVdqQjdNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldRZ1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKUVZKTExVMXBiR0Z1TUlJQ0lqQU5CZ2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJSSk9kZWlKbHFLMkpkc1ZtRDdGa3R1b3RXd1gxZk5nClc0MVhZOVh6MUhFaFNVbWhMejlDdTlESFJsdmdKU054YmVZWXNuSmZ2eWp4MU1mVTBWNXRrS2lVMUVlc05GdGEKMWtUQTBzek5pc2RZYzlpc3FrN21YVDUrS2ZHUmJmYzRWLzl6UkljRThqbEhONjFTMWp1OFg5Mys2ZHhEVXJHMgpTenhxSjRCaHF5WW1VRHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0yQitPK3Zqc0MwCjYwZDM3alk5TEZldU9QNE1lcmk4cWdmaTJTNWtLcWcvYUY2YVB0dUFaUVZSN3UzS0ZZWFA1OVhtSmd0Y29nMDUKZ21JMFQvT2l0TGh1elZ2cFpjTHBoMG9kaC8xSVBYcXgzK01uakQ5N0E3ZlhwcUdkL3k4S3hYN2prc1RFekFPZwpiS0FlYW0zbG0rM3lLSWNUWU1sc1JNWFBjak5iSXZtc0J5a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzCitnVkRrdVZQaHNueklSTmdZdk00OFkrN0xHaUpZbnJtRTh4Y3JleGVrQnhydmEyVjlUSlFxbk4zUTUza3Q1dmkKUWkzK2dDZm1rd0MwRjB0aXJJWmJMa1hQclB3elowTTllTnhoSXlTYjJucEpmZ25xejU1STB1MzN3aDRyMFpOUQplVEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBDcTcrT2dwQ0NvTU5pdDJ1TG85TTE4CmZIejEwbE9NVDhuV0FVdlJaRnp0ZVhDbSs3UEhkWVBsbVF3VXczTHZlbkovSUxYb1FQSGZia0gwQ3lQZmhsMWoKV2hKRlphc0NBd0VBQWFOK01Id3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CMEdBMVVkRGdRV0JCU0ZyQnJSUS9mSQpyRlhVeFIxQlNLdlZlRXJVVXpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VHCktXaDBkSEJ6T2k4dmEyUnphVzUwWmk1aGJXUXVZMjl0TDNaalpXc3ZkakV2VFdsc1lXNHZZM0pzTUVZR0NTcUcKU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQkFRZ3dEUVlKWUlaSQpBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDNm0wa0RwNnp2NE9qZmd5K3psZWVoc3g2b2wwb2NnVmVsCkVUb2JweCtFdUNzcVZGUlBLMWpaMXNwL2x5ZDkrMGZRMHI2Nm43a2FnUms0Q2EzOWc2NldHVEpNZUpkcVlyaXcKU1RqakRDS1ZQU2VzV1hZUFZBeURobVA1bjJ2K0JZaXBaV2hwdnFwYWlPK0VHSzVJQlArNTc4UWVXL3NTb2tySwpkSGFMQXhHMkxoWnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dTZ2tEZ3V0
Q1RCMVlxCnpUNUR1d3ZBZStjbzJDSVZJek1EYW1ZdVNGalBOMEJDZ29qbDdWK2JUb3U3ZE1zcUl1L1RXL3JQQ1g5L0VVY3AKS0dLcVBRM1ArTjlyMWhqRUZZMXBsQmc5M3Q1M09PbzQ5R05JK1YxenZYUExJNnhJRlZzaCttdG8yUnRnRVgvZQpwbU1LVE5ONnBzVzg4cWc3YzFoVFd0TjZNYlJ1UTB2bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxCkhuSVloeHkwWUtYR3lhVzFOamZVTHhycm14Vlc0d2NuNUU4R2RkbXZOYTZ5WW04c2NKYWdFaTEzbWhHdTRKcWgKM1FVM3NmOGlVU1VyMDl4UUR3SHRPUVVWSXF4NG1hQlpQQnRTTWYrcVVEdGpYU1NxOGxmV2NkOGJMcjltZHNVbgpKWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2VzFVbXEyNWJveENZSitUdUJvYTRzK0hICkNWaUF2Z1Q5a2YvckJxMWQraXZqNnNra0h4dXpjeGJrMXh2NlpHeHJ0ZUp4Vkg3S2xYN1lSZFo2ZUFSS3dMZTQKQUZaRUF3b0tDUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K""",
                "format": "AMD_SEV_SNP_v1",
                "mrenclave": "03fea02823189b25d0623a5c81f97c8ba4d2fbc48c914a55ce525f90454ddcec303743dac2fc013f0846912d1412f6df",
                "node_id": "0bb79965d12f30a80917304180a3886e5b809694a745f9926b8b6eb36e853125",
                "raw": "AgAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAAAI0gEAAAAAAAAAAAAAAAAAAAALt5ll0S8wqAkXMEGAo4huW4CWlKdF+ZJri26zboUxJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6gKCMYmyXQYjpcgfl8i6TS+8SMkUpVzlJfkEVN3OwwN0PawvwBPwhGkS0UEvbfT0RIxn88jfyN6KXjcSXYB9rcxB8GzyP2FdvVLux3fRDr7uq84HXuq6PZ6iTYSVE3ood8DSCsbqc/xtL4rrUN4TIVDgoHUmZJGbzrvy6MWAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtyoU+xDCNI/n4DHYmVdG+3NwB7hr+863whqgEX7szrP//////////////////////////////////////////AwAAAAAACHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9lsmvfq8yzkjvMmRpjiN+1YxWO3djdBfAlrLmgP2djJlw2kPoI2PMQPEcTqT7pEwWGCi2xTLLi1UHwloq2V+PAwAAAAAACHMENAEABDQBAAMAAAAAAAhzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApgYvMehGmkOCv22Tf+8ddV+0CyLuGkpVwvZ3eVfTpVxE/TogI8UOnIMPfhbUKPXwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG7LZf7ziqDf/WmFhiAY+m/QafKBReO6b+Kje5Oh/+x1BDtMEKVxa79nr2/j3HUwZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "uvm_endorsements": """
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""",
            }

            r = c.post(
                "/app/verifySnpAttestation",
                {
                    "evidence": reference_quote["raw"],
                    "endorsements": reference_quote["endorsements"],
                    "uvm_endorsements": reference_quote["uvm_endorsements"],
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code
            report_json = r.body.json()["attestation"]
            print(f"{report_json=}")
            assert report_json[
                "report_data"
            ] == "0bb79965d12f30a80917304180a3886e5b809694a745f9926b8b6eb36e853125" + (
                "0" * 32 * 2
            )
            assert (
                report_json["measurement"]
                == "03fea02823189b25d0623a5c81f97c8ba4d2fbc48c914a55ce525f90454ddcec303743dac2fc013f0846912d1412f6df"
            )
            assert (
                report_json["host_data"]
                == "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10"
            )

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
    bundle = infra.consortium.slurp_json(bundle_path)
    network.consortium.set_js_app_from_bundle(primary, bundle)

    LOG.info("Store JWT signing keys")
    jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)
    jwt_kid = "my_other_key_id"
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
        # fetch defaults from js_metrics endpoint
        r = c.get("/node/js_metrics")
        body = r.body.json()
        default_max_heap_size = body["max_heap_size"]
        default_max_stack_size = body["max_stack_size"]
        default_max_execution_time = body["max_execution_time"]

        # set JS execution time to a lower value which will timeout this
        # endpoint execution
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=50 * 1024 * 1024,
            max_stack_bytes=1024 * 512,
            max_execution_time_ms=1,
        )
        user_id = "user0"
        jwt = infra.crypto.create_jwt({"sub": user_id}, jwt_key_priv_pem, jwt_kid)

        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["message"] == "Operation took too long to complete."

        # reset the execution time
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
        )
        r = c.get("/app/jwt", headers={"authorization": "Bearer " + jwt})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        assert body["userId"] == user_id, r.body

    return network


@reqs.description("Test JS exception output")
def test_js_exception_output(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        default_max_heap_size = body["max_heap_size"]
        default_max_stack_size = body["max_stack_size"]
        default_max_execution_time = body["max_execution_time"]

        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert "details" not in body["error"]

        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            return_exception_details=True,
        )
        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert body["error"]["details"][0]["code"] == "JSException"
        assert body["error"]["details"][0]["message"] == "Error: test error: 42"
        assert (
            body["error"]["details"][0]["trace"]
            == "    at nested (endpoints/rpc.js:27)\n    at throwError (endpoints/rpc.js:29)\n"
        )

        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            return_exception_details=False,
        )

        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert "details" not in body["error"]

        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            log_exception_details=True,
        )

        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert "details" not in body["error"]

    return network


@reqs.description("Test User Cose authentication")
def test_user_cose_authentication(network, args):
    primary, _ = network.find_nodes()

    with primary.client() as c:
        r = c.put("/app/cose", {})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r

    with primary.client("user0") as c:
        r = c.put("/app/cose", {})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r

    with primary.client("user0", headers={"content-type": "application/cose"}) as c:
        r = c.put("/app/cose", {})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r

    with primary.client(None, None, "user0") as c:
        r = c.put("/app/cose", body={"some": "content"})
        assert r.status_code == http.HTTPStatus.OK, r
        body = r.body.json()
        assert body["policy"] == "user_cose_sign1"
        assert body["id"] == network.users[0].service_id

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
        network = test_js_exception_output(network, args)
        network = test_user_cose_authentication(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
