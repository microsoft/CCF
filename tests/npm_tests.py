# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
#
from base64 import b64encode, b64decode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from jwcrypto import jwk
import hmac
import http
import infra.proc
import json
import openapi_spec_validator
import os
import random
import subprocess
import suite.test_requirements as reqs

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
    curves = [ec.SECP256R1, ec.SECP384R1]
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
    key_sizes = [2048, 4096]
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
        converted_pem = body["pem"]

        # PEMs may vary because of discrepancies of RSA key private components
        # computation, in particular, using Euler VS Carmichael totient
        # functions. For more details check the thread:
        # https://github.com/microsoft/CCF/issues/6588#issuecomment-2568037993.
        algorithm = {"name": "RSA-PSS", "hash": "SHA-256"}
        data = rand_bytes(random.randint(2, 50))
        signature = infra.crypto.sign(algorithm, converted_pem, data)
        infra.crypto.verify_signature(algorithm, signature, data, pub_pem)

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
    for curve in ["curve25519", "x25519"]:
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


def rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


@reqs.description("Build basic Node.js/npm app")
def build_npm_app(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Building ccf-app npm package (dependency)")
    ccf_pkg_dir = os.path.join(PARENT_DIR, "js", "ccf-app")
    subprocess.run(["npm", "install", "--no-package-lock"], cwd=ccf_pkg_dir, check=True)

    LOG.info("Running ccf-app unit tests")
    subprocess.run(["npm", "test"], cwd=ccf_pkg_dir, check=True)

    LOG.info("Building npm app")
    app_dir = os.path.join(THIS_DIR, "npm-app")
    assert infra.proc.ccall("npm", "install", path=app_dir).returncode == 0
    assert (
        infra.proc.ccall("npm", "run", "build", "--verbose", path=app_dir).returncode
        == 0
    )

    return network


@reqs.description("Deploy basic Node.js/npm app")
def deploy_npm_app(network, args):
    primary, _ = network.find_nodes()

    app_dir = os.path.join(THIS_DIR, "npm-app")

    LOG.info("Deploying npm app")
    bundle_path = os.path.join(
        app_dir, "dist", "bundle.json"
    )  # Produced by build_npm_app
    bundle = infra.consortium.slurp_json(bundle_path)
    network.consortium.set_js_app_from_bundle(primary, bundle)

    return network


@reqs.description("Test basic Node.js/npm app")
def test_npm_app(network, args):
    primary, _ = network.find_nodes()

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

        # Test KV converter APIs
        r = c.post("/app/converters/set")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert "Passed" in r.body.text(), r.body

        r = c.get("/app/converters/get")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert "Passed" in r.body.text(), r.body

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
        algorithm = {"name": "RSA-PSS", "hash": "SHA-256", "saltLength": 32}
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
        curves = [ec.SECP256R1, ec.SECP384R1]
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
        algorithm = {"name": "RSA-PSS", "hash": "SHA-256", "saltLength": 32}
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

        curves = [ec.SECP256R1, ec.SECP384R1]
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
        r = c.post("/app/isValidX509CertChain", {"chain": pem2, "trusted": pem2})
        assert r.body.json(), r.body
        # does not validate trusted certificates where CA=False
        r = c.post("/app/isValidX509CertChain", {"chain": pem3, "trusted": pem3})
        assert r.status_code == 200, r.status_code
        assert r.body.text() == "false", r.body
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

        # Test that static SNP attestation report format can be verified
        LOG.info("Test verifySnpAttestation with a static attestation report")
        reference_quote = {
            "endorsements": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZRekNDQXZlZ0F3SUJBZ0lCQURCQkJna3Foa2lHOXcwQkFRb3dOS0FQTUEwR0NXQ0dTQUZsQXdRQ0FnVUEKb1J3d0dnWUpLb1pJaHZjTkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVEF3ZXpFVU1CSUdBMVVFQ3d3TApSVzVuYVc1bFpYSnBibWN4Q3pBSkJnTlZCQVlUQWxWVE1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMCk1Ba0dBMVVFQ0F3Q1EwRXhIekFkQmdOVkJBb01Ga0ZrZG1GdVkyVmtJRTFwWTNKdklFUmxkbWxqWlhNeEVqQVEKQmdOVkJBTU1DVk5GVmkxTmFXeGhiakFlRncweU5UQXhNak14T1RVd01EbGFGdzB6TWpBeE1qTXhPVFV3TURsYQpNSG94RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1Rc3dDUVlEVlFRR0V3SlZVekVVTUJJR0ExVUVCd3dMClUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CTVI4d0hRWURWUVFLREJaQlpIWmhibU5sWkNCTmFXTnkKYnlCRVpYWnBZMlZ6TVJFd0R3WURWUVFEREFoVFJWWXRWa05GU3pCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaQpBMklBQkhHcG4zUWZSeU1aUTdMZDRIUUt6YlJOcmQwMVRyZzd2WnpRd282STRWNHVsdWJnRGt1dUd3NTFOYUZkCktlVE1MR04zWHdMWWZlRExUcDJkekNzcTdsK3dOMGQ4aGJ1bjF0aTBYSE5EaG4yb1pnTVd5SzF5clBZeFVlQTYKbkd1ZERLT0NBUmN3Z2dFVE1CQUdDU3NHQVFRQm5IZ0JBUVFEQWdFQU1CY0dDU3NHQVFRQm5IZ0JBZ1FLRmdoTgphV3hoYmkxQ01EQVJCZ29yQmdFRUFaeDRBUU1CQkFNQ0FRUXdFUVlLS3dZQkJBR2NlQUVEQWdRREFnRUFNQkVHCkNpc0dBUVFCbkhnQkF3UUVBd0lCQURBUkJnb3JCZ0VFQVp4NEFRTUZCQU1DQVFBd0VRWUtLd1lCQkFHY2VBRUQKQmdRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdjRUF3SUJBREFSQmdvckJnRUVBWng0QVFNREJBTUNBUmd3RWdZSwpLd1lCQkFHY2VBRURDQVFFQWdJQTJ6Qk5CZ2tyQmdFRUFaeDRBUVFFUUYwRk9NWDlwdVorWXJQV01KZGJwRFZYCjNyWnhXNXA2Ni9BenhBTmd4Yk5pS1hxUFVlQXBYTmZmZUlrbGVkWlZJenRxcjhtNUc0ODh0Z3ZSbmJ0SU10Y3cKUVFZSktvWklodmNOQVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTgpCZ2xnaGtnQlpRTUVBZ0lGQUtJREFnRXdBNElDQVFBUFdSNXVYVExjVUhlQm1FNjVtbmtDM1NDby83ZzNFaVowCnQ5Wm9lQUg4VE84WE5nWEJxNk9ZR2NPc1NHb2lLUThodklTOVhNYkwwdW9qVytOd1VPVTJvT0E5dTBTNlNLOGwKOEc0amRBOTJTcVE2c1NDU0RaVXBBUVVwWUhuVW9RaGFNK3BENjBmTUExelQ0eGUxOTh6RmpGdjhPUWtkVmlragpLYmVyTnJtcG5GTUQrcXI4ZFRwSENHdWx0R3ljd1JzOG95WVhDa2hSMHpabEZwRDdyb2JFU25ZZCtvQ09mQ2pYCmFpSFB6RnBxZnIwczV4SkJNMENuT2tjOTAyUmNHNlhCU2FKaUdsT3JlZHlFUlkra1RyODZ2Z0ppVndSMUlBWHoKTTZOUXpEdjhMOWtEM3BkRGVRS2dmd1RoMmFQZGdVNnBPVGF3eG41T3Rtb2tZM1Ztdi9DNHkvMVlBVG9zZjRsUgpkSTBhSFQxc3BmdEF6UldPL0VLbVdXMHBxZWw2Q21DR2tQODJwR1NGZVh2T3pHcUhzaVNTUjBXODBiS2pGak5QCjdrNkRMb20zb2dWNnlHK3lJSDhqK1RRVVU2OGJXdTh4bEZqQUtGd0hsY1VobVVYM1FabHdHMXo4Qm9xeGZmUXAKZWNnVzlDZmEvUHZ1ZlovL09EUWhMTnVBL2czNWVhczh0azJBLzhxU1hjV1FTaDJKbzVHNlFBUGNTTlJmQWNGUgpOYkhQRnBrc05Xa3hBZjJjQWZQSFlnbURpOWNkbzFEQ3kvQU1oajd4UjhKVnhReW9qdmxDRGEvL0xxc1ozRUFoCnlkMHJEWnJyWFdOOXN3VmtlT25HcUVEWTdZUkRmRFp3Z0YyR2g0QWRhWUtGeEFhNW83Qmt2RSt6VEdOMUtJV2YKQ1JEWDNOUmVQQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlHaVRDQ0JEaWdBd0lCQWdJREFRQUJNRVlHQ1NxR1NJYjNEUUVCQ2pBNW9BOHdEUVlKWUlaSUFXVURCQUlDCkJRQ2hIREFhQmdrcWhraUc5dzBCQVFnd0RRWUpZSVpJQVdVREJBSUNCUUNpQXdJQk1LTURBZ0VCTUhzeEZEQVMKQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVFzd0NRWURWUVFHRXdKVlV6RVVNQklHQTFVRUJ3d0xVMkZ1ZEdFZwpRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUjh3SFFZRFZRUUtEQlpCWkhaaGJtTmxaQ0JOYVdOeWJ5QkVaWFpwClkyVnpNUkl3RUFZRFZRUUREQWxCVWtzdFRXbHNZVzR3SGhjTk1qQXhNREl5TVRneU5ESXdXaGNOTkRVeE1ESXkKTVRneU5ESXdXakI3TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RUxNQWtHQTFVRUJoTUNWVk14RkRBUwpCZ05WQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqClpXUWdUV2xqY204Z1JHVjJhV05sY3pFU01CQUdBMVVFQXd3SlUwVldMVTFwYkdGdU1JSUNJakFOQmdrcWhraUcKOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQW5VMmRyck5UZmJoTlFJbGxmK1cyeStST0NiU3pJZDFhS1pmdAoyVDl6alpRT3pqR2NjbDE3aTFtSUtXbDdOVGNCMFZZWHQzSnhaU3pPWmpzakxOVkFFTjJNR2o5VGllZEwrUWV3CktaWDBKbVFFdVlqbStXS2tzTHR4Z2RMcDlFN0VaTndORHFWMXIwcVJQNXRCOE9Xa3lRYklkTGV1NGFDejdqL1MKbDFGa0J5dGV2OXNiRkd6dDdjd25qemk5bTdub3Fzayt1UlZCcDMrSW4zNVFQZGNqOFlmbEVtbkhCTnZ1VURKaApMQ0pNVzhLT2pQNisrUGhiczNpQ2l0SmNBTkV0VzRxVE5Gb0tXM0NIbGJjU0NqVE04S3NOYlV4M0E4ZWs1RVZMCmpaV0gxcHQ5RTNUZnBSNlh5ZlFLblk2a2w1YUVJUHdkVzNlRllhcUNGUHJJbzlwUVQ2V3VEU1A0SkNZSmJabmUKS0tJYlpqelhrSnQzTlFHMzJFdWtZSW1CYjlTQ2ttOStmUzVMWkZnOW9qenViTVgzK05rQm9TWEk3T1B2bkhNeApqdXA5bXc1c2U2UVVWN0dxcENBMlROeXBvbG11UStjQWF4VjdKcUhFOGRsOXBXZitZM2FyYis5aWlGQ3dGdDRsCkFsSnc1RDBDVFJUQzFZNVlXRkRCQ3JBL3ZHbm1UbnFHOEMrampVQVM3Y2pqUjhxNE9QaHlEbUpSUG5hQy9aRzUKdVAwSzB6NkdvTy8zdWVuOXdxc2hDdUhlZ0xUcE9lSEVKUktyUUZyNFBWSXdWT0IwK2ViTzVGZ295T3c0M255RgpENVVLQkR4RUI0QktvLzB1QWlLSExSdnZnTGJPUmJVOEtBUklzMUVvcUVqbUY4VXRybVFXVjJoVWp3enF3dkhGCmVpOHJQeE1DQXdFQUFhT0JvekNCb0RBZEJnTlZIUTRFRmdRVU84WnVHQ3JEL1QxaVpFaWI0N2RITExUOHYvZ3cKSHdZRFZSMGpCQmd3Rm9BVWhhd2EwVVAzeUt4VjFNVWRRVWlyMVhoSzFGTXdFZ1lEVlIwVEFRSC9CQWd3QmdFQgovd0lCQURBT0JnTlZIUThCQWY4RUJBTUNBUVF3T2dZRFZSMGZCRE13TVRBdm9DMmdLNFlwYUhSMGNITTZMeTlyClpITnBiblJtTG1GdFpDNWpiMjB2ZG1ObGF5OTJNUzlOYVd4aGJpOWpjbXd3UmdZSktvWklodmNOQVFFS01EbWcKRHpBTkJnbGdoa2dCWlFNRUFnSUZBS0VjTUJvR0NTcUdTSWIzRFFFQkNEQU5CZ2xnaGtnQlpRTUVBZ0lGQUtJRApBZ0V3b3dNQ0FRRURnZ0lCQUlnZVVRU2NBZjNsRFlxZ1dVMVZ0bERibUlOOFMyZEM1a21RenNaL0h0QWpRbkxFClBJMWpoM2dKYkx4TDZnZjNLOGp4Y3R6T1dua1ljYmRmTU9PcjI4S1QzNUlhQVIyMHJla0tSRnB0VEhoZStERnIKM0FGelpMREQ3Y1dLMjkvR3BQaXRQSkRLQ3ZJN0E0VWcwNnJrN0owekJlMWZ6L3FlNGkyL0YxMnJ2ZndDR1loYwpSeFB5N1FGM3E4ZlI2R0NKZEIxVVE1U2x3Q2pGeEQ0dWV6VVJ6dElsSUFqTWt0N0RGdktSaCsyeksrNXBsVkdHCkZzakRKdE16MnVkOXkwcHZPRTRqM2RINUlXOWpHeGFTR1N0cU5yYWJubnBGMjM2RVRyMS9hNDNiOEZGS0w1UU4KbXQ4VnI5eG5YUnB6bnFDUnZxanIra1ZyYjZkbGZ1VGxsaVhlUVRNbEJvUldGSk9STDhBY0JKeEdaNEsybVhmdApsMWpVNVRMZWg1S1hMOU5XN2EvcUFPSVVzMkZpT2hxcnR6QWhKUmc5SWo4UWtROVBrK2NLR3p3NkVsM1Qza0ZyCkVnNnpreG12TXVhYlpPc2RLZlJrV2ZoSDJaS2NUbERmbUgxSDB6cTBRMmJHM3V2YVZkaUN0RlkxTGxXeUIzOEoKUzJmTnNSL1B5NnQ1YnJFSkNGTnZ6YURreTZLZUM0aW9uL2NWZ1VhaTd6elMzYkdRV3pLREtVMzVTcU5VMldrUApJOHhDWjAwV3RJaUtLRm5YV1VReHZsS21tZ1pCSVlQZTAxekQwTjhhdEZ4bVdpU25mSmw2OTBCOXJKcE5SL2ZJCmFqeENXM1NlaXdzNnIxWm0rdEN1VmJNaU50cFM5VGhqTlg0dXZlNXRoeWZFMkRnb3hSRnZZMUNzb0Y1TQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlHWXpDQ0JCS2dBd0lCQWdJREFRQUFNRVlHQ1NxR1NJYjNEUUVCQ2pBNW9BOHdEUVlKWUlaSUFXVURCQUlDCkJRQ2hIREFhQmdrcWhraUc5dzBCQVFnd0RRWUpZSVpJQVdVREJBSUNCUUNpQXdJQk1LTURBZ0VCTUhzeEZEQVMKQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVFzd0NRWURWUVFHRXdKVlV6RVVNQklHQTFVRUJ3d0xVMkZ1ZEdFZwpRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUjh3SFFZRFZRUUtEQlpCWkhaaGJtTmxaQ0JOYVdOeWJ5QkVaWFpwClkyVnpNUkl3RUFZRFZRUUREQWxCVWtzdFRXbHNZVzR3SGhjTk1qQXhNREl5TVRjeU16QTFXaGNOTkRVeE1ESXkKTVRjeU16QTFXakI3TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RUxNQWtHQTFVRUJoTUNWVk14RkRBUwpCZ05WQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqClpXUWdUV2xqY204Z1JHVjJhV05sY3pFU01CQUdBMVVFQXd3SlFWSkxMVTFwYkdGdU1JSUNJakFOQmdrcWhraUcKOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQTBMZDUyUkpPZGVpSmxxSzJKZHNWbUQ3Rmt0dW90V3dYMWZOZwpXNDFYWTlYejFIRWhTVW1oTHo5Q3U5REhSbHZnSlNOeGJlWVlzbkpmdnlqeDFNZlUwVjV0a0tpVTFFZXNORnRhCjFrVEEwc3pOaXNkWWM5aXNxazdtWFQ1K0tmR1JiZmM0Vi85elJJY0U4amxITjYxUzFqdThYOTMrNmR4RFVyRzIKU3p4cUo0QmhxeVltVURydVBYSlNYNHZVYzAxUDdqOThNcHFPUzk1ck9SZEdIZUk1Mk5hejVtMkIrTyt2anNDMAo2MGQzN2pZOUxGZXVPUDRNZXJpOHFnZmkyUzVrS3FnL2FGNmFQdHVBWlFWUjd1M0tGWVhQNTlYbUpndGNvZzA1CmdtSTBUL09pdExodXpWdnBaY0xwaDBvZGgvMUlQWHF4MytNbmpEOTdBN2ZYcHFHZC95OEt4WDdqa3NURXpBT2cKYktBZWFtM2xtKzN5S0ljVFlNbHNSTVhQY2pOYkl2bXNCeWtELy94U25pdXN1SEJrZ25sRU5FV3gxVWNiUVFycworZ1ZEa3VWUGhzbnpJUk5nWXZNNDhZKzdMR2lKWW5ybUU4eGNyZXhla0J4cnZhMlY5VEpRcW5OM1E1M2t0NXZpClFpMytnQ2Zta3dDMEYwdGlySVpiTGtYUHJQd3paME05ZU54aEl5U2IybnBKZmducXo1NUkwdTMzd2g0cjBaTlEKZVRHZncwM01CVXR5dXpHZXNHa2N3K2xvcU1hcTFxUjR0akdiUFl4Q3ZwQ3E3K09ncENDb01OaXQydUxvOU0xOApmSHoxMGxPTVQ4bldBVXZSWkZ6dGVYQ20rN1BIZFlQbG1Rd1V3M0x2ZW5KL0lMWG9RUEhmYmtIMEN5UGZobDFqCldoSkZaYXNDQXdFQUFhTitNSHd3RGdZRFZSMFBBUUgvQkFRREFnRUdNQjBHQTFVZERnUVdCQlNGckJyUlEvZkkKckZYVXhSMUJTS3ZWZUVyVVV6QVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Eb0dBMVVkSHdRek1ERXdMNkF0b0N1RwpLV2gwZEhCek9pOHZhMlJ6YVc1MFppNWhiV1F1WTI5dEwzWmpaV3N2ZGpFdlRXbHNZVzR2WTNKc01FWUdDU3FHClNJYjNEUUVCQ2pBNW9BOHdEUVlKWUlaSUFXVURCQUlDQlFDaEhEQWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWkkKQVdVREJBSUNCUUNpQXdJQk1LTURBZ0VCQTRJQ0FRQzZtMGtEcDZ6djRPamZneSt6bGVlaHN4Nm9sMG9jZ1ZlbApFVG9icHgrRXVDc3FWRlJQSzFqWjFzcC9seWQ5KzBmUTByNjZuN2thZ1JrNENhMzlnNjZXR1RKTWVKZHFZcml3ClNUampEQ0tWUFNlc1dYWVBWQXlEaG1QNW4yditCWWlwWldocHZxcGFpTytFR0s1SUJQKzU3OFFlVy9zU29rcksKZEhhTEF4RzJMaFp4ajlhRjczZnFDN09BSlo1YVBvbnc0UkUyOTlGVmFyaDFUeDJlVDN3U2drRGd1dENUQjFZcQp6VDVEdXd2QWUrY28yQ0lWSXpNRGFtWXVTRmpQTjBCQ2dvamw3VitiVG91N2RNc3FJdS9UVy9yUENYOS9FVWNwCktHS3FQUTNQK045cjFoakVGWTFwbEJnOTN0NTNPT280OUdOSStWMXp2WFBMSTZ4SUZWc2grbXRvMlJ0Z0VYL2UKcG1NS1ROTjZwc1c4OHFnN2MxaFRXdE42TWJSdVEwdm0rTysvMnRLQkYyaDhUSGI5NE92dkhIb0ZEcGJDRUxscQpIbklZaHh5MFlLWEd5YVcxTmpmVUx4cnJteFZXNHdjbjVFOEdkZG12TmE2eVltOHNjSmFnRWkxM21oR3U0SnFoCjNRVTNzZjhpVVNVcjA5eFFEd0h0T1FVVklxeDRtYUJaUEJ0U01mK3FVRHRqWFNTcThsZldjZDhiTHI5bWRzVW4KSlpKMCt0dVBNS21CblNIODYwbGxLaytWcFZRc2dxYnpESXZPTHZENlcxVW1xMjVib3hDWUorVHVCb2E0cytISApDVmlBdmdUOWtmL3JCcTFkK2l2ajZza2tIeHV6Y3hiazF4djZaR3hydGVKeFZIN0tsWDdZUmRaNmVBUkt3TGU0CkFGWkVBd29LQ1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
            "format": "AMD_SEV_SNP_v1",
            "raw": "AwAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAEAAAAAAAY2yUAAAAAAAAAAAAAAAAAAAB6amjAorhbiq4AygT2RIMWgCIvRBZ+VVip4HK3DGDpWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX+7jDW1+Gin0A9cKQZgjfd+xMFGi1pdkOUh8YJOI7X+YGJiHkgqy+gCWkDoMI/yhT0RIxn88jfyN6KXjcSXYB9rcxB8GzyP2FdvVLux3fRAK15zrC2SLDmqQ2KqfbqJMM6lotmMghTUxReixmkdBotq5ujQuE75PwNIl6InMGlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACVIk2axvE+bIOosxmtSxh/icSsczgbmecB8dbxgQDaV///////////////////////////////////////////BAAAAAAAGNsZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAABdBTjF/abmfmKz1jCXW6Q1V962cVuaeuvwM8QDYMWzYil6j1HgKVzX33iJJXnWVSM7aq/JuRuPPLYL0Z27SDLXBAAAAAAAGNsdNwEAHTcBAAQAAAAAABjbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg4r0K9bTsYnNMxE2LKWFwN2e6cnv0EwLjfJfOQBs6srRjpk3M3v/zMNiPTELMqEEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbkat92q6Bp9MIyIoH2uQsLrcCRs5MxbznVcqtVp5+glEEQmKm97IRyOUUBePAs2YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "uvm_endorsements": "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",
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
        ] == "7a6a68c0a2b85b8aae00ca04f644831680222f44167e5558a9e072b70c60e958" + (
            "0" * 32 * 2
        )
        assert (
            report_json["measurement"]
            == "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1"
        )
        assert (
            report_json["host_data"]
            == "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10"
        )

        LOG.info("Test verifySnpAttestation")

        def corrupt_value(value: str):
            return value[len(value) // 2 :] + value[: len(value) // 2]

        # Test without UVM endorsements
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"],
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert "uvm_endorsements" not in r.body.json()
        for key, value in r.body.json().items():
            LOG.info(f"{key} : {value}")
        report_json = r.body.json()["attestation"]
        assert report_json[
            "report_data"
        ] == "7a6a68c0a2b85b8aae00ca04f644831680222f44167e5558a9e072b70c60e958" + (
            "0" * 32 * 2
        )

        # Test with UVM endorsements
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"],
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
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"],
                "endorsed_tcb": "0000000000000000",
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        assert "does not match reported TCB" in r.body.json()["error"]["message"]

        # Test too short a quote
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"][:-10],
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"],
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
                "evidence": reference_quote["raw"] + "1",
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"],
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
                "evidence": corrupt_value(reference_quote["raw"]),
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"],
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

        # Test too short an endorsement
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"][:-10],
                "uvm_endorsements": reference_quote["uvm_endorsements"],
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        assert (
            "Expected 3 endorsement certificates but got 2"
            in r.body.json()["error"]["message"]
        )

        # Test too long an endorsement
        extended_endorsements = (
            b64decode(reference_quote["endorsements"])
            + b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"
        )
        extended_endorsements = b64encode(extended_endorsements).decode(
            encoding="utf-8"
        )
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": extended_endorsements,
                "uvm_endorsements": reference_quote["uvm_endorsements"],
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        assert (
            "Expected 3 endorsement certificates but got 4"
            in r.body.json()["error"]["message"]
        )

        # Test corrupted endorsements
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": corrupt_value(reference_quote["endorsements"]),
                "uvm_endorsements": reference_quote["uvm_endorsements"],
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

        # Test too short a uvm endorsement
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"][:-10],
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

        # Test too long a uvm endorsement
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": reference_quote["uvm_endorsements"] + "1",
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

        # Test corrupted uvm endorsements
        r = c.post(
            "/app/verifySnpAttestation",
            {
                "evidence": reference_quote["raw"],
                "endorsements": reference_quote["endorsements"],
                "uvm_endorsements": corrupt_value(reference_quote["uvm_endorsements"]),
            },
        )
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

        if infra.platform_detection.is_snp():
            LOG.info("Test primary's attestation is verifiable")

            r = c.get("/node/quotes/self")
            primary_quote_info = r.body.json()

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

        validate_openapi(c)
        generate_and_verify_jwk(c)

    return network
