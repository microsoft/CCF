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
            "endorsements": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZURENDQXZ1Z0F3SUJBZ0lCQURCR0Jna3Foa2lHOXcwQkFRb3dPYUFQTUEwR0NXQ0dTQUZsQXdRQ0FnVUEKb1J3d0dnWUpLb1pJaHZjTkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVENqQXdJQkFUQjdNUlF3RWdZRApWUVFMREF0RmJtZHBibVZsY21sdVp6RUxNQWtHQTFVRUJoTUNWVk14RkRBU0JnTlZCQWNNQzFOaGJuUmhJRU5zCllYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqWldRZ1RXbGpjbThnUkdWMmFXTmwKY3pFU01CQUdBMVVFQXd3SlUwVldMVTFwYkdGdU1CNFhEVEl6TURFeE5URTBNRGt6T1ZvWERUTXdNREV4TlRFMApNRGt6T1Zvd2VqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4Q3pBSkJnTlZCQVlUQWxWVE1SUXdFZ1lEClZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhIekFkQmdOVkJBb01Ga0ZrZG1GdVkyVmsKSUUxcFkzSnZJRVJsZG1salpYTXhFVEFQQmdOVkJBTU1DRk5GVmkxV1EwVkxNSFl3RUFZSEtvWkl6ajBDQVFZRgpLNEVFQUNJRFlnQUVZdElnNUQ2dlErajljQVRPYkd1dkhGa1lqU05ma3JLNXJIWHJUdEJUTnJXMjhDMkFxTFJsCkZpRDcrT0daRTJxa3UyVFVtUlM5cHhxbUNKM2pGK0NDMXZGOXg2UmF5dXVqVnA4Z0VGTWwzU0cvaFZwZjJCZzMKaWorYVFiZUhqUHgrbzRJQkZqQ0NBUkl3RUFZSkt3WUJCQUdjZUFFQkJBTUNBUUF3RndZSkt3WUJCQUdjZUFFQwpCQW9XQ0UxcGJHRnVMVUl3TUJFR0Npc0dBUVFCbkhnQkF3RUVBd0lCQXpBUkJnb3JCZ0VFQVp4NEFRTUNCQU1DCkFRQXdFUVlLS3dZQkJBR2NlQUVEQkFRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdVRUF3SUJBREFSQmdvckJnRUUKQVp4NEFRTUdCQU1DQVFBd0VRWUtLd1lCQkFHY2VBRURCd1FEQWdFQU1CRUdDaXNHQVFRQm5IZ0JBd01FQXdJQgpDREFSQmdvckJnRUVBWng0QVFNSUJBTUNBWE13VFFZSkt3WUJCQUdjZUFFRUJFRGNmamZNbTVXMDBITHNURzY4CnErcjVpbVpWc3VhU2RvK2V0NTRQNGZxZGJIQ3gwS0pSZFgzTlNMTmcxbUQ0bTc4aWp2bjVrQU1CVEcxVFNtZ1UKYytvSE1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQgpBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFBRUt1YUtlQnVKL21EZDhFcWRxcHFQCnVyY0JtYUhmVmRaZGhrU0lCMWxmaytoZVNLU1UvWVBUemt0M0NxK0R5UkFHanRoSFMwTktWcUh0dGZXSmszL3gKbEFkYTJvdFdDQ1VXR2tyamhRdE9vekVuclJpV1RabEpuQjZJZGtFcVphTkFDUFNJQ0tuOE5ZWW1mU3FNOUd6bApWbFFwNzBJZlZKKy9xQXV3ZXJRUFNGaC9BUys4K1JTQmtiMVVaUGdkNTFiS25rSDB4L0ZBSjBsQWdocWxSTDNyCkttczZsMW5hS1pNQWxVY1lXQ0h0UjlOdnh2SnVkNTR4S0d5UWhHSU1jKzJiUXYxVnJYK1hkZHJORmJZc2V2c3UKV0FYdVhidytMVnZFR3RXL2lKY1ZXb1d1NXk1eWZWYXRWQ2kySFprREpGaTcweEQxZkhkUGU1WWlYQ3ZLdW9OWQp5Q2YrS2I5RUxGMjJnd09ybFJaSDZDcHJ2dkVMaThaV1l3dTRWZHpkYkdnUkFybnlQWGVCS0luUGJCZys4dmlVCkV6TGlaSmRVWTNxMnNzM0VUN0s3ais0dWlWOU5NV2FqYzB2aTAxSnNBSVNNUEJqVmZtNmhSTmM4cExZKzBnNEQKMkJ5SmhnOVZEVkMvMzhBcnRtRWVxQWd4VnZNZW9Kbzhac0hDUTJDY2o3dmlueGJobXg0cnV4L3I1dEN4ekJZUQpOVEErczYvbHozRWdnTHZIa3FKSHYvSFVjbkpDWWlwbHVWMHZYdm5rVUNoTElYZzNzQjNzRmpFNFlZdmkrYkc5CkNIc2lqRGpOT2JpemNHNy8vQVppWlJ3MStRRStuTkNGaXpHc1A3VU10M1NmQ1FHQm9QRVFWS29waTBUdlJDeDcKcUpSYmRVME4zcjJ3WWRBdGkrb0d2QT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdpVENDQkRpZ0F3SUJBZ0lEQVFBQk1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNOTWpBeE1ESXlNVGd5TkRJd1doY05ORFV4TURJeQpNVGd5TkRJd1dqQjdNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldRZ1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKVTBWV0xVMXBiR0Z1TUlJQ0lqQU5CZ2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBblUyZHJyTlRmYmhOUUlsbGYrVzJ5K1JPQ2JTeklkMWFLWmZ0CjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05UY0IwVllYdDNKeFpTek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXcKS1pYMEptUUV1WWptK1dLa3NMdHhnZExwOUU3RVpOd05EcVYxcjBxUlA1dEI4T1dreVFiSWRMZXU0YUN6N2ovUwpsMUZrQnl0ZXY5c2JGR3p0N2N3bmp6aTltN25vcXNrK3VSVkJwMytJbjM1UVBkY2o4WWZsRW1uSEJOdnVVREpoCkxDSk1XOEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pUTThLc05iVXgzQThlazVFVkwKalpXSDFwdDlFM1RmcFI2WHlmUUtuWTZrbDVhRUlQd2RXM2VGWWFxQ0ZQcklvOXBRVDZXdURTUDRKQ1lKYlpuZQpLS0liWmp6WGtKdDNOUUczMkV1a1lJbUJiOVNDa205K2ZTNUxaRmc5b2p6dWJNWDMrTmtCb1NYSTdPUHZuSE14Cmp1cDltdzVzZTZRVVY3R3FwQ0EyVE55cG9sbXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGwKQWxKdzVEMENUUlRDMVk1WVdGREJDckEvdkdubVRucUc4QytqalVBUzdjampSOHE0T1BoeURtSlJQbmFDL1pHNQp1UDBLMHo2R29PLzN1ZW45d3FzaEN1SGVnTFRwT2VIRUpSS3JRRnI0UFZJd1ZPQjArZWJPNUZnb3lPdzQzbnlGCkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FSSXMxRW9xRWptRjhVdHJtUVdWMmhVand6cXd2SEYKZWk4clB4TUNBd0VBQWFPQm96Q0JvREFkQmdOVkhRNEVGZ1FVTzhadUdDckQvVDFpWkVpYjQ3ZEhMTFQ4di9ndwpId1lEVlIwakJCZ3dGb0FVaGF3YTBVUDN5S3hWMU1VZFFVaXIxWGhLMUZNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCCi93SUJBREFPQmdOVkhROEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIwY0hNNkx5OXIKWkhOcGJuUm1MbUZ0WkM1amIyMHZkbU5sYXk5Mk1TOU5hV3hoYmk5amNtd3dSZ1lKS29aSWh2Y05BUUVLTURtZwpEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTkJnbGdoa2dCWlFNRUFnSUZBS0lECkFnRXdvd01DQVFFRGdnSUJBSWdlVVFTY0FmM2xEWXFnV1UxVnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEUKUEkxamgzZ0piTHhMNmdmM0s4anhjdHpPV25rWWNiZGZNT09yMjhLVDM1SWFBUjIwcmVrS1JGcHRUSGhlK0RGcgozQUZ6WkxERDdjV0syOS9HcFBpdFBKREtDdkk3QTRVZzA2cms3SjB6QmUxZnovcWU0aTIvRjEycnZmd0NHWWhjClJ4UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpNa3Q3REZ2S1JoKzJ6Sys1cGxWR0cKRnNqREp0TXoydWQ5eTBwdk9FNGozZEg1SVc5akd4YVNHU3RxTnJhYm5ucEYyMzZFVHIxL2E0M2I4RkZLTDVRTgptdDhWcjl4blhScHpucUNSdnFqcitrVnJiNmRsZnVUbGxpWGVRVE1sQm9SV0ZKT1JMOEFjQkp4R1o0SzJtWGZ0CmwxalU1VExlaDVLWEw5Tlc3YS9xQU9JVXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnIKRWc2emt4bXZNdWFiWk9zZEtmUmtXZmhIMlpLY1RsRGZtSDFIMHpxMFEyYkczdXZhVmRpQ3RGWTFMbFd5QjM4SgpTMmZOc1IvUHk2dDVickVKQ0ZOdnphRGt5NktlQzRpb24vY1ZnVWFpN3p6UzNiR1FXektES1UzNVNxTlUyV2tQCkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBlMDF6RDBOOGF0RnhtV2lTbmZKbDY5MEI5ckpwTlIvZkkKYWp4Q1czU2Vpd3M2cjFabSt0Q3VWYk1pTnRwUzlUaGpOWDR1dmU1dGh5ZkUyRGdveFJGdlkxQ3NvRjVNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdZekNDQkJLZ0F3SUJBZ0lEQVFBQU1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNOTWpBeE1ESXlNVGN5TXpBMVdoY05ORFV4TURJeQpNVGN5TXpBMVdqQjdNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldRZ1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKUVZKTExVMXBiR0Z1TUlJQ0lqQU5CZ2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJSSk9kZWlKbHFLMkpkc1ZtRDdGa3R1b3RXd1gxZk5nClc0MVhZOVh6MUhFaFNVbWhMejlDdTlESFJsdmdKU054YmVZWXNuSmZ2eWp4MU1mVTBWNXRrS2lVMUVlc05GdGEKMWtUQTBzek5pc2RZYzlpc3FrN21YVDUrS2ZHUmJmYzRWLzl6UkljRThqbEhONjFTMWp1OFg5Mys2ZHhEVXJHMgpTenhxSjRCaHF5WW1VRHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0yQitPK3Zqc0MwCjYwZDM3alk5TEZldU9QNE1lcmk4cWdmaTJTNWtLcWcvYUY2YVB0dUFaUVZSN3UzS0ZZWFA1OVhtSmd0Y29nMDUKZ21JMFQvT2l0TGh1elZ2cFpjTHBoMG9kaC8xSVBYcXgzK01uakQ5N0E3ZlhwcUdkL3k4S3hYN2prc1RFekFPZwpiS0FlYW0zbG0rM3lLSWNUWU1sc1JNWFBjak5iSXZtc0J5a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzCitnVkRrdVZQaHNueklSTmdZdk00OFkrN0xHaUpZbnJtRTh4Y3JleGVrQnhydmEyVjlUSlFxbk4zUTUza3Q1dmkKUWkzK2dDZm1rd0MwRjB0aXJJWmJMa1hQclB3elowTTllTnhoSXlTYjJucEpmZ25xejU1STB1MzN3aDRyMFpOUQplVEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBDcTcrT2dwQ0NvTU5pdDJ1TG85TTE4CmZIejEwbE9NVDhuV0FVdlJaRnp0ZVhDbSs3UEhkWVBsbVF3VXczTHZlbkovSUxYb1FQSGZia0gwQ3lQZmhsMWoKV2hKRlphc0NBd0VBQWFOK01Id3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CMEdBMVVkRGdRV0JCU0ZyQnJSUS9mSQpyRlhVeFIxQlNLdlZlRXJVVXpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VHCktXaDBkSEJ6T2k4dmEyUnphVzUwWmk1aGJXUXVZMjl0TDNaalpXc3ZkakV2VFdsc1lXNHZZM0pzTUVZR0NTcUcKU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQkFRZ3dEUVlKWUlaSQpBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDNm0wa0RwNnp2NE9qZmd5K3psZWVoc3g2b2wwb2NnVmVsCkVUb2JweCtFdUNzcVZGUlBLMWpaMXNwL2x5ZDkrMGZRMHI2Nm43a2FnUms0Q2EzOWc2NldHVEpNZUpkcVlyaXcKU1RqakRDS1ZQU2VzV1hZUFZBeURobVA1bjJ2K0JZaXBaV2hwdnFwYWlPK0VHSzVJQlArNTc4UWVXL3NTb2tySwpkSGFMQXhHMkxoWnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dTZ2tEZ3V0Q1RCMVlxCnpUNUR1d3ZBZStjbzJDSVZJek1EYW1ZdVNGalBOMEJDZ29qbDdWK2JUb3U3ZE1zcUl1L1RXL3JQQ1g5L0VVY3AKS0dLcVBRM1ArTjlyMWhqRUZZMXBsQmc5M3Q1M09PbzQ5R05JK1YxenZYUExJNnhJRlZzaCttdG8yUnRnRVgvZQpwbU1LVE5ONnBzVzg4cWc3YzFoVFd0TjZNYlJ1UTB2bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxCkhuSVloeHkwWUtYR3lhVzFOamZVTHhycm14Vlc0d2NuNUU4R2RkbXZOYTZ5WW04c2NKYWdFaTEzbWhHdTRKcWgKM1FVM3NmOGlVU1VyMDl4UUR3SHRPUVVWSXF4NG1hQlpQQnRTTWYrcVVEdGpYU1NxOGxmV2NkOGJMcjltZHNVbgpKWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2VzFVbXEyNWJveENZSitUdUJvYTRzK0hICkNWaUF2Z1Q5a2YvckJxMWQraXZqNnNra0h4dXpjeGJrMXh2NlpHeHJ0ZUp4Vkg3S2xYN1lSZFo2ZUFSS3dMZTQKQUZaRUF3b0tDUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
            "format": "AMD_SEV_SNP_v1",
            "raw": "AgAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAAAI0gEAAAAAAAAAAAAAAAAAAAB6amjAorhbiq4AygT2RIMWgCIvRBZ+VVip4HK3DGDpWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsOw1b8dJW+k47Xe78B7Vf8vcCkIXtNQ9glZFAoaUfExB1O6WrLAOgU2scDBk69HT0RIxn88jfyN6KXjcSXYB9rcxB8GzyP2FdvVLux3fRCBLO9VZ+eO/KBz/eiJSxgOqu87VghAkMZHgrWtU2vPED0ZSRSyKcqsXFQIr86R/IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABzAj353ZqUJOyLyHZA6jlk0VTLQabX3fKVGE5McBPVvf//////////////////////////////////////////AwAAAAAACHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADcfjfMm5W00HLsTG68q+r5imZVsuaSdo+et54P4fqdbHCx0KJRdX3NSLNg1mD4m78ijvn5kAMBTG1TSmgUc+oHAwAAAAAACHMENAEABDQBAAMAAAAAAAhzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUTPbGEK/BTYf/zNGKj++WA/kuhpuFXG3YCJSasBKgH0Iqmie5LAQK2Cl7UpndpfjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT+ra0aakz2J5YHK5YngV26JnoUbgmFos83epi2rQsWA8pSo+Pd1wxxFxluOkZdcYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
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
            == "02c3b0d5bf1d256fa4e3b5deefc07b55ff2f7029085ed350f60959140a1a51f1310753ba5ab2c03a0536b1c0c193af47"
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
