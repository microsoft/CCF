# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
import json
import base64
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
from infra.proposal import ProposalState
import suite.test_requirements as reqs

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)


def create_jwks(kid, cert_pem, test_invalid_is_key=False):
    der_b64 = base64.b64encode(
        infra.crypto.cert_pem_to_der(cert_pem)
        if not test_invalid_is_key
        else infra.crypto.pub_key_pem_to_der(cert_pem)
    ).decode("ascii")
    return {"keys": [{"kty": "RSA", "kid": kid, "x5c": [der_b64]}]}


@reqs.description("JWT without key policy")
def test_jwt_without_key_policy(network, args):
    primary, _ = network.find_nodes()

    key_priv_pem, key_pub_pem = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem)
    kid = "my_kid"
    issuer = "my_issuer"

    LOG.info("Try to add JWT signing key without matching issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, cert_pem), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer, "validate_issuer": True}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add a public key instead of a certificate")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, key_pub_pem, test_invalid_is_key=True), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add JWT signing key with matching issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, cert_pem), jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(primary, issuer, jwks_fp.name)

    LOG.info("Check if JWT signing key was stored correctly")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt_public_signing_keys", "key": kid}
        )
        assert r.status_code == 200, r.status_code
        # Note that /gov/read returns all data as JSON.
        # Here, the stored data is a uint8 array, therefore it
        # is returned as an array of integers.
        cert_kv_der = bytes(r.body.json())
        cert_kv_pem = infra.crypto.cert_der_to_pem(cert_kv_der)
        assert infra.crypto.are_certs_equal(
            cert_pem, cert_kv_pem
        ), "stored cert not equal to input cert"

    LOG.info("Remove JWT issuer")
    network.consortium.remove_jwt_issuer(primary, issuer)

    LOG.info("Check if JWT signing key was deleted")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt_public_signing_keys", "key": kid}
        )
        assert r.status_code == 400, r.status_code

    LOG.info("Add JWT issuer with initial keys")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer, "jwks": create_jwks(kid, cert_pem)}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Check if JWT signing key was stored correctly")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt_public_signing_keys", "key": kid}
        )
        assert r.status_code == 200, r.status_code
        cert_kv_der = bytes(r.body.json())
        cert_kv_pem = infra.crypto.cert_der_to_pem(cert_kv_der)
        assert infra.crypto.are_certs_equal(
            cert_pem, cert_kv_pem
        ), "stored cert not equal to input cert"

    return network


@reqs.description("JWT with SGX key policy")
def test_jwt_with_sgx_key_policy(network, args):
    primary, _ = network.find_nodes()

    oe_cert_path = os.path.join(this_dir, "ca_cert.pem")
    with open(oe_cert_path) as f:
        oe_cert_pem = f.read()

    kid = "my_kid"
    issuer = "my_issuer"

    matching_key_policy = {
        "sgx_claims": {
            "signer_id": "ca9ad7331448980aa28890ce73e433638377f179ab4456b2fe237193193a8d0a",
            "attributes": "0300000000000000",
        }
    }

    mismatching_key_policy = {
        "sgx_claims": {
            "signer_id": "da9ad7331448980aa28890ce73e433638377f179ab4456b2fe237193193a8d0a",
            "attributes": "0300000000000000",
        }
    }

    LOG.info("Add JWT issuer with SGX key policy")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer, "key_policy": matching_key_policy}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add a non-OE-attested cert")
    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    non_oe_cert_pem = infra.crypto.generate_cert(key_priv_pem)
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, non_oe_cert_pem), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add an OE-attested cert with matching claims")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, oe_cert_pem), jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(primary, issuer, jwks_fp.name)

    LOG.info("Update JWT issuer with mismatching SGX key policy")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {
                "issuer": issuer,
                "validate_issuer": True,
                "key_policy": mismatching_key_policy,
            },
            metadata_fp,
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add an OE-attested cert with mismatching claims")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, non_oe_cert_pem), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    return network


@reqs.description("JWT with SGX key filter")
def test_jwt_with_sgx_key_filter(network, args):
    primary, _ = network.find_nodes()

    oe_cert_path = os.path.join(this_dir, "ca_cert.pem")
    with open(oe_cert_path) as f:
        oe_cert_pem = f.read()
    oe_kid = "oe_kid"

    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    non_oe_cert_pem = infra.crypto.generate_cert(key_priv_pem)
    non_oe_kid = "non_oe_kid"

    issuer = "my_issuer"

    LOG.info("Add JWT issuer with SGX key filter")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer, "key_filter": "sgx"}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Add multiple certs (1 SGX, 1 non-SGX)")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        oe_jwks = create_jwks(oe_kid, oe_cert_pem)
        non_oe_jwks = create_jwks(non_oe_kid, non_oe_cert_pem)
        jwks = {"keys": non_oe_jwks["keys"] + oe_jwks["keys"]}
        json.dump(jwks, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(primary, issuer, jwks_fp.name)

    LOG.info("Check that only SGX cert was added")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read",
            {"table": "public:ccf.gov.jwt_public_signing_keys", "key": non_oe_kid},
        )
        assert r.status_code == 400, r.status_code
        r = c.post(
            "/gov/read",
            {"table": "public:ccf.gov.jwt_public_signing_keys", "key": oe_kid},
        )
        assert r.status_code == 200, r.status_code

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_jwt_without_key_policy(network, args)
        network = test_jwt_with_sgx_key_policy(network, args)
        network = test_jwt_with_sgx_key_filter(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
