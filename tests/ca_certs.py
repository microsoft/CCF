# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
import http
from cryptography import x509
import cryptography.hazmat.backends as crypto_backends
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import ccf.proposal_generator

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)


@reqs.description("Add and remove CA certs")
def test_cert_store(network, args):
    primary, _ = network.find_nodes()

    cert_name = "mycert"

    LOG.info("Member builds a ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("foo")
        f.flush()
        try:
            ccf.proposal_generator.set_ca_cert(cert_name, f.name)
        except ValueError:
            pass
        else:
            assert False, "set_ca_cert should have raised an error"

    LOG.info("Member makes a ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("foo")
        f.flush()
        try:
            network.consortium.set_ca_cert(primary, cert_name, f.name, skip_checks=True)
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been accepted"

    LOG.info("Member makes a ca cert update proposal with valid cert")
    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem)
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as cert_pem_fp:
        cert_pem_fp.write(cert_pem)
        cert_pem_fp.flush()
        network.consortium.set_ca_cert(primary, cert_name, cert_pem_fp.name)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt.ca_certs_der", "key": cert_name}
        )
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        cert_ref = x509.load_pem_x509_certificate(
            cert_pem.encode(), crypto_backends.default_backend()
        )
        cert_kv = x509.load_der_x509_certificate(
            # Note that /gov/read returns all data as JSON.
            # Here, the stored data is a uint8 array, therefore it
            # is returned as an array of integers.
            bytes(r.body.json()),
            crypto_backends.default_backend(),
        )
        assert (
            cert_ref == cert_kv
        ), f"stored cert not equal to input cert: {cert_ref} != {cert_kv}"

    LOG.info("Member removes a ca cert")
    network.consortium.remove_ca_cert(primary, cert_name)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt.ca_certs_der", "key": cert_name}
        )
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_cert_store(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
