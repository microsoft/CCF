# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
from cryptography import x509
import cryptography.hazmat.backends as crypto_backends
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
from infra.proposal import ProposalState
import suite.test_requirements as reqs
import ccf.proposal_generator

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)


@reqs.description("Add certificate with quote, query, update")
def test_cert_store(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member builds a ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("foo")
        f.flush()
        try:
            proposal_body, _ = ccf.proposal_generator.update_ca_cert("mycert", f.name)
        except ValueError:
            pass
        else:
            assert False, "update_ca_cert should have raised an error"

    LOG.info("Member makes a ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("foo")
        f.flush()
        proposal_body, _ = ccf.proposal_generator.update_ca_cert(
            "mycert", f.name, skip_checks=True
        )
        try:
            proposal = network.consortium.get_any_active_member().propose(
                primary, proposal_body
            )
        except infra.proposal.ProposalNotCreated:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Member makes a ca cert update proposal with valid cert")
    ca_cert_path = os.path.join(this_dir, "ca_cert.pem")
    proposal_body, _ = ccf.proposal_generator.update_ca_cert("mycert", ca_cert_path)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    assert proposal.state == ProposalState.Accepted

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "ccf.ca_cert_ders", "key": "mycert"})
        assert r.status_code == 200, r.status_code
        cert_pem_str = open(ca_cert_path).read()
        cert_ref = x509.load_pem_x509_certificate(
            cert_pem_str.encode(), crypto_backends.default_backend()
        )
        cert_kv = x509.load_der_x509_certificate(
            r.body.data(), crypto_backends.default_backend()
        )
        assert (
            cert_ref == cert_kv
        ), f"stored cert not equal to input cert: {cert_ref} != {cert_kv}"

    return network


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "bft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_cert_store(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    run(args)
