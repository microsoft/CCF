# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import ccf.proposal_generator
import json

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)


@reqs.description("Add and remove CA certs")
def test_cert_store(network, args):
    primary, _ = network.find_nodes()

    cert_name = "mycert"
    raw_cert_name = cert_name.encode()

    LOG.info("Member builds a ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("foo")
        f.flush()
        try:
            ccf.proposal_generator.set_ca_cert_bundle(cert_name, f.name)
        except ValueError:
            pass
        else:
            assert False, "set_ca_cert_bundle should have raised an error"

    LOG.info("Member makes a ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("foo")
        f.flush()
        try:
            network.consortium.set_ca_cert_bundle(
                primary, cert_name, f.name, skip_checks=True
            )
        except (infra.proposal.ProposalNotAccepted, infra.proposal.ProposalNotCreated):
            pass
        else:
            assert False, "Proposal should not have been accepted"

    LOG.info("Member makes a ca cert update proposal with valid certs")
    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem)
    key2_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert2_pem = infra.crypto.generate_cert(key2_priv_pem)
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as cert_pem_fp:
        cert_pem_fp.write(cert_pem)
        cert_pem_fp.write(cert2_pem)
        cert_pem_fp.flush()
        set_proposal = network.consortium.set_ca_cert_bundle(
            primary, cert_name, cert_pem_fp.name
        )

        stored_cert = json.loads(
            network.get_ledger_public_state_at(set_proposal.completed_seqno)[
                "public:ccf.gov.tls.ca_cert_bundles"
            ][raw_cert_name]
        )
        cert_ref = cert_pem + cert2_pem
        assert (
            cert_ref == stored_cert
        ), f"input certs not equal to stored cert: {cert_ref} != {stored_cert}"

    LOG.info("Member removes a ca cert")
    remove_proposal = network.consortium.remove_ca_cert_bundle(primary, cert_name)

    assert (
        network.get_ledger_public_state_at(remove_proposal.completed_seqno)[
            "public:ccf.gov.tls.ca_cert_bundles"
        ][raw_cert_name]
        == None
    ), "CA bundle was not removed"

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.consensus,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        network = test_cert_store(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
