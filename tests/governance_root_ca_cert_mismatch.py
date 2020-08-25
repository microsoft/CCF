# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
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


@reqs.description("Add certificate with mismatching MRSIGNER")
def test_cert_mrsigner_mismatch(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member makes a root ca cert update proposal with mismatching MRSIGNER")
    ca_cert_path = os.path.join(this_dir, "maa_root_ca_cert.pem")
    proposal_body, _ = ccf.proposal_generator.update_root_ca_cert(
        "mycert", ca_cert_path
    )
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    assert proposal.state == ProposalState.Rejected

    return network


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "pbft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_cert_mrsigner_mismatch(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    run(args)
