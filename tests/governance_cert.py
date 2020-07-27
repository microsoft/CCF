# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import subprocess
import base64
import tempfile
import infra.network
import infra.path
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args
from infra.proposal import ProposalState
import suite.test_requirements as reqs
import infra.logging_app as app
import ccf.proposal_generator

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)

@reqs.description("Add certificate with quote, query, update")
#@reqs.supports_methods("log/private")
def test_cert_store(network, args, notifications_queue=None, verify=True):
    # Test 2:
    # Propose a cert update with valid cert but mismatching mrsigner
    # Check that proposal gets rejected

    # Test 3:
    # Propose a cert update with valid cert and matching mrsigner
    # Check that proposal gets accepted
    # Check that cert can be queried and matches the input

    primary, _ = network.find_nodes()

    LOG.info("Member builds a root ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('foo')
        try:
            proposal_body, _ = ccf.proposal_generator.update_root_ca_cert("mycert", f.name)
        except ValueError:
            pass
        else:
            assert False, "update_root_ca_cert should have raised an error"

    LOG.info("Member makes a root ca cert update proposal with malformed cert")
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('foo')
        proposal_body, _ = ccf.proposal_generator.update_root_ca_cert("mycert", f.name, skip_checks=True)
        try:
            proposal = network.consortium.get_any_active_member().propose(primary, proposal_body)
        except infra.proposal.ProposalNotCreated:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Member makes a root ca cert update proposal with valid cert")
    ca_cert_path = os.path.join(this_dir, 'attested_cert.pem')
    proposal_body, _ = ccf.proposal_generator.update_root_ca_cert("mycert", ca_cert_path)
    proposal = network.consortium.get_any_active_member().propose(primary, proposal_body)
    assert proposal.state == ProposalState.Accepted
    
    #txs = app.LoggingTxs(notifications_queue=notifications_queue, user_id=3)
    
    with primary.client() as c:
        pass
        #r = c.get("/app/log/private")
        #assert r.status == 403
    return network

def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "pbft" else 2)

    with infra.notification.notification_server(args.notify_server) as notifications:
        # Lua apps do not support notifications
        # https://github.com/microsoft/CCF/issues/415
        notifications_queue = (
            notifications.get_queue()
            if (args.package == "liblogging" and args.consensus == "raft")
            else None
        )

        with infra.network.network(
            hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            network.start_and_join(args)
            network = test_cert_store(network, args, notifications_queue)


if __name__ == "__main__":

    def add(parser):
        pass

    # temporary hack...
    for i, arg in enumerate(sys.argv):
        if 'gov.lua' in arg:
            sys.argv[i] = arg.replace('gov.lua', 'gov_certs.lua')

    args = infra.e2e_args.cli_args(add=add)

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )

    args.package = "liblogging"
    run(args)
