# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import infra.network
import infra.proposal

from loguru import logger as LOG


def run(args):

    LOG.info("Starting service with insufficient number of recovery members")
    args.initial_member_count = 2
    args.initial_recovery_member_count = 0
    args.initial_operator_count = 1
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        try:
            network.start_and_join(args)
            assert False, "Service cannot be opened with no recovery members"
        except infra.proposal.ProposalNotAccepted:
            LOG.success(
                "Service could not be opened with insufficient number of recovery mmebers"
            )
            pass

    LOG.info(
        "Starting service with a recovery operator member, a non-recovery operator member and a non-recovery non-operator member"
    )
    args.initial_member_count = 3
    args.initial_recovery_member_count = 1
    args.initial_operator_count = 2
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        network.start_and_join(args)

    LOG.info(
        "Starting service with a recovery operator member, a recovery non-operator member and a non-recovery non-operator member"
    )
    args.initial_member_count = 3
    args.initial_recovery_member_count = 2
    args.initial_operator_count = 1
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        network.start_and_join(args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    # For faster startup
    args.nodes = ["local://localhost"]
    args.initial_user_count = 0

    run(args)