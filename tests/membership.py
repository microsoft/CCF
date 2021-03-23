# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http

import infra.e2e_args
import infra.network
import infra.consortium
import random

import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Add and activate a new member to the consortium")
def test_add_member(network, args, recovery_member=True):
    primary, _ = network.find_primary()

    member_data = {
        "example": "of",
        "structured": ["and", {"nested": "arbitrary data"}],
    }

    new_member = network.consortium.generate_and_add_new_member(
        primary,
        curve=infra.network.ParticipantsCurve(args.participants_curve).next(),
        member_data=member_data,
        recovery_member=recovery_member,
    )

    r = new_member.ack(primary)
    with primary.client() as nc:
        nc.wait_for_commit(r)

    return network


@reqs.description("Retire existing member")
@reqs.sufficient_recovery_member_count()
def test_remove_member(network, args, member_to_remove=None, recovery_member=True):
    primary, _ = network.find_primary()
    if member_to_remove is None:
        member_to_remove = network.consortium.get_any_active_member(recovery_member)
    network.consortium.remove_member(primary, member_to_remove)

    # Check that remove member cannot be authenticated by the service
    try:
        member_to_remove.ack(primary)
    except infra.member.UnauthenticatedMember:
        pass
    else:
        assert False, "Member should have been removed"

    return network


@reqs.description("Issue new recovery shares (without re-key)")
def test_update_recovery_shares(network, args):
    primary, _ = network.find_primary()
    network.consortium.update_recovery_shares(primary)
    return network


@reqs.description("Set recovery threshold")
def test_set_recovery_threshold(network, args, recovery_threshold=None):
    if recovery_threshold is None:
        # If the recovery threshold is not specified, a new threshold is
        # randomly selected based on the number of active recovery members.
        # The new recovery threshold is guaranteed to be different from the
        # previous one.
        list_recovery_threshold = list(
            range(1, len(network.consortium.get_active_recovery_members()) + 1)
        )
        list_recovery_threshold.remove(network.consortium.recovery_threshold)
        recovery_threshold = random.choice(list_recovery_threshold)

    primary, _ = network.find_primary()
    network.consortium.set_recovery_threshold(primary, recovery_threshold)
    return network


def assert_recovery_shares_update(are_shared_updated, func, network, args, **kwargs):
    primary, _ = network.find_primary()

    saved_recovery_shares = {}
    for m in network.consortium.get_active_recovery_members():
        saved_recovery_shares[m] = m.get_and_decrypt_recovery_share(primary)

    if func is test_remove_member:
        recovery_member = kwargs.pop("recovery_member")
        member_to_remove = network.consortium.get_any_active_member(
            recovery_member=recovery_member
        )
        if recovery_member:
            saved_recovery_shares.pop(member_to_remove)

        func(network, args, member_to_remove)
    elif func is test_set_recovery_threshold and "recovery_threshold" in kwargs:
        func(network, args, recovery_threshold=kwargs["recovery_threshold"])
    else:
        func(network, args, **kwargs)

    for m, share_before in saved_recovery_shares.items():
        if are_shared_updated:
            assert share_before != m.get_and_decrypt_recovery_share(primary)
        else:
            assert share_before == m.get_and_decrypt_recovery_share(primary)


def service_startups(args):
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


def recovery_shares_scenario(args):
    # Members 0 and 1 are recovery members, member 2 isn't
    args.initial_member_count = 3
    args.initial_recovery_member_count = 2
    non_recovery_member_id = "member2"

    # Recovery threshold is initially set to number of recovery members (2)
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        # Membership changes trigger re-sharing and re-keying and are
        # only supported with CFT
        if args.consensus != "cft":
            LOG.warning("Skipping test recovery threshold as consensus is not CFT")
            return

        LOG.info("Update recovery shares")
        assert_recovery_shares_update(True, test_update_recovery_shares, network, args)

        LOG.info("Non-recovery member does not have a recovery share")
        primary, _ = network.find_primary()
        with primary.client(non_recovery_member_id) as mc:
            r = mc.get("/gov/recovery_share")
            assert r.status_code == http.HTTPStatus.NOT_FOUND.value
            assert (
                f"Recovery share not found for member {network.consortium.get_member_by_local_id(non_recovery_member_id).service_id}"
                in r.body.json()["error"]["message"]
            )

        # Removing a recovery number is not possible as the number of recovery
        # members would be under recovery threshold (2)
        LOG.info("Removing a recovery member should not be possible")
        try:
            test_remove_member(network, args, recovery_member=True)
            assert False, "Removing a recovery member should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            assert e.proposal.state == infra.proposal.ProposalState.FAILED

        # However, removing a non-recovery member is allowed
        LOG.info("Removing a non-recovery member is still possible")
        member_to_remove = network.consortium.get_member_by_local_id(
            non_recovery_member_id
        )
        test_remove_member(network, args, member_to_remove=member_to_remove)

        LOG.info("Removing an already-removed member succeeds with no effect")
        test_remove_member(network, args, member_to_remove=member_to_remove)

        LOG.info("Adding one non-recovery member")
        assert_recovery_shares_update(
            False, test_add_member, network, args, recovery_member=False
        )
        LOG.info("Adding one recovery member")
        assert_recovery_shares_update(
            True, test_add_member, network, args, recovery_member=True
        )
        LOG.info("Removing one non-recovery member")
        assert_recovery_shares_update(
            False, test_remove_member, network, args, recovery_member=False
        )
        LOG.info("Removing one recovery member")
        assert_recovery_shares_update(
            True, test_remove_member, network, args, recovery_member=True
        )

        LOG.info("Reduce recovery threshold")
        assert_recovery_shares_update(
            True,
            test_set_recovery_threshold,
            network,
            args,
            recovery_threshold=network.consortium.recovery_threshold - 1,
        )

        # Removing a recovery member now succeeds
        LOG.info("Removing one recovery member")
        assert_recovery_shares_update(
            True, test_remove_member, network, args, recovery_member=True
        )

        LOG.info("Set recovery threshold to 0 is impossible")
        try:
            test_set_recovery_threshold(network, args, recovery_threshold=0)
            assert False, "Setting recovery threshold to 0 should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            assert e.proposal.state == infra.proposal.ProposalState.FAILED

        LOG.info(
            "Set recovery threshold to more that number of active recovery members is impossible"
        )
        try:
            test_set_recovery_threshold(
                network,
                args,
                recovery_threshold=len(network.consortium.get_active_recovery_members())
                + 1,
            )
            assert (
                False
            ), "Setting recovery threshold to more than number of active recovery members should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            assert e.proposal.state == infra.proposal.ProposalState.FAILED

        LOG.info(
            "Setting recovery threshold to current threshold does not update shares"
        )
        assert_recovery_shares_update(
            False,
            test_set_recovery_threshold,
            network,
            args,
            recovery_threshold=network.consortium.recovery_threshold,
        )


def run(args):
    service_startups(args)
    recovery_shares_scenario(args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    # Fast test
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    args.initial_user_count = 0
    run(args)
