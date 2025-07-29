# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.consortium
import random
from infra.runner import ConcurrentRunner
import memberclient
import infra.proposal
import infra.member

import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Add and activate a new member to the consortium")
def test_add_member(network, args, recovery_role=infra.member.RecoveryRole.Participant):
    primary, _ = network.find_primary()

    member_data = {
        "example": "of",
        "structured": ["and", {"nested": "arbitrary data"}],
    }

    new_member = network.consortium.generate_and_add_new_member(
        primary,
        curve=infra.network.EllipticCurve(args.participants_curve).next(),
        member_data=member_data,
        recovery_role=recovery_role,
    )

    r = new_member.ack(primary)
    with primary.client() as nc:
        nc.wait_for_commit(r)

    return network


@reqs.description("Retire existing member")
def test_remove_member_no_reqs(
    network,
    args,
    member_to_remove=None,
    recovery_role=infra.member.RecoveryRole.Participant,
):
    primary, _ = network.find_primary()
    if member_to_remove is None:
        member_to_remove = network.consortium.get_any_active_member(recovery_role)
    network.consortium.remove_member(primary, member_to_remove)

    # Check that remove member cannot be authenticated by the service
    try:
        member_to_remove.ack(primary)
    except infra.member.UnauthenticatedMember:
        pass
    else:
        assert False, "Member should have been removed"

    return network


# Called by test suite. membership test deliberately attempts to remove recovery member.
@reqs.sufficient_recovery_member_count()
def test_remove_member(
    network,
    args,
    member_to_remove=None,
    recovery_role=infra.member.RecoveryRole.Participant,
):
    return test_remove_member_no_reqs(network, args, member_to_remove, recovery_role)


@reqs.description("Issue new recovery shares (without re-key)")
def test_update_recovery_shares(network, args):
    primary, _ = network.find_primary()
    network.consortium.trigger_recovery_shares_refresh(primary)
    return network


@reqs.description("Set recovery threshold")
def test_set_recovery_threshold(network, args, recovery_threshold=None):
    if recovery_threshold is None:
        # If the recovery threshold is not specified, a new threshold is
        # randomly selected based on the number of active recovery members.
        # The new recovery threshold is guaranteed to be different from the
        # previous one.
        list_recovery_threshold = list(
            range(1, len(network.consortium.get_active_recovery_participants()) + 1)
        )
        list_recovery_threshold.remove(network.consortium.recovery_threshold)
        recovery_threshold = random.choice(list_recovery_threshold)

    primary, _ = network.find_primary()
    network.consortium.set_recovery_threshold(primary, recovery_threshold)
    return network


def assert_recovery_shares_update(are_shares_updated, func, network, args, **kwargs):
    primary, _ = network.find_primary()

    saved_recovery_member_shares = {}
    saved_recovery_owner_shares = {}
    for m in network.consortium.get_active_recovery_participants():
        saved_recovery_member_shares[m] = m.get_and_decrypt_recovery_share(primary)
    for m in network.consortium.get_active_recovery_owners():
        saved_recovery_owner_shares[m] = m.get_and_decrypt_recovery_share(primary)

    if func is test_remove_member:
        recovery_role = kwargs.pop("recovery_role")
        member_to_remove = network.consortium.get_any_active_member(
            recovery_role=recovery_role
        )
        if recovery_role == infra.member.RecoveryRole.Owner:
            saved_recovery_owner_shares.pop(member_to_remove)
        elif recovery_role == infra.member.RecoveryRole.Participant:
            saved_recovery_member_shares.pop(member_to_remove)

        func(network, args, member_to_remove, recovery_role)
    elif func is test_set_recovery_threshold and "recovery_threshold" in kwargs:
        func(network, args, recovery_threshold=kwargs["recovery_threshold"])
    else:
        func(network, args, **kwargs)

    for m, share_before in saved_recovery_member_shares.items():
        if are_shares_updated:
            assert share_before != m.get_and_decrypt_recovery_share(primary)
        else:
            assert share_before == m.get_and_decrypt_recovery_share(primary)

    for m, share_before in saved_recovery_owner_shares.items():
        if are_shares_updated:
            assert share_before != m.get_and_decrypt_recovery_share(primary)
        else:
            assert share_before == m.get_and_decrypt_recovery_share(primary)


def service_startups(args):
    LOG.info("Starting service with insufficient number of recovery members")
    args.initial_member_count = 2
    args.initial_recovery_participant_count = 0
    args.initial_recovery_owner_count = 0
    args.initial_operator_count = 1
    args.ledger_recovery_timeout = 5
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        try:
            network.start_and_open(args)
            assert False, "Service cannot be opened with no recovery members"
        except infra.proposal.ProposalNotAccepted:
            primary, _ = network.find_primary()
            network.consortium.check_for_service(
                primary, infra.network.ServiceStatus.OPENING
            )
            LOG.success(
                "Service could not be opened with insufficient number of recovery members"
            )

    LOG.info(
        "Starting service with a recovery operator member, a non-recovery operator member and a non-recovery non-operator member"
    )
    args.initial_member_count = 3
    args.initial_recovery_participant_count = 1
    args.initial_recovery_owner_count = 0
    args.initial_operator_count = 2
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        network.start_and_open(args)

    LOG.info(
        "Starting service with a recovery operator member, a recovery non-operator member, a non-recovery non-operator member and a recovery owner member"
    )
    args.initial_member_count = 4
    args.initial_recovery_participant_count = 2
    args.initial_recovery_owner_count = 1
    args.initial_operator_count = 1
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        network.start_and_open(args)

    LOG.info("Starting service with a recovery member number of recovery members")
    args.initial_member_count = 2
    args.initial_recovery_participant_count = 0
    args.initial_recovery_owner_count = 0
    args.initial_operator_count = 1
    args.ledger_recovery_timeout = 5
    with infra.network.network(args.nodes, args.binary_dir, pdb=args.pdb) as network:
        try:
            network.start_and_open(args)
            assert False, "Service cannot be opened with no recovery members"
        except infra.proposal.ProposalNotAccepted:
            primary, _ = network.find_primary()
            network.consortium.check_for_service(
                primary, infra.network.ServiceStatus.OPENING
            )
            LOG.success(
                "Service could not be opened with insufficient number of recovery members"
            )


def recovery_shares_scenario(args):
    # Members 0 and 1 are recovery members, member 2 isn't
    args.initial_member_count = 3
    args.initial_recovery_participant_count = 2
    args.initial_recovery_owner_count = 0
    non_recovery_member_id = "member2"

    # Recovery threshold is initially set to number of recovery members (2)
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        LOG.info("Update recovery shares")
        assert_recovery_shares_update(True, test_update_recovery_shares, network, args)

        LOG.info("Non-recovery member does not have a recovery share")
        primary, _ = network.find_primary()
        member = network.consortium.get_member_by_local_id(non_recovery_member_id)
        try:
            member.get_and_decrypt_recovery_share(primary)
            assert False, "Expected a NoRecoveryShare exception to be thrown"
        except infra.member.NoRecoveryShareFound as e:
            r = e.response
            body = r.body.json()
            assert (
                f"Recovery share not found for member m[{member.service_id}]"
                in body["error"]["message"]
            ), body["error"]

        # Removing a recovery number is not possible as the number of recovery
        # members would be under recovery threshold (2)
        LOG.info("Removing a recovery member should not be possible")
        try:
            test_remove_member_no_reqs(
                network, args, recovery_role=infra.member.RecoveryRole.Participant
            )
            assert False, "Removing a recovery member should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            # This is an apply() time failure, so the proposal remains Open
            # since the last vote is effectively discarded
            assert e.proposal.state == infra.proposal.ProposalState.OPEN

        # However, removing a non-recovery member is allowed
        LOG.info("Removing a non-recovery member is still possible")
        member_to_remove = network.consortium.get_member_by_local_id(
            non_recovery_member_id
        )
        test_remove_member(
            network,
            args,
            member_to_remove=member_to_remove,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )

        LOG.info("Removing an already-removed member succeeds with no effect")
        test_remove_member(
            network,
            args,
            member_to_remove=member_to_remove,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )

        LOG.info("Adding one non-recovery member")
        assert_recovery_shares_update(
            False,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )
        LOG.info("Adding one recovery member")
        assert_recovery_shares_update(
            True,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )
        LOG.info("Adding one recovery owner")
        assert_recovery_shares_update(
            True,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Owner,
        )
        LOG.info("Removing one non-recovery member")
        assert_recovery_shares_update(
            False,
            test_remove_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )
        LOG.info("Removing one recovery member")
        assert_recovery_shares_update(
            True,
            test_remove_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )
        LOG.info("Removing one recovery owner")
        assert_recovery_shares_update(
            True,
            test_remove_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Owner,
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
            True,
            test_remove_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )

        LOG.info("Set recovery threshold to 0 is impossible")
        exception = infra.proposal.ProposalNotCreated
        try:
            test_set_recovery_threshold(network, args, recovery_threshold=0)
            assert False, "Setting recovery threshold to 0 should not be possible"
        except exception as e:
            assert (
                e.response.status_code == 400
                and e.response.body.json()["error"]["code"]
                == "ProposalFailedToValidate"
            ), e.response.body.text()

        LOG.info(
            "Set recovery threshold to more that number of active recovery members is impossible"
        )
        try:
            test_set_recovery_threshold(
                network,
                args,
                recovery_threshold=len(
                    network.consortium.get_active_recovery_participants()
                )
                + 1,
            )
            assert (
                False
            ), "Setting recovery threshold to more than number of active recovery members should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            # This is an apply() time failure, so the proposal remains Open
            # since the last vote is effectively discarded
            assert e.proposal.state == infra.proposal.ProposalState.OPEN

        try:
            test_set_recovery_threshold(network, args, recovery_threshold=256)
            assert False, "Recovery threshold cannot be set to > 255"
        except exception as e:
            assert (
                e.response.status_code == 400
                and e.response.body.json()["error"]["code"]
                == "ProposalFailedToValidate"
            ), e.response.body.text()

        try:
            network.consortium.set_recovery_threshold(primary, recovery_threshold=None)
            assert False, "Recovery threshold value must be passed as proposal argument"
        except exception as e:
            assert (
                e.response.status_code == 400
                and e.response.body.json()["error"]["code"]
                == "ProposalFailedToValidate"
            ), e.response.body.text()

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


def recovery_shares_with_owners_scenario(args):
    # Members 0 and 1 are recovery participants, member 2 is recovery owner and member 3 is non-recovery member
    args.initial_member_count = 4
    args.initial_recovery_participant_count = 2
    args.initial_recovery_owner_count = 1
    recovery_owner_id = "member2"
    non_recovery_member_id = "member3"

    # Recovery threshold is initially set to number of recovery participants (2)
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        assert (
            len(network.consortium.get_active_recovery_participants()) == 2
        ), f"Unexpected recovery members count: {len(network.consortium.get_active_recovery_participants())}"

        assert (
            len(network.consortium.get_active_recovery_owners()) == 1
        ), f"Unexpected recovery owners count: {len(network.consortium.get_active_recovery_owners())}"

        # Removing the only recovery owner is allowed as recovery participant members exist.
        LOG.info(
            "Removing the recovery owner is still possible as recovery members exist"
        )
        member_to_remove = network.consortium.get_member_by_local_id(recovery_owner_id)
        test_remove_member(
            network,
            args,
            member_to_remove=member_to_remove,
            recovery_role=infra.member.RecoveryRole.Owner,
        )

        # Recovery owner count should now be 0.
        assert (
            len(network.consortium.get_active_recovery_owners()) == 0
        ), f"Unexpected recovery owners count: {len(network.consortium.get_active_recovery_owners())}"

        # Removing a recovery member is not possible as the number of recovery
        # participant members (2) would be under recovery threshold (2)
        LOG.info("Removing a recovery member should not be possible")
        try:
            test_remove_member_no_reqs(
                network, args, recovery_role=infra.member.RecoveryRole.Participant
            )
            assert False, "Removing a recovery member should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            # This is an apply() time failure, so the proposal remains Open
            # since the last vote is effectively discarded
            assert e.proposal.state == infra.proposal.ProposalState.OPEN

        # However, removing a non-recovery member is allowed
        LOG.info("Removing a non-recovery member is still possible")
        member_to_remove = network.consortium.get_member_by_local_id(
            non_recovery_member_id
        )
        test_remove_member(
            network,
            args,
            member_to_remove=member_to_remove,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )

        LOG.info("Removing an already-removed member succeeds with no effect")
        test_remove_member(
            network,
            args,
            member_to_remove=member_to_remove,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )

        LOG.info("Adding one non-recovery member")
        assert_recovery_shares_update(
            False,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.NonParticipant,
        )

        LOG.info("Adding one recovery owner")
        assert_recovery_shares_update(
            True,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Owner,
        )
        assert (
            len(network.consortium.get_active_recovery_owners()) == 1
        ), f"Unexpected recovery owners count: {len(network.consortium.get_active_recovery_owners())}"

        assert (
            len(network.consortium.get_active_recovery_participants()) == 2
        ), f"Unexpected recovery members count: {len(network.consortium.get_active_recovery_participants())}"

        LOG.info("Reduce recovery threshold")
        assert_recovery_shares_update(
            True,
            test_set_recovery_threshold,
            network,
            args,
            recovery_threshold=network.consortium.recovery_threshold - 1,
        )

        # Removing a recovery member now succeeds as threshold was reduced by 1
        LOG.info("Removing one recovery member")
        assert_recovery_shares_update(
            True,
            test_remove_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )

        # Removing the last recovery member also succeeds as there are owners and threshold is 1
        LOG.info("Removing the last recovery member when a recovery owner is present")
        assert_recovery_shares_update(
            True,
            test_remove_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )

        # Removing the only recovery owner when no other owner/participants exist should be impossible
        LOG.info(
            "Removing the only recovery owner when no other owner/participants exist should not be possible"
        )
        try:
            test_remove_member_no_reqs(
                network, args, recovery_role=infra.member.RecoveryRole.Owner
            )
            assert False, "Removing the recovery owner should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            # This is an apply() time failure, so the proposal remains Open
            # since the last vote is effectively discarded
            assert e.proposal.state == infra.proposal.ProposalState.OPEN

        assert (
            len(network.consortium.get_active_recovery_participants()) == 0
        ), f"Unexpected recovery members count: {len(network.consortium.get_active_recovery_participants())}"

        assert (
            len(network.consortium.get_active_recovery_owners()) == 1
        ), f"Unexpected recovery owners count: {len(network.consortium.get_active_recovery_owners())}"

        LOG.info("Set recovery threshold to 0 is impossible")
        exception = infra.proposal.ProposalNotCreated
        try:
            test_set_recovery_threshold(network, args, recovery_threshold=0)
            assert False, "Setting recovery threshold to 0 should not be possible"
        except exception as e:
            assert (
                e.response.status_code == 400
                and e.response.body.json()["error"]["code"]
                == "ProposalFailedToValidate"
            ), e.response.body.text()

        LOG.info(
            "Set recovery threshold to more than 1 when only active recovery owners exist is impossible"
        )
        try:
            test_set_recovery_threshold(
                network,
                args,
                recovery_threshold=2,
            )
            assert (
                False
            ), "Setting recovery threshold to more than 1 when only active recovery owners exist should not be possible"
        except infra.proposal.ProposalNotAccepted as e:
            # This is an apply() time failure, so the proposal remains Open
            # since the last vote is effectively discarded
            assert e.proposal.state == infra.proposal.ProposalState.OPEN

        try:
            test_set_recovery_threshold(network, args, recovery_threshold=256)
            assert False, "Recovery threshold cannot be set to > 255"
        except exception as e:
            assert (
                e.response.status_code == 400
                and e.response.body.json()["error"]["code"]
                == "ProposalFailedToValidate"
            ), e.response.body.text()

        primary, _ = network.find_primary()
        try:
            network.consortium.set_recovery_threshold(primary, recovery_threshold=None)
            assert False, "Recovery threshold value must be passed as proposal argument"
        except exception as e:
            assert (
                e.response.status_code == 400
                and e.response.body.json()["error"]["code"]
                == "ProposalFailedToValidate"
            ), e.response.body.text()

        LOG.info(
            "Setting recovery threshold to current threshold of 1 does not update shares"
        )
        assert_recovery_shares_update(
            False,
            test_set_recovery_threshold,
            network,
            args,
            recovery_threshold=1,
        )

        LOG.info("Adding two recovery participant members")
        assert_recovery_shares_update(
            True,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )
        assert_recovery_shares_update(
            True,
            test_add_member,
            network,
            args,
            recovery_role=infra.member.RecoveryRole.Participant,
        )

        assert (
            len(network.consortium.get_active_recovery_participants()) == 2
        ), f"Unexpected recovery members count: {len(network.consortium.get_active_recovery_participants())}"

        assert (
            len(network.consortium.get_active_recovery_owners()) == 1
        ), f"Unexpected recovery owners count: {len(network.consortium.get_active_recovery_owners())}"

        LOG.info("Setting recovery threshold to 2 should now be possible")
        assert_recovery_shares_update(
            True,
            test_set_recovery_threshold,
            network,
            args,
            recovery_threshold=2,
        )


def run(args):
    service_startups(args)
    recovery_shares_scenario(args)
    recovery_shares_with_owners_scenario(args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "membership",
        run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=0,
    )

    cr.add(
        "member_client",
        memberclient.run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=1),
    )

    cr.run()
