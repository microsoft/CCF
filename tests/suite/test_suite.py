# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import e2e_logging
import memberclient
import reconfiguration
import recovery
import election
import code_update
import membership
import governance_history
import jwt_test
import governance
import e2e_operations
import e2e_common_endpoints

from inspect import signature, Parameter

suites = {}


# This suite tests that rekeying, network configuration changes, recoveries and
# curve changes can be interleaved
suite_rekey_recovery = [
    recovery.test_recover_service,
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_on_other_curve,
    e2e_logging.test_rekey,
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_on_other_curve,
    recovery.test_recover_service,
    e2e_logging.test_rekey,
    reconfiguration.test_add_node,
    reconfiguration.test_change_curve,
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_on_other_curve,
    e2e_logging.test_rekey,
    recovery.test_recover_service,
    e2e_logging.test_rekey,
    recovery.test_recover_service_with_wrong_identity,
]
suites["rekey_recovery"] = suite_rekey_recovery

# This suite tests that membership changes and recoveries can be interleaved
suite_membership_recovery = [
    membership.test_add_member,
    recovery.test_recover_service,
    membership.test_remove_member,
    recovery.test_recover_service,
    membership.test_set_recovery_threshold,
    recovery.test_recover_service,
    membership.test_update_recovery_shares,
    recovery.test_recover_service,
]
suites["membership_recovery"] = suite_membership_recovery

# This suite tests that nodes addition, deletion and primary changes
# can be interleaved
suite_reconfiguration = [
    reconfiguration.test_add_node_from_snapshot,
    reconfiguration.test_retire_primary,
    e2e_logging.test_rekey,
    reconfiguration.test_add_node,
    election.test_kill_primary,
    election.test_commit_view_history,
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_from_snapshot,
    reconfiguration.test_retire_backup,
    reconfiguration.test_add_node,
    election.test_kill_primary,
    election.test_commit_view_history,
    e2e_logging.test_view_history,
]
suites["reconfiguration"] = suite_reconfiguration


all_tests_suite = [
    # e2e_logging:
    e2e_logging.test,
    e2e_logging.test_illegal,
    e2e_common_endpoints.test_large_messages,
    e2e_logging.test_remove,
    e2e_logging.test_cert_prefix,
    e2e_logging.test_anonymous_caller,
    e2e_logging.test_raw_text,
    e2e_logging.test_forwarding_frontends,
    e2e_logging.test_user_data_ACL,
    e2e_logging.test_view_history,
    e2e_logging.test_tx_statuses,
    e2e_logging.test_random_receipts,
    # membership:
    membership.test_set_recovery_threshold,
    membership.test_add_member,
    membership.test_remove_member,
    membership.test_remove_member,
    membership.test_update_recovery_shares,
    # memberclient:
    memberclient.test_missing_signature_header,
    memberclient.test_corrupted_signature,
    # reconfiguration:
    reconfiguration.test_node_replacement,
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_on_other_curve,
    reconfiguration.test_add_node_from_backup,
    reconfiguration.test_add_as_many_pending_nodes,
    reconfiguration.test_retire_backup,
    reconfiguration.test_node_certificates_validity_period,
    reconfiguration.test_retire_primary,
    # recovery:
    recovery.test_recover_service,
    recovery.test_recover_service_aborted,
    # rekey:
    e2e_logging.test_rekey,
    # election:
    reconfiguration.test_add_node,
    election.test_kill_primary,
    # code update:
    code_update.test_verify_quotes,
    code_update.test_add_node_with_bad_code,
    # curve migration:
    reconfiguration.test_change_curve,
    recovery.test_recover_service,
    # jwt
    jwt_test.test_refresh_jwt_issuer,
    # governance
    governance.test_each_node_cert_renewal,
    governance.test_service_cert_renewal,
    # Note: to be fixed for 3.0.0 final
    # governance.test_cose_ack,
    # governance.test_cose_withdrawal,
    # e2e_operations:
    e2e_operations.test_forced_ledger_chunk,
    e2e_operations.test_forced_snapshot,
    #
    #
    #
    # Below tests should always stay last, so that they
    # test the most complete ledgers
    governance_history.test_ledger_is_readable,
    governance_history.test_tables_doc,
]

suites["all"] = all_tests_suite

#
# Test functions are expected to be in the following format:
#
# @requirements_decorator (see suite/test_requirements.py)
def test_example(network, args):
    # Test logic, e.g. issuing transaction or adding a node
    return network


def test_name(test):
    return f"{test.__module__}.{test.__name__}"


def validate_tests_signature(suite):
    """
    Validates that the test functions signatures are in the correct format
    """
    valid_sig = signature(test_example)

    for test in suite:
        sig = signature(test)

        assert len(sig.parameters) >= len(
            valid_sig.parameters
        ), f"{test_name(test)} should have at least {len(valid_sig.parameters)} parameters (only has {len(sig.parameters)})"

        p_index = 0
        for p, v in zip(sig.parameters.items(), valid_sig.parameters.items()):
            assert (
                p[0] == v[0]
            ), f'Signature of {test_name(test)} does not contain "{v[0]}" parameter in the right order'
            p_index += 1

        for p in list(sig.parameters.values())[p_index:]:
            assert (
                p.default is not Parameter.empty
            ), f'Signature of {test_name(test)} includes custom non-defaulted parameter "{p}"'
