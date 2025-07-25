# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import http
import infra.member
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import infra.proposal
import suite.test_requirements as reqs
import infra.logging_app as app
import json
import jinja2
import infra.crypto
from datetime import datetime, timezone
import governance_js
from infra.runner import ConcurrentRunner
import governance_history
import tempfile
import infra.interfaces
import infra.log_capture
import governance_api
from hashlib import md5
import random

from loguru import logger as LOG


@reqs.description("Test create endpoint is not available")
def test_create_endpoint(network, args):
    primary, _ = network.find_nodes()
    with primary.client() as c:
        r = c.post("/node/create")
        assert r.status_code == http.HTTPStatus.FORBIDDEN.value
        assert r.body.json()["error"]["message"] == "Node is not in initial state."
    return network


@reqs.description("Test consensus status")
def test_consensus_status(network, args):
    primary, _ = network.find_nodes()
    with primary.client() as c:
        r = c.get("/node/consensus")
        assert r.status_code == http.HTTPStatus.OK.value
        assert r.body.json()["details"]["leadership_state"] == "Leader"
    return network


@reqs.description("Add user, remove user")
@reqs.supports_methods("/app/log/private")
def test_user(network, args, verify=True):
    # Note: This test should not be chained in the test suite as it creates
    # a new user and uses its own LoggingTxs
    primary, _ = network.find_nodes()
    new_user_local_id = "user3"
    new_user = network.create_user(new_user_local_id, args.participants_curve)
    user_data = {"lifetime": "temporary"}
    network.consortium.add_user(primary, new_user.local_id, user_data)
    txs = app.LoggingTxs(user_id=new_user.local_id)
    txs.issue(
        network=network,
        number_txs=1,
    )
    if verify:
        txs.verify()
    network.consortium.remove_user(primary, new_user.service_id)
    with primary.client(new_user_local_id) as c:
        r = c.get("/app/log/private")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value
    return network


@reqs.description("Validate sample Jinja templates")
@reqs.supports_methods("/app/log/private")
def test_jinja_templates(network, args, verify=True):
    primary, _ = network.find_primary()

    new_user_local_id = "bob"
    new_user = network.create_user(new_user_local_id, args.participants_curve)

    with primary.client(new_user_local_id) as c:
        r = c.post("/app/log/private", {"id": 42, "msg": "New user test"})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value

    template_loader = jinja2.ChoiceLoader(
        [
            jinja2.FileSystemLoader(args.jinja_templates_path),
            jinja2.FileSystemLoader(os.path.dirname(new_user.cert_path)),
        ]
    )
    template_env = jinja2.Environment(
        loader=template_loader, undefined=jinja2.StrictUndefined
    )

    proposal_template = template_env.get_template("set_user_proposal.json.jinja")
    proposal_body = proposal_template.render(cert=os.path.basename(new_user.cert_path))
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    ballot_template = template_env.get_template("ballot.json.jinja")
    ballot_body = ballot_template.render(**json.loads(proposal_body))
    network.consortium.vote_using_majority(primary, proposal, ballot_body)

    with primary.client(new_user_local_id) as c:
        r = c.post("/app/log/private", {"id": 42, "msg": "New user test"})
        assert r.status_code == http.HTTPStatus.OK.value

    network.consortium.remove_user(primary, new_user.service_id)
    with primary.client(new_user_local_id) as c:
        r = c.get("/app/log/private")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value

    return network


@reqs.description("Add untrusted node, check no quote is returned")
def test_no_quote(network, args):
    untrusted_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    endorsement=infra.interfaces.Endorsement(
                        authority=infra.interfaces.EndorsementAuthority.Node
                    )
                )
            }
        )
    )
    network.join_node(untrusted_node, args.package, args)
    with untrusted_node.client(
        ca=os.path.join(
            untrusted_node.common_dir, f"{untrusted_node.local_node_id}.pem"
        )
    ) as uc:
        r = uc.get("/node/quotes/self")
        assert r.status_code == http.HTTPStatus.NOT_FOUND
    return network


@reqs.description("Test node data set at node construction, and updated by governance")
def test_node_data(network, args):
    with tempfile.NamedTemporaryFile(mode="w+") as ntf:
        primary, _ = network.find_primary()
        with primary.client() as c:

            def get_nodes():
                r = c.get("/node/network/nodes")
                assert r.status_code == 200, (r.status_code, r.body.text())
                return {
                    node_info["node_id"]: node_info
                    for node_info in r.body.json()["nodes"]
                }

            new_node_data = {"my_id": "0xdeadbeef", "location": "The Moon"}
            json.dump(new_node_data, ntf)
            ntf.flush()
            untrusted_node = network.create_node(
                infra.interfaces.HostSpec(
                    rpc_interfaces={
                        infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                            endorsement=infra.interfaces.Endorsement(
                                authority=infra.interfaces.EndorsementAuthority.Node
                            )
                        )
                    }
                ),
                node_data_json_file=ntf.name,
            )

            # NB: This new node joins but is never trusted
            network.join_node(untrusted_node, args.package, args)

            nodes = get_nodes()
            assert untrusted_node.node_id in nodes, nodes
            new_node_info = nodes[untrusted_node.node_id]
            assert new_node_info["node_data"] == new_node_data, new_node_info

            # Set modified node data
            new_node_data["previous_locations"] = [new_node_data["location"]]
            new_node_data["location"] = "Secret Base"

            network.consortium.set_node_data(
                primary, untrusted_node.node_id, new_node_data
            )

            nodes = get_nodes()
            assert untrusted_node.node_id in nodes, nodes
            new_node_info = nodes[untrusted_node.node_id]
            assert new_node_info["node_data"] == new_node_data, new_node_info

            # Set modified node data on trusted primary
            primary_node_data = "Some plain JSON string"
            network.consortium.set_node_data(
                primary, primary.node_id, primary_node_data
            )

            nodes = get_nodes()
            assert primary.node_id in nodes, nodes
            primary_node_info = nodes[primary.node_id]
            assert (
                primary_node_info["node_data"] == primary_node_data
            ), primary_node_info

    return network


@reqs.description("Check member data")
def test_member_data(network, args):
    assert args.initial_operator_count > 0
    latest_public_tables, _ = network.get_latest_ledger_public_state()
    members_info = latest_public_tables["public:ccf.gov.members.info"]

    md_count = 0
    for member in network.get_members():
        stored_member_info = json.loads(members_info[member.service_id.encode()])
        if member.member_data:
            assert (
                stored_member_info["member_data"] == member.member_data
            ), f'stored member data "{stored_member_info["member_data"]}" != expected "{member.member_data} "'
            md_count += 1
        else:
            assert "member_data" not in stored_member_info

    assert md_count == args.initial_operator_count

    return network


@reqs.description("Check /gov/service/members endpoint")
def test_all_members(network, args):
    def run_test_all_members(network):
        primary, _ = network.find_primary()
        with primary.api_versioned_client(api_version=args.gov_api_version) as c:
            r = c.get("/gov/service/members")
            assert r.status_code == http.HTTPStatus.OK.value
            m_body = r.body.json()["value"]
            response_members = {m["memberId"]: m for m in m_body}

        network_members = network.get_members()
        assert len(network_members) == len(response_members)

        for member in network_members:
            assert member.service_id in response_members
            response_member = response_members[member.service_id]

            response_cert = response_member["certificate"]
            assert response_cert == member.cert

            response_status = infra.member.MemberStatus(response_member["status"])
            assert response_status == member.status

            response_data = response_member.get("memberData")
            assert response_data == member.member_data

            response_pub_enc_key = response_member.get("publicEncryptionKey")
            if member.recovery_role != infra.member.RecoveryRole.NonParticipant:
                enc_pub_key_file = os.path.join(
                    primary.common_dir, member.member_info["encryption_public_key_file"]
                )
                recovery_enc_key = open(enc_pub_key_file, encoding="utf-8").read()
                assert response_pub_enc_key == recovery_enc_key
            else:
                assert response_pub_enc_key is None

            response_recovery_role = response_member.get("recoveryRole")
            if member.recovery_role == infra.member.RecoveryRole.Owner:
                assert response_recovery_role == "Owner"
            elif member.recovery_role == infra.member.RecoveryRole.Participant:
                assert response_recovery_role == "Participant"
            else:
                assert response_recovery_role == "NonParticipant"

    # Test on current network
    run_test_all_members(network)

    # Test on mid-recovery network
    network.save_service_identity(args)
    primary, _ = network.find_primary()
    network.stop_all_nodes()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    # NB: Don't try to get snapshots, since there may not be any committed,
    # and we cannot wait for commit now that the node is stopped
    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    run_test_all_members(recovered_network)
    recovered_network.recover(args)

    return recovered_network


@reqs.description("Test ack state digest updates")
def test_ack_state_digest_update(network, args):
    for node in network.get_joined_nodes():
        network.consortium.get_any_active_member().update_ack_state_digest(node)
    return network


@reqs.description("Renew certificates of all nodes, one by one")
def test_each_node_cert_renewal(network, args):
    primary, _ = network.find_primary()
    now = datetime.now(timezone.utc)
    validity_period_allowed = args.maximum_node_certificate_validity_days - 1
    validity_period_forbidden = args.maximum_node_certificate_validity_days + 1

    test_vectors = [
        (now, validity_period_allowed, None),
        (now, None, None),  # Omit validity period (deduced from service configuration)
        (now, -1, infra.proposal.ProposalNotCreated),
        (now, validity_period_forbidden, infra.proposal.ProposalNotAccepted),
    ]

    for valid_from, validity_period_days, expected_exception in test_vectors:
        for node in network.get_joined_nodes():
            LOG.info(f"Renewing certificate for node {node.local_node_id}")
            for interface_name, rpc_interface in node.host.rpc_interfaces.items():
                LOG.debug(f"On interface {interface_name}")
                with node.client(interface_name=interface_name) as c:
                    c.get("/node/network/nodes")

                    node_cert_tls_before = node.get_tls_certificate_pem(
                        interface_name=interface_name
                    )

                    # Verify that presented self-signed certificate matches the one returned by
                    # operator endpoint
                    self_signed_cert = node.retrieve_self_signed_cert(
                        interface_name=interface_name
                    )
                    if (
                        rpc_interface.endorsement.authority
                        == infra.interfaces.EndorsementAuthority.Node
                    ):
                        assert node_cert_tls_before == self_signed_cert

                    assert (
                        infra.crypto.compute_public_key_der_hash_hex_from_pem(
                            node_cert_tls_before
                        )
                        == node.node_id
                    )

                    try:
                        network.consortium.set_node_certificate_validity(
                            primary,
                            node,
                            valid_from=valid_from,
                            validity_period_days=validity_period_days,
                        )
                        node.set_certificate_validity_period(
                            valid_from,
                            validity_period_days
                            or args.maximum_node_certificate_validity_days,
                        )
                    except Exception as e:
                        if expected_exception is None:
                            raise e
                        assert isinstance(e, expected_exception)
                        continue
                    else:
                        assert (
                            expected_exception is None
                        ), "Proposal should have not succeeded"

                    # Node certificate is updated on global commit hook
                    network.wait_for_all_nodes_to_commit(primary)

                    node_cert_tls_after = node.get_tls_certificate_pem(
                        interface_name=interface_name
                    )
                    assert (
                        node_cert_tls_before != node_cert_tls_after
                    ), f"Node {node.local_node_id} certificate was not renewed"

                    # verify_ca is false since the certificate has been renewed and
                    # it needs to be retrieved from the node
                    self_signed_cert = node.retrieve_self_signed_cert(
                        interface_name=interface_name,
                        verify_ca=rpc_interface.endorsement.authority
                        != infra.interfaces.EndorsementAuthority.Node,
                    )
                    if (
                        rpc_interface.endorsement.authority
                        == infra.interfaces.EndorsementAuthority.Node
                    ):
                        assert node_cert_tls_after == self_signed_cert

                    # Once the self-signed certificate has been retrieved and stored
                    # on disk, it can be used to verify the server identity
                    node.retrieve_self_signed_cert(
                        interface_name=interface_name, verify_ca=True
                    )

                    node.verify_certificate_validity_period(
                        interface_name=interface_name
                    )
                    LOG.info(
                        f"Certificate for node {node.local_node_id} has successfully been renewed"
                    )

                    # Long-connected client is still connected after certificate renewal
                    c.get("/node/network/nodes")

    return network


def renew_service_certificate(network, args, valid_from, validity_period_days):
    primary, _ = network.find_primary()
    valid_from_x509 = str(valid_from)
    network.consortium.set_service_certificate_validity(
        primary,
        valid_from=valid_from_x509,
        validity_period_days=validity_period_days,
    )
    network.verify_service_certificate_validity_period(
        validity_period_days or args.maximum_service_certificate_validity_days
    )
    return network


@reqs.description("Renew service certificate")
def test_service_cert_renewal(network, args, valid_from=None):
    return renew_service_certificate(
        network,
        args,
        valid_from=valid_from or datetime.now(timezone.utc),
        validity_period_days=args.maximum_service_certificate_validity_days - 1,
    )


@reqs.description("Renew service certificate - extended")
def test_service_cert_renewal_extended(network, args):
    validity_period_forbidden = args.maximum_service_certificate_validity_days + 1

    now = datetime.now(timezone.utc)
    test_vectors = [
        (now, None, None),  # Omit validity period (deduced from service configuration)
        (now, -1, infra.proposal.ProposalNotCreated),
        (now, validity_period_forbidden, infra.proposal.ProposalNotAccepted),
    ]

    for valid_from, validity_period_days, expected_exception in test_vectors:
        try:
            renew_service_certificate(network, args, valid_from, validity_period_days)
        except Exception as e:
            assert isinstance(e, expected_exception)
            continue
        else:
            assert expected_exception is None, "Proposal should have not succeeded"

    # Confirm that we can renew the service certificate multiple times
    # without issue
    for _ in range(0, 5):
        new_duration = random.randint(1, 100)
        LOG.info(f"Renewing service certificate for {new_duration} days")
        renew_service_certificate(network, args, now, new_duration)
        # Old cert still valid
        primary, _ = network.find_primary()
        with primary.client() as c:
            c.get("/node/network/nodes")
        # Update service identity used by clients to connect to the network
        network.refresh_service_identity_file(args)
        # Using new cert also works
        with primary.client() as c:
            c.get("/node/network/nodes")

    return network


@reqs.description("Binding proposal to service identity")
def test_binding_proposal_to_service_identity(network, args):
    primary, _ = network.find_primary()
    network.consortium.assert_service_identity(primary, network.cert_path)
    created = True
    try:
        network.consortium.assert_service_identity(primary, network.users[0].cert_path)
    except infra.proposal.ProposalNotCreated as pe:
        assert (
            pe.response.status_code == 400
            and pe.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), pe.response.body.text()
        created = False
    assert not created
    return network


@reqs.description("Update certificates of all nodes at once")
def test_all_nodes_cert_renewal(network, args, valid_from=None):
    primary, _ = network.find_primary()

    valid_from = valid_from or datetime.now(timezone.utc)
    validity_period_days = args.maximum_node_certificate_validity_days

    self_signed_node_certs_before = {}
    for node in network.get_joined_nodes():
        # Note: GET /node/self_signed_certificate endpoint was added after 2.0.0-r6
        if node.version_after("ccf-2.0.0-rc6"):
            self_signed_node_certs_before[node.local_node_id] = (
                node.retrieve_self_signed_cert()
            )

    network.consortium.set_all_nodes_certificate_validity(
        primary,
        valid_from=valid_from,
        validity_period_days=validity_period_days,
    )

    # Node certificates are updated on global commit hook
    network.wait_for_all_nodes_to_commit(primary)

    for node in network.get_joined_nodes():
        node.set_certificate_validity_period(valid_from, validity_period_days)
        if node.version_after("ccf-2.0.0-rc6"):
            assert (
                self_signed_node_certs_before[node.local_node_id]
                != node.retrieve_self_signed_cert()
            ), f"Self-signed node certificate for node {node.local_node_id} was not renewed"


@reqs.description("Change authentication method used for governance")
def test_change_authenticate_session(network, args):
    # NB: This doesn't actually test things, it just changes the configuration
    # for future tests. Expects to be part of an interesting suite
    if network.consortium.authenticate_session != "COSE":
        network.consortium.set_authenticate_session(False)
    else:
        network.consortium.set_authenticate_session("COSE")
    return network


def gov(args):
    for node in args.nodes:
        node.rpc_interfaces.update(infra.interfaces.make_secondary_interface())

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network.consortium.set_authenticate_session(args.authenticate_session)
        test_create_endpoint(network, args)
        test_consensus_status(network, args)
        test_member_data(network, args)
        network = test_all_members(network, args)
        test_user(network, args)
        test_jinja_templates(network, args)
        test_no_quote(network, args)
        test_node_data(network, args)
        test_ack_state_digest_update(network, args)
        test_each_node_cert_renewal(network, args)
        test_binding_proposal_to_service_identity(network, args)
        test_all_nodes_cert_renewal(network, args)
        test_service_cert_renewal(network, args)
        test_service_cert_renewal_extended(network, args)


# These tests requiring starting up + shutting down a node with specific
# requirements, so are run in a standalone network
def single_node(args):
    def test_desc(s):
        LOG.opt(colors=True).info(f"<magenta>Test: {s}</>")

    test_desc("Node data on start node")
    with tempfile.NamedTemporaryFile(mode="w+") as ntf:
        start_node_data = {"on_start": "some_node_data"}
        json.dump(start_node_data, ntf)
        ntf.flush()

        with infra.network.network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            pdb=args.pdb,
            node_data_json_file=ntf.name,
        ) as network:
            network.start_and_open(args)
            primary, _ = network.find_primary()
            with primary.client() as c:
                r = c.get("/node/network/nodes")
                assert r.status_code == 200, (r.status_code, r.body.text())
                assert (
                    r.body.json()["nodes"][0]["node_data"] == start_node_data
                ), r.body.json()["nodes"][0]["node_data"]

            test_desc("Logging levels of governance operations")
            consortium = network.consortium

            def rand_hex():
                return md5(random.getrandbits(32).to_bytes(4, "big")).hexdigest()

            validate_info = f"Logged at info during validate: {rand_hex()}"
            validate_warn = f"Logged at warn during validate: {rand_hex()}"
            validate_js = (
                f"console.info('{validate_info}'); console.warn('{validate_warn}')"
            )
            apply_info = f"Logged at info during apply: {rand_hex()}"
            apply_warn = f"Logged at warn during apply: {rand_hex()}"
            apply_js = f"console.info('{apply_info}'); console.warn('{apply_warn}')"
            eval_info = f"Logged during constitution evaluation: {rand_hex()}"
            eval_js = f"\nconsole.info('{eval_info}')\n"
            with governance_js.temporary_constitution(
                network,
                args,
                governance_js.make_action_snippet(
                    "just_log",
                    validate=validate_js,
                    apply=apply_js,
                )
                + eval_js,
            ):
                proposal_body, vote = consortium.make_proposal("just_log")
                proposal = consortium.get_any_active_member().propose(
                    primary, proposal_body
                )
                consortium.vote_using_majority(primary, proposal, vote)

            test_desc("Logging governance error responses")
            validate_error = f"Error thrown during validate: {rand_hex()}"
            validate_js = f"throw new Error('{validate_error}')"
            with governance_js.temporary_constitution(
                network,
                args,
                governance_js.make_action_snippet(
                    "throw_in_validate",
                    validate=validate_js,
                ),
            ):
                proposal_body, vote = consortium.make_proposal("throw_in_validate")
                try:
                    proposal = consortium.get_any_active_member().propose(
                        primary, proposal_body
                    )
                except infra.proposal.ProposalNotCreated as e:
                    assert validate_error in e.response.body.text()
                else:
                    assert False, "Expected to throw"

            apply_error = f"Error thrown during apply: {rand_hex()}"
            apply_js = f"throw new Error('{apply_error}')"
            with governance_js.temporary_constitution(
                network,
                args,
                governance_js.make_action_snippet(
                    "throw_in_apply",
                    apply=apply_js,
                ),
            ):
                proposal_body, vote = consortium.make_proposal("throw_in_apply")
                proposal = consortium.get_any_active_member().propose(
                    primary, proposal_body
                )
                try:
                    consortium.vote_using_majority(primary, proposal, vote)
                except infra.proposal.ProposalNotAccepted as e:
                    assert apply_error in e.response.body.text()
                else:
                    assert False, "Expected to throw"

            LOG.info("Stopping network to read node logs")

    test_desc("Checking logging after node shutdown")
    info_counts = {
        k: 0
        for k in {validate_info, apply_info, eval_info, validate_error, apply_error}
    }
    warn_counts = {k: 0 for k in {validate_warn, apply_warn}}
    out_path, _ = primary.get_logs()
    for line in open(out_path, "r", encoding="utf-8").readlines():
        for k in info_counts.keys():
            if k in line and "[info ]" in line:
                info_counts[k] += 1

        for k in warn_counts.keys():
            if k in line and "[fail ]" in line:
                warn_counts[k] += 1

    LOG.debug("Found following info line occurrences in node output:")
    for k, v in info_counts.items():
        LOG.debug(f"  '{k}': {v}")

    LOG.debug("Found following warn line occurrences in node output:")
    for k, v in warn_counts.items():
        LOG.debug(f"  '{k}': {v}")

    assert info_counts[validate_info] == 1
    assert warn_counts[validate_warn] == 1
    assert info_counts[apply_info] == 1
    assert warn_counts[apply_warn] == 1

    # We eval a lot!
    # Each proposal results in 5 separate evaluations for strict sandboxing:
    # - Proposal validation (in initial request)
    # - 3 separate ballot submissions (1 per member)
    # - Proposal application
    # And we approve 2 proposals while this proposal is active ("just_log", and "set_constitution" to the original)
    assert info_counts[eval_info] == 10

    assert info_counts[validate_error] == 1, info_counts
    assert info_counts[apply_error] == 1, info_counts


def js_gov(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network.consortium.set_authenticate_session(args.authenticate_session)
        governance_js.test_all_open_proposals(network, args)
        governance_js.test_proposal_validation(network, args)
        governance_js.test_proposal_storage(network, args)
        governance_js.test_proposal_withdrawal(network, args)
        governance_js.test_ballot_storage(network, args)
        governance_js.test_pure_proposals(network, args)
        governance_js.test_set_constitution(network, args)
        governance_js.test_proposals_with_votes(network, args)
        governance_js.test_check_proposal_id_is_set_correctly(network, args)
        governance_js.test_vote_failure_reporting(network, args)
        governance_js.test_operator_proposals_and_votes(network, args)
        governance_js.test_operator_provisioner_proposals_and_votes(network, args)
        governance_js.test_apply(network, args)
        governance_js.test_read_write_restrictions(network, args)
        governance_js.test_final_proposal_visibility(network, args)

        network.stop_all_nodes()
        # Should come last, requires stopped network
        governance_js.test_ledger_governance_invariants(network, args)


def gov_replay(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network.consortium.set_authenticate_session(args.authenticate_session)
        governance_js.test_proposal_replay_protection(network, args)
        governance_js.test_cose_msg_type_validation(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--jinja-templates-path",
            help="Path to directory containing sample Jinja templates",
            required=True,
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "single_node",
        single_node,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        authenticate_session="COSE",
    )

    cr.add(
        "session_coseauth",
        gov,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=3,
        authenticate_session="COSE",
    )

    cr.add(
        "js",
        js_gov,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=3,
        authenticate_session="COSE",
    )

    cr.add(
        "replay",
        gov_replay,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        initial_user_count=3,
        authenticate_session="COSE",
    )

    cr.add(
        "history",
        governance_history.run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        authenticate_session="COSE",
    )

    cr.add(
        "gov_api",
        governance_api.run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run(2)
