# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.member
import infra.network
import infra.node
import infra.logging_app as app
import infra.checker
import infra.crypto
import suite.test_requirements as reqs
import ccf.ledger
import os
import subprocess
import json
from infra.runner import ConcurrentRunner
from infra.consortium import slurp_file
import infra.health_watcher
import time
from e2e_logging import verify_receipt, test_cose_receipt_schema
import infra.service_load
import ccf.tx_id
import tempfile
import http
import base64
import shutil
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from ccf.cose import validate_cose_sign1
from pycose.messages import Sign1Message  # type: ignore
import random
from loguru import logger as LOG


def shifted_tx(tx, view_diff, seq_dif):
    return ccf.tx_id.TxID(tx.view + view_diff, tx.seqno + seq_dif)


def get_and_verify_historical_receipt(network, ref_msg):
    primary, _ = network.find_primary()
    if not ref_msg:
        if not network.txs.priv:
            network.txs.issue(network, number_txs=1)
        idx, _ = network.txs.get_last_tx()
        ref_msg = network.txs.priv[idx][-1]
        ref_msg["idx"] = idx
    r = network.txs.get_receipt(
        primary,
        ref_msg["idx"],
        ref_msg["seqno"],
        ref_msg["view"],
    )
    verify_receipt(r.json()["receipt"], network.cert)
    return ref_msg


def query_endorsements_chain(node, txid):
    for _ in range(0, 10):
        with node.client("user0") as cli:
            response = cli.get(
                "/log/public/cose_endorsements",
                headers={infra.clients.CCF_TX_ID_HEADER: str(txid)},
            )
            if response.status_code != http.HTTPStatus.ACCEPTED:
                return response
        time.sleep(0.1)
    return response


def verify_endorsements_chain(primary, endorsements, pubkey):
    for endorsement in endorsements:
        validate_cose_sign1(cose_sign1=endorsement, pubkey=pubkey)

        cose_msg = Sign1Message.decode(endorsement)
        last_tx = ccf.tx_id.TxID.from_str(cose_msg.phdr["ccf.v1"]["epoch.end.txid"])
        receipt = primary.get_receipt(last_tx.view, last_tx.seqno)
        root_from_receipt = bytes.fromhex(receipt.json()["leaf"])
        root_from_headers = cose_msg.phdr["ccf.v1"]["epoch.end.merkle.root"]
        assert root_from_receipt == root_from_headers

        CWT_KEY = 15
        IAT_CWT_LABEL = 6
        assert (
            CWT_KEY in cose_msg.phdr and IAT_CWT_LABEL in cose_msg.phdr[CWT_KEY]
        ), cose_msg.phdr

        last_five_minutes = 5 * 60
        assert (
            time.time() - cose_msg.phdr[CWT_KEY][IAT_CWT_LABEL] < last_five_minutes
        ), cose_msg.phdr

        endorsement_filename = "prev_service_identoty_endorsement.cose"
        with open(endorsement_filename, "wb") as f:
            f.write(endorsement)
        subprocess.run(
            [
                "cddl",
                "../cddl/ccf-cose-endorsement-service-identity.cddl",
                "v",
                endorsement_filename,
            ],
            check=True,
        )

        next_key_bytes = cose_msg.payload
        pubkey = serialization.load_der_public_key(next_key_bytes, default_backend())


def restart_network(old_network, args, current_ledger_dir, committed_ledger_dirs):
    network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=old_network,
    )
    network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    network.recover(args)
    return network


def recover_with_primary_dying(args, recovered_network):
    # Minimal copy-paste from network.recover() with primary shut down.
    recovered_network.consortium.activate(recovered_network.find_random_node())
    recovered_network.consortium.check_for_service(
        recovered_network.find_random_node(),
        status=infra.network.ServiceStatus.RECOVERING,
    )
    recovered_network.wait_for_all_nodes_to_be_trusted(
        recovered_network.find_random_node()
    )

    prev_service_identity = None
    if args.previous_service_identity_file:
        prev_service_identity = slurp_file(args.previous_service_identity_file)
    LOG.info(f"Prev identity: {prev_service_identity}")

    recovered_network.consortium.transition_service_to_open(
        recovered_network.find_random_node(),
        previous_service_identity=prev_service_identity,
    )

    recovered_network.consortium.recover_with_shares(
        recovered_network.find_random_node()
    )
    for node in recovered_network.get_joined_nodes():
        recovered_network.wait_for_state(
            node,
            infra.node.State.READING_PRIVATE_LEDGER.value,
            timeout=args.ledger_recovery_timeout,
        )

    retired_primary, _ = recovered_network.find_primary()
    retired_id = retired_primary.node_id

    LOG.info(f"Force-kill primary {retired_id}")
    retired_primary.sigkill()
    recovered_network.nodes.remove(retired_primary)

    primary, _ = recovered_network.find_primary()
    while not primary or primary.node_id == retired_id:
        LOG.info("Keep looking for new primary")
        time.sleep(0.1)
        primary, _ = recovered_network.find_primary()

    # Ensure new primary has been elected while all nodes are still reading private entries.
    for node in recovered_network.get_joined_nodes():
        LOG.info(f"Check state for node id {node.node_id}")
        with node.client(connection_timeout=1) as c:
            assert (
                infra.node.State.READING_PRIVATE_LEDGER.value
                == c.get("/node/state").body.json()["state"]
            )

    # Wait for recovery to complete.
    for node in recovered_network.get_joined_nodes():
        recovered_network.wait_for_state(
            node,
            infra.node.State.PART_OF_NETWORK.value,
            timeout=args.ledger_recovery_timeout,
        )


@reqs.description("Recover a service")
@reqs.recover(number_txs=2)
def test_recover_service(
    network,
    args,
    from_snapshot=True,
    no_ledger=False,
    via_recovery_owner=False,
    force_election=False,
):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    prev_ident = open(args.previous_service_identity_file, "r", encoding="utf-8").read()
    # Strip trailing null byte
    prev_ident = prev_ident.strip("\x00")
    with old_primary.client() as c:
        r = c.get("/node/service/previous_identity")
        assert r.status_code in (200, 404), r.status_code
        prev_view = c.get("/node/network").body.json()["current_view"]

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    if force_election:
        # Necessary to make recovering private entries taking long enough time
        # to allow election to happen if primary gets killed. These later get verified post-recovery (logging app verify_tx() thing).
        network.txs.issue(
            network,
            number_txs=10000,
            send_public=False,
            msg=str(bytes(random.getrandbits(8) for _ in range(512))),
        )

    # Start health watcher and stop nodes one by one until a recovery has to be staged
    watcher = infra.health_watcher.NetworkHealthWatcher(network, args, verbose=True)
    watcher.start()

    for node in network.get_joined_nodes():
        time.sleep(args.election_timeout_ms / 1000)
        node.stop()

    watcher.wait_for_recovery()

    if no_ledger:
        current_ledger_dir = None
        committed_ledger_dirs = None
    else:
        current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    with tempfile.NamedTemporaryFile(mode="w+") as node_data_tf:
        start_node_data = {"this is a": "recovery node"}
        json.dump(start_node_data, node_data_tf)
        node_data_tf.flush()
        recovered_network = infra.network.Network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            existing_network=network,
            node_data_json_file=node_data_tf.name,
        )

        with tempfile.NamedTemporaryFile(mode="w+") as ntf:
            service_data = {"this is a": "recovery service"}
            json.dump(service_data, ntf)
            ntf.flush()
            recovered_network.start_in_recovery(
                args,
                ledger_dir=current_ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=snapshots_dir,
                service_data_json_file=ntf.name,
            )
            LOG.info("Check that service data has been set")
            primary, _ = recovered_network.find_primary()
            with primary.client() as c:
                r = c.get("/node/network").body.json()
                assert r["service_data"] == service_data
                LOG.info("Check that the node data has been set")
                r = c.get("/node/network/nodes").body.json()
                assert r["nodes"]
                did_check = False
                for node in r["nodes"]:
                    if node["status"] == "Trusted":
                        assert node["node_data"] == start_node_data
                        did_check = True
                assert did_check

    recovered_network.verify_service_certificate_validity_period(
        args.initial_service_cert_validity_days
    )

    new_nodes = recovered_network.get_joined_nodes()
    for n in new_nodes:
        with n.client() as c:
            r = c.get("/node/service/previous_identity")
            assert r.status_code == 200, r.status_code
            body = r.body.json()
            assert "previous_service_identity" in body, body
            received_prev_ident = body["previous_service_identity"]
            assert (
                received_prev_ident == prev_ident
            ), f"Response doesn't match previous identity: {received_prev_ident} != {prev_ident}"
            r = c.get("/node/ready/gov")
            assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r
            r = c.get("/node/ready/app")
            assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE.value, r

    if force_election:
        recover_with_primary_dying(args, recovered_network)
    else:
        recovered_network.recover(args, via_recovery_owner=via_recovery_owner)

    LOG.info("Check that new service view is as expected")
    new_primary, _ = recovered_network.find_primary()
    with new_primary.client() as c:
        assert (
            ccf.tx_id.TxID.from_str(
                c.get("/node/network").body.json()["current_service_create_txid"]
            ).view
            == prev_view + 2
        )
        r = c.get("/node/ready/gov")
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r
        r = c.get("/node/ready/app")

        # Service opening may be slightly delayed due to forced election (if option enabled).
        app_ready_attempts = 10 if force_election else 0
        while (
            r.status_code != http.HTTPStatus.NO_CONTENT.value and app_ready_attempts > 0
        ):
            time.sleep(0.1)
            app_ready_attempts -= 1
            r = c.get("/node/ready/app")

        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r

    return recovered_network


@reqs.description("Recover a service with wrong service identity")
@reqs.recover(number_txs=2)
@reqs.sufficient_network_recovery_count(required_count=1)
def test_recover_service_with_wrong_identity(network, args):
    old_primary, _ = network.find_primary()

    snapshots_dir = network.get_committed_snapshots(old_primary)

    network.save_service_identity(args)
    first_service_identity_file = args.previous_service_identity_file

    with old_primary.client() as c:
        before_recovery_tx_id = ccf.tx_id.TxID.from_str(
            c.get("/node/commit").body.json()["transaction_id"]
        )
        previous_service_created_tx_id = ccf.tx_id.TxID.from_str(
            c.get("/node/network").body.json()["current_service_create_txid"]
        )

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    # Attempt a recovery with the wrong previous service certificate

    args.previous_service_identity_file = network.consortium.user_cert_path("user0")

    broken_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )

    exception = None
    try:
        broken_network.start_in_recovery(
            args,
            ledger_dir=current_ledger_dir,
            committed_ledger_dirs=committed_ledger_dirs,
            snapshots_dir=snapshots_dir,
        )
    except Exception as ex:
        exception = ex

    broken_network.ignoring_shutdown_errors = True
    broken_network.stop_all_nodes(skip_verification=True)

    if exception is None:
        raise ValueError("Recovery should have failed")
    if not broken_network.nodes[0].check_log_for_error_message(
        "Previous service identity does not endorse the node identity that signed the snapshot"
    ):
        raise ValueError("Node log does not contain the expected error message")

    # Attempt a second recovery with the broken cert but no snapshot
    # Now the mismatch is only noticed when the transition proposal is submitted

    broken_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )

    broken_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )

    exception = None
    try:
        broken_network.recover(args)
    except Exception as ex:
        exception = ex

    broken_network.ignoring_shutdown_errors = True
    broken_network.stop_all_nodes(skip_verification=True)

    if exception is None:
        raise ValueError("Recovery should have failed")
    if not broken_network.nodes[0].check_log_for_error_message(
        "Unable to open service: Previous service identity does not match."
    ):
        raise ValueError("Node log does not contain the expected error message")

    # Recover, now with the correct service identity

    args.previous_service_identity_file = first_service_identity_file

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
        snapshots_dir=snapshots_dir,
    )

    # Must fail with a dedicated error message if requesting a receipt for a TX
    # from past epochs, since ledger secrets are not yet available,
    # therefore no receipt can be generated.
    primary, _ = recovered_network.find_primary()
    with primary.client() as cli:
        curr_tx_id = ccf.tx_id.TxID.from_str(
            cli.get("/node/commit").body.json()["transaction_id"]
        )

        response = cli.get(f"/node/receipt?transaction_id={str(before_recovery_tx_id)}")
        assert response.status_code == http.HTTPStatus.NOT_FOUND, response
        assert (
            "not signed by the current service"
            in response.body.json()["error"]["message"]
        ), response

        current_service_created_tx_id = ccf.tx_id.TxID.from_str(
            cli.get("/node/network").body.json()["current_service_create_txid"]
        )

    # TX from the current epoch though can be verified, as soon as the caller
    # trusts the current service identity.
    receipt = primary.get_receipt(curr_tx_id.view, curr_tx_id.seqno).json()
    verify_receipt(receipt, recovered_network.cert, is_signature_tx=True)

    recovered_network.recover(args)

    # Needs refreshing, recovery has completed.
    with primary.client() as cli:
        curr_tx_id = ccf.tx_id.TxID.from_str(
            cli.get("/node/commit").body.json()["transaction_id"]
        )

    # Check receipts for transactions after multiple recoveries. This test
    # relies on previous recoveries and is therefore prone to failures if
    # surrounding test calls change.
    txids = [
        # Last TX before previous recovery
        shifted_tx(previous_service_created_tx_id, -2, -1),
        # First after previous recovery
        previous_service_created_tx_id,
        # Random TX before previous and last recovery
        shifted_tx(current_service_created_tx_id, -2, -5),
        # Last TX before last recovery
        shifted_tx(current_service_created_tx_id, -2, -1),
        # First TX after last recovery
        current_service_created_tx_id,
        # Random TX after last recovery
        shifted_tx(curr_tx_id, 0, -3),
    ]

    for tx in txids:
        receipt = primary.get_receipt(tx.view, tx.seqno).json()

        try:
            verify_receipt(receipt, recovered_network.cert)
        except AssertionError:
            # May fail due to missing leaf components if it's a signature TX,
            # try again with a flag to force skip leaf components verification.
            verify_receipt(receipt, recovered_network.cert, is_signature_tx=True)

    with primary.client() as cli:
        service_cert = cli.get("/node/network").body.json()["service_certificate"]
        cert = load_pem_x509_certificate(
            service_cert.encode("ascii"), default_backend()
        )

    for tx in txids[0:1]:
        response = query_endorsements_chain(primary, tx)
        assert response.status_code == http.HTTPStatus.OK, response
        endorsements = [
            base64.b64decode(x) for x in response.body.json()["endorsements"]
        ]
        assert len(endorsements) == 2  # 2 recoveries behind
        verify_endorsements_chain(primary, endorsements, cert.public_key())

    for tx in txids[1:4]:
        response = query_endorsements_chain(primary, tx)
        assert response.status_code == http.HTTPStatus.OK, response
        endorsements = [
            base64.b64decode(x) for x in response.body.json()["endorsements"]
        ]
        assert len(endorsements) == 1  # 1 recovery behind
        verify_endorsements_chain(primary, endorsements, cert.public_key())

    for tx in txids[4:]:
        response = query_endorsements_chain(primary, tx)
        assert response.status_code == http.HTTPStatus.NOT_FOUND, response

    return recovered_network


@reqs.description("Recover a service from local files")
def test_recover_service_from_files(
    args, directory, expected_recovery_count, test_receipt=True
):
    service_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "testdata", directory
    )

    old_common = os.path.join(service_dir, "common")
    LOG.info(f"Copying common folder: {old_common}")
    new_common = infra.network.get_common_folder_name(args.workspace, args.label)

    cmd = ["rm", "-rf", new_common]
    assert (
        infra.proc.ccall(*cmd).returncode == 0
    ), f"Could not remove existing {new_common} directory"
    cmd = ["mkdir", "-p", new_common]
    assert (
        infra.proc.ccall(*cmd).returncode == 0
    ), f"Could not create fresh {new_common} directory"
    for file in os.listdir(old_common):
        cmd = ["cp", os.path.join(old_common, file), new_common]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not copy {file} to {new_common}"

    network = infra.network.Network(args.nodes, args.binary_dir)

    args.previous_service_identity_file = os.path.join(old_common, "service_cert.pem")

    network.start_in_recovery(
        args,
        committed_ledger_dirs=[os.path.join(service_dir, "ledger")],
        snapshots_dir=os.path.join(service_dir, "snapshots"),
        common_dir=new_common,
    )

    network.recover(args, expected_recovery_count=expected_recovery_count)

    primary, _ = network.find_primary()

    # The member and user certs stored on this service are all currently expired.
    # Remove user certs and add new users before attempting any user requests
    primary, _ = network.find_primary()

    user_certs = [
        os.path.join(old_common, file)
        for file in os.listdir(old_common)
        if file.startswith("user") and file.endswith("_cert.pem")
    ]
    user_ids = [
        infra.crypto.compute_cert_der_hash_hex_from_pem(open(cert).read())
        for cert in user_certs
    ]
    for user_id in user_ids:
        LOG.info(f"Removing expired user {user_id}")
        network.consortium.remove_user(primary, user_id)

    new_user_local_id = "recovery_user"
    new_user = network.create_user(new_user_local_id, args.participants_curve)
    LOG.info(f"Adding new user {new_user.service_id}")
    network.consortium.add_user(primary, new_user.local_id)

    infra.checker.check_can_progress(primary, local_user_id=new_user_local_id)

    if test_receipt:
        r = primary.get_receipt(2, 3)
        verify_receipt(r.json(), network.cert)


@reqs.description("Attempt to recover a service but abort before recovery is complete")
def test_recover_service_aborted(network, args, from_snapshot=False):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    network.stop_all_nodes()
    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    aborted_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    aborted_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )

    LOG.info("Fill in ledger to trigger new chunks, which should be marked as recovery")
    primary, _ = aborted_network.find_primary()
    while (
        len(
            [
                f
                for f in os.listdir(primary.remote.ledger_paths()[0])
                if f.endswith(
                    f"{ccf.ledger.COMMITTED_FILE_SUFFIX}{ccf.ledger.RECOVERY_FILE_SUFFIX}"
                )
            ]
        )
        < 2
    ):
        # Wait until at least two recovery ledger chunks are committed
        aborted_network.consortium.force_ledger_chunk(primary)

    LOG.info(
        "Do not complete service recovery on purpose and initiate new recovery from scratch"
    )

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(primary)

    # Check that all nodes have the same (recovery) ledger files
    aborted_network.stop_all_nodes(
        skip_verification=True, read_recovery_ledger_files=True
    )

    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=aborted_network,
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )
    recovered_network.recover(args)
    return recovered_network


# https://github.com/microsoft/CCF/issues/4557
@reqs.description(
    "Recover ledger after an isolated node restarted from an old snapshot"
)
def test_persistence_old_snapshot(network, args):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    # Retrieve oldest snapshot
    snapshots_dir = network.get_committed_snapshots(old_primary)
    snapshots_to_delete = sorted(
        os.listdir(snapshots_dir),
        key=lambda x: infra.node.get_snapshot_seqnos(x)[0],
    )[1:]
    for s in snapshots_to_delete:
        os.remove(os.path.join(snapshots_dir, s))

    # All ledger files, including committed ones, are copied to the main
    # ledger directory (note: they used to be marked as ".ignored" by the new node)
    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()
    for committed_ledger_dir in committed_ledger_dirs:
        for ledger_file_path in os.listdir(committed_ledger_dir):
            shutil.copy(
                os.path.join(committed_ledger_dir, ledger_file_path), current_ledger_dir
            )

    # Capture latest committed TxID on primary so we can check later that the
    # entire ledger has been fully recovered
    with old_primary.client() as c:
        latest_txid = c.get("/node/commit").body.json()["transaction_id"]

    new_node = network.create_node("local://localhost")
    # Use invalid node-to-node interface so that the new node is isolated and does
    # not receive any consensus updates.
    new_node.n2n_interface = infra.interfaces.Interface(host="invalid", port=8000)
    network.join_node(
        new_node,
        args.package,
        args,
        copy_ledger=False,
        snapshots_dir=snapshots_dir,
        ledger_dir=current_ledger_dir,
    )

    try:
        network.trust_node(new_node, args, timeout=3)
    except TimeoutError:
        pass
    else:
        assert (
            False
        ), "Trusting new node should have failed as n2n interface is not valid"

    new_node_ledger_path = new_node.remote.ledger_paths()[0]

    network.stop_all_nodes()

    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )
    recovered_network.start_in_recovery(args, ledger_dir=new_node_ledger_path)
    recovered_network.recover(args)

    new_primary, _ = recovered_network.find_primary()
    with new_primary.client() as c:
        status = c.get(f"/node/tx?transaction_id={latest_txid}").body.json()["status"]
        assert status == "Committed"

    return recovered_network


@reqs.description("Recovering a service, kill one node while submitting shares")
@reqs.recover(number_txs=2)
def test_share_resilience(network, args, from_snapshot=False):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    recovered_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )
    primary, _ = recovered_network.find_primary()
    recovered_network.consortium.transition_service_to_open(
        primary,
        previous_service_identity=slurp_file(args.previous_service_identity_file),
    )

    # Submit all required recovery shares minus one. Last recovery share is
    # submitted after a new primary is found.
    encrypted_submitted_shares_count = 0
    for m in recovered_network.consortium.get_active_members():
        with primary.client() as nc:
            if (
                encrypted_submitted_shares_count
                >= recovered_network.consortium.recovery_threshold - 1
            ):
                last_member_to_submit = m
                break

            check_commit = infra.checker.Checker(nc)
            check_commit(m.get_and_submit_recovery_share(primary))
            encrypted_submitted_shares_count += 1

    LOG.info(
        f"Shutting down node {primary.node_id} before submitting last recovery share"
    )
    primary.stop()
    new_primary, _ = recovered_network.wait_for_new_primary(primary)

    last_member_to_submit.get_and_submit_recovery_share(new_primary)

    for node in recovered_network.get_joined_nodes():
        recovered_network.wait_for_state(
            node,
            infra.node.State.PART_OF_NETWORK.value,
            timeout=args.ledger_recovery_timeout,
        )

    recovered_network.recovery_count += 1
    recovered_network.consortium.check_for_service(
        new_primary,
        infra.network.ServiceStatus.OPEN,
        recovery_count=recovered_network.recovery_count,
    )

    if recovered_network.service_load:
        recovered_network.service_load.set_network(recovered_network)
    return recovered_network


@reqs.description("Recover a service from malformed ledger")
@reqs.recover(number_txs=2)
def test_recover_service_truncated_ledger(network, args, get_truncation_point):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    LOG.info("Force new ledger chunk for app txs to be in committed chunks")
    network.consortium.force_ledger_chunk(old_primary)

    LOG.info(
        "Fill ledger with dummy entries until at least one ledger chunk is not committed, and contains a signature"
    )
    current_ledger_path = old_primary.remote.ledger_paths()[0]
    while True:
        # NB: This is used as an app agnostic write, nothing to do with the large
        # size, or trying to force a chunk
        network.consortium.create_and_withdraw_large_proposal(
            old_primary, wait_for_commit=True
        )
        # A signature will have been emitted by now (wait_for_commit)
        # Wait a little longer so it should have been persisted to disk, but
        # retry if that has produced a committed chunk
        # Also wait long enough to avoid proposal replay protection
        time.sleep(1)
        if not all(
            f.endswith(ccf.ledger.COMMITTED_FILE_SUFFIX)
            for f in os.listdir(current_ledger_path)
        ):
            LOG.warning(
                f"Decided to stop network after looking at ledger dir {current_ledger_path}: {os.listdir(current_ledger_path)}"
            )
            break

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()
    LOG.warning(
        f"Ledger dir after stopping node is {current_ledger_dir}: {os.listdir(current_ledger_dir)}"
    )

    # Corrupt _uncommitted_ ledger before starting new service
    ledger = ccf.ledger.Ledger([current_ledger_dir], committed_only=False)

    chunk_filename, truncate_offset = get_truncation_point(ledger)

    assert truncate_offset is not None, "Should always truncate within tx"

    truncated_ledger_file_path = os.path.join(current_ledger_dir, chunk_filename)

    with open(truncated_ledger_file_path, "r+", encoding="utf-8") as f:
        f.truncate(truncate_offset)
    LOG.warning(
        f"Truncated ledger file {truncated_ledger_file_path} at {truncate_offset}"
    )

    recovered_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    recovered_network.recover(args)

    return recovered_network


def run_corrupted_ledger(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        def get_middle_tx_offset(tx):
            offset, next_offset = tx.get_offsets()
            return offset + (next_offset - offset) // 2

        def all_txs(ledger, verbose):
            for chunk in ledger:
                if verbose:
                    LOG.info(f"Considering chunk {chunk.filename()}")
                for tx in chunk:
                    if verbose:
                        LOG.info(f"Considering tx {tx.get_tx_digest()}")
                    yield chunk, tx

        def corrupt_first_tx(ledger, verbose=False):
            LOG.info("Finding first tx to corrupt")
            for chunk, tx in all_txs(ledger, verbose):
                return chunk.filename(), get_middle_tx_offset(tx)
            return None, None

        def corrupt_last_tx(ledger, verbose=False):
            LOG.info("Finding last tx to corrupt")
            chunk_filename, truncate_offset = None, None
            for chunk, tx in all_txs(ledger, verbose):
                chunk_filename = chunk.filename()
                truncate_offset = get_middle_tx_offset(tx)
            return chunk_filename, truncate_offset

        def corrupt_first_sig(ledger, verbose=False):
            LOG.info("Finding first sig to corrupt")
            for chunk, tx in all_txs(ledger, verbose):
                tables = tx.get_public_domain().get_tables()
                if ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables:
                    return chunk.filename(), get_middle_tx_offset(tx)
            return None, None

        network = test_recover_service_truncated_ledger(network, args, corrupt_first_tx)
        network = test_recover_service_truncated_ledger(network, args, corrupt_last_tx)
        network = test_recover_service_truncated_ledger(
            network, args, corrupt_first_sig
        )

    network.stop_all_nodes()

    # Make sure ledger can be read once recovered (i.e. ledger corruption does not affect recovered ledger)
    for node in network.nodes:
        ledger = ccf.ledger.Ledger(node.remote.ledger_paths(), committed_only=False)
        _, last_seqno = ledger.get_latest_public_state()
        LOG.info(
            f"Successfully read ledger for node {node.local_node_id} up to seqno {last_seqno}"
        )


def find_recovery_tx_seqno(node):
    min_recovery_seqno = 0
    with node.client() as c:
        r = c.get("/node/state").body.json()
        if "last_recovered_seqno" not in r:
            return None
        min_recovery_seqno = r["last_recovered_seqno"]

    ledger = ccf.ledger.Ledger(node.remote.ledger_paths(), committed_only=False)
    for chunk in ledger:
        _, chunk_end_seqno = chunk.get_seqnos()
        if chunk_end_seqno < min_recovery_seqno:
            continue
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()
            seqno = tx.get_public_domain().get_seqno()
            if ccf.ledger.SERVICE_INFO_TABLE_NAME in tables:
                service_status = json.loads(
                    tables[ccf.ledger.SERVICE_INFO_TABLE_NAME][
                        ccf.ledger.WELL_KNOWN_SINGLETON_TABLE_KEY
                    ]
                )["status"]
                if service_status == "Open":
                    return seqno
    return None


def check_snapshots(args, network):
    primary, _ = network.find_primary()
    seqno = find_recovery_tx_seqno(primary)

    if seqno:
        # Check that primary node has produced a snapshot. The wait timeout is larger than the
        # signature interval, so the snapshots should become available within the timeout.
        assert args.sig_ms_interval < 3000
        if not network.get_committed_snapshots(
            primary, target_seqno=True, issue_txs=False
        ):
            raise ValueError(
                f"No snapshot found after seqno={seqno} on primary {primary.local_node_id}"
            )


def run(args):
    recoveries_count = 3

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()

        LOG.info("Check for well-known genesis service TxID")
        with primary.client() as c:
            r = c.get("/node/network").body.json()
            assert ccf.tx_id.TxID.from_str(
                r["current_service_create_txid"]
            ) == ccf.tx_id.TxID(2, 1)

        if args.with_load:
            # See https://github.com/microsoft/CCF/issues/3788 for justification
            LOG.info("Loading service before recovery...")
            primary, _ = network.find_primary()
            with infra.service_load.load() as load:
                load.begin(network, rate=infra.service_load.DEFAULT_REQUEST_RATE_S * 10)
                while True:
                    with primary.client() as c:
                        r = c.get("/node/commit", log_capture=[]).body.json()
                        tx_id = ccf.tx_id.TxID.from_str(r["transaction_id"])
                        if tx_id.seqno > args.sig_tx_interval:
                            LOG.info(f"Loaded service successfully: tx_id, {tx_id}")
                            break
                    time.sleep(0.1)

        ref_msg = get_and_verify_historical_receipt(network, None)

        network = test_persistence_old_snapshot(network, args)
        network = test_recover_service_with_wrong_identity(network, args)

        for i in range(recoveries_count):
            # Issue transactions which will required historical ledger queries recovery
            # when the network is shutdown
            network.txs.issue(network, number_txs=1)
            network.txs.issue(network, number_txs=1, repeat=True)

            # Alternate between recovery with primary change and stable primary-ship,
            # with and without snapshots
            if i % recoveries_count == 0:
                network = test_share_resilience(network, args, from_snapshot=True)
            elif i % recoveries_count == 1:
                network = test_recover_service_aborted(
                    network, args, from_snapshot=False
                )
            else:
                # Vary nodes certificate elliptic curve
                args.curve_id = infra.network.EllipticCurve.secp256r1
                network = test_recover_service(network, args, from_snapshot=False)

            for node in network.get_joined_nodes():
                node.verify_certificate_validity_period()

            check_snapshots(args, network)
            ref_msg = get_and_verify_historical_receipt(network, ref_msg)

            LOG.success("Recovery complete on all nodes")
            # Verify COSE receipt schema and issuer/subject have remained the same
            test_cose_receipt_schema(network, args)

        primary, _ = network.find_primary()
        network.stop_all_nodes()

    # Verify that a new ledger chunk was created at the start of each recovery
    validator = ccf.ledger.LedgerValidator(accept_deprecated_entry_types=False)
    ledger = ccf.ledger.Ledger(
        primary.remote.ledger_paths(),
        committed_only=False,
    )
    for chunk in ledger:
        chunk_start_seqno, _ = chunk.get_seqnos()
        for tx in chunk:
            validator.add_transaction(tx)
            tables = tx.get_public_domain().get_tables()
            seqno = tx.get_public_domain().get_seqno()
            if ccf.ledger.SERVICE_INFO_TABLE_NAME in tables:
                service_status = json.loads(
                    tables[ccf.ledger.SERVICE_INFO_TABLE_NAME][
                        ccf.ledger.WELL_KNOWN_SINGLETON_TABLE_KEY
                    ]
                )["status"]
                if service_status == "Opening" or service_status == "Recovering":
                    LOG.info(
                        f"New ledger chunk found for service {service_status.lower()} at {seqno}"
                    )
                    assert (
                        chunk_start_seqno == seqno
                    ), f"{service_status} service at seqno {seqno} did not start a new ledger chunk (started at {chunk_start_seqno})"


def run_recovery_from_files(args):
    test_recover_service_from_files(
        args,
        directory=args.directory,
        expected_recovery_count=args.expected_recovery_count,
        test_receipt=args.test_receipt,
    )


def test_incomplete_ledger_recovery(network, args):
    # Try to get incomplete pre-recovery ledger files with at least one
    # signature and some unsigned payload following.
    ATTEMPTS = 5

    network.save_service_identity(args)
    primary, _ = network.find_primary()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    network.stop_all_nodes(skip_verification=True)

    for attempt in range(0, ATTEMPTS):
        LOG.info(
            f"Try get incomplete pre-recovery ledger files on primary, attempt=#{attempt}/{ATTEMPTS}"
        )

        network = restart_network(
            network, args, current_ledger_dir, committed_ledger_dirs
        )
        network.save_service_identity(args)

        primary, _ = network.find_primary()
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

        with primary.client("user0") as c:
            for _ in range(100 + 100 * attempt):
                r = c.post(
                    "/app/log/public",
                    {
                        "id": 42,
                        "msg": "Boring recoverable transactions",
                    },
                )
                assert r.status_code == 200, r

        network.stop_all_nodes(skip_verification=True)

        # Calling .get_ledger() after shutdown because it lazy-copies the files.
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

        ledger = ccf.ledger.Ledger(
            primary.remote.ledger_paths(),
            committed_only=False,
        )

        _, last_seqno = ledger.get_latest_public_state()
        last_tx = ledger.get_transaction(last_seqno)

        if "ccf.internal.signatures" in last_tx.get_raw_tx().decode(errors="ignore"):
            LOG.info(
                f"Found signature in last tx {last_tx.get_tx_digest()}, not a suitable candidate for this test"
            )
            continue

        # We've got a suffix with extra payload with no following signature.
        break
    else:
        raise RuntimeError(
            f"Failed to get incomplete pre-recovery ledger files after {ATTEMPTS} attempts"
        )

    network = restart_network(network, args, current_ledger_dir, committed_ledger_dirs)

    primary, _ = network.find_nodes()
    with primary.client("user0") as c:
        for _ in range(10):
            r = c.post(
                "/app/log/public",
                {
                    "id": 42,
                    "msg": "Less boring recoverable transactions",
                },
            )
            assert r.status_code == 200, r

    network.wait_for_all_nodes_to_commit(primary=primary)
    network.save_service_identity(args)
    primary, _ = network.find_primary()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    network.stop_all_nodes(skip_verification=True)

    network.check_ledger_files_identical()

    network = restart_network(network, args, current_ledger_dir, committed_ledger_dirs)
    return network


def run_recover_snapshot_alone(args):
    """
    Recover a service from a snapshot alone, without any ledger files from a previous service.
    """
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()
        # Recover node solely from snapshot
        test_recover_service(network, args, from_snapshot=True, no_ledger=True)
        return network


def run_recovery_with_election(args):
    """
    Recover a service but force election during recovery.
    """
    if not args.with_election:
        return

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        test_recover_service(network, args, force_election=True)
        return network


def run_recovery_with_incomplete_ledger(args):
    """
    Recover a service with incomplete ledger file on a primary which contains unsigned suffix.
    """
    if not args.with_unsigned_suffix:
        return

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        test_incomplete_ledger_recovery(network, args)
        return network


def run_recover_via_initial_recovery_owner(args):
    """
    Recover a service using the recovery owner added as part of service creation, without requiring any other recovery members to participate.
    """
    txs = app.LoggingTxs("user0")
    args.initial_member_count = 4
    args.initial_recovery_participant_count = 3
    args.initial_recovery_owner_count = 1
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        # Recover service using recovery owner and participants
        network = test_recover_service(
            network, args, from_snapshot=True, via_recovery_owner=True
        )
        network = test_recover_service(network, args, from_snapshot=True)
        return network


def run_recover_via_added_recovery_owner(args):
    """
    Recover a service using the recovery owner added after opening the service, without requiring any other recovery members to participate.
    """
    txs = app.LoggingTxs("user0")
    args.initial_recovery_participant_count = 2
    args.initial_recovery_owner_count = 0
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()

        # Add a recovery owner after opening the network
        recovery_owner = network.consortium.generate_and_add_new_member(
            primary,
            curve=args.participants_curve,
            recovery_role=infra.member.RecoveryRole.Owner,
        )
        r = recovery_owner.ack(primary)
        with primary.client() as nc:
            nc.wait_for_commit(r)

        # Recover service using recovery owner and participants
        network = test_recover_service(
            network, args, from_snapshot=True, via_recovery_owner=True
        )
        network = test_recover_service(network, args, from_snapshot=True)
        return network


if __name__ == "__main__":

    def add(parser):
        parser.description = """
This test_recover_service executes multiple recoveries,
with a fixed number of messages applied between each network crash (as
specified by the "--msgs-per-recovery" arg). After the network is recovered
and before applying new transactions, all transactions previously applied are
checked. Note that the key for each logging message is unique (per table).
"""
        parser.add_argument(
            "--msgs-per-recovery",
            help="Number of public and private messages between two recoveries",
            type=int,
            default=5,
        )
        parser.add_argument(
            "--with-load",
            help="If set, the service is loaded before being recovered",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--with-election",
            help="If set, the primary gets killed to force election mid-recovery",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--with-unsigned-suffix",
            help="If set, recover with open-ranged ledger file with unsigned suffix",
            action="store_true",
            default=False,
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "recovery",
        run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=30,
    )

    for directory, expected_recovery_count, test_receipt in (
        ("expired_service", 2, True),
        # sgx_service is historical ledger, from 1.x -> 2.x -> 3.x -> 5.x -> main.
        # This is used to test recovery from SGX to SNP.
        ("sgx_service", 4, False),
        # double_sealed_service is a regression test for the issue described in #6906
        ("double_sealed_service", 2, False),
        # cose_flipflop_service is a regression test for the issue described in #7002
        ("cose_flipflop_service", 0, False),
    ):
        cr.add(
            f"recovery_from_{directory}",
            run_recovery_from_files,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.min_nodes(cr.args, f=1),
            ledger_chunk_bytes="50KB",
            snapshot_tx_interval=30,
            directory=directory,
            expected_recovery_count=expected_recovery_count,
            test_receipt=test_receipt,
            gov_api_version="2024-07-01",
        )

    # Note: `run_corrupted_ledger` runs with very a specific node configuration
    # so that the contents of recovered (and tampered) ledger chunks
    # can be dictated by the test. In particular, the signature interval is large
    # enough to create in-progress ledger files that do not end on a signature. The
    # test is also in control of the ledger chunking.
    cr.add(
        "recovery_corrupt_ledger",
        run_corrupted_ledger,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),  # 1 node suffices for recovery
        sig_ms_interval=1000,
        ledger_chunk_bytes="1GB",
        snapshot_tx_interval=1000000,
    )

    cr.add(
        "recovery_snapshot_alone",
        run_recover_snapshot_alone,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),  # 1 node suffices for recovery
    )

    cr.add(
        "recovery_via_initial_recovery_owner",
        run_recover_via_initial_recovery_owner,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),  # 1 node suffices for recovery
    )

    cr.add(
        "recovery_via_added_recovery_owner",
        run_recover_via_added_recovery_owner,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),  # 1 node suffices for recovery
    )

    cr.add(
        "recovery_with_incomplete_ledger",
        run_recovery_with_incomplete_ledger,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=10000,
    )

    cr.run()
