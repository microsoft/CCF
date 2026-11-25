# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import datetime
import http
import time

import infra.e2e_args
import infra.interfaces
import infra.network
from infra.runner import ConcurrentRunner


def exercise_traffic(network, first_id):
    """Write through every replica, then read the replicated private ledger."""
    nodes = network.get_joined_nodes()
    for offset, node in enumerate(nodes):
        record_id = first_id + offset
        message = f"n2n-{record_id}-" + "x" * (128 * 1024)
        with node.client("user0") as client:
            response = client.post(
                "/app/log/private",
                {"id": record_id, "msg": message},
                allow_redirects=False,
            )
            assert response.status_code == http.HTTPStatus.OK, response
            client.wait_for_commit(response)
        primary, _ = network.find_primary()
        network.wait_for_all_nodes_to_commit(primary=primary)
        for replica in nodes:
            with replica.client("user0") as client:
                response = client.get(f"/app/log/private?id={record_id}")
                assert response.status_code == http.HTTPStatus.OK, response
                assert response.body.json()["msg"] == message


def assert_tls_streams(network):
    """Observe authenticated real N2N streams, not just endpoint metadata."""
    primary, _ = network.find_primary()
    for node in network.get_joined_nodes():
        tls = node.host.node_to_node_tls_interface
        with primary.client() as client:
            response = client.get(f"/node/network/nodes/{node.node_id}")
            assert response.status_code == http.HTTPStatus.OK, response
            recorded = response.body.json().get("node_to_node_tls_interface")
            assert (recorded is not None) == (tls is not None), response
        if node == primary:
            continue
        should_use_tls = (
            tls is not None and primary.host.node_to_node_tls_interface is not None
        )
        stdout, _ = node.get_logs()
        deadline = time.monotonic() + 5
        while True:
            with open(stdout, encoding="utf-8") as logs:
                text = logs.read()
            consensus = f"authenticated n[{primary.node_id}] (ccf-consensus/1)"
            forwarding = f"authenticated n[{primary.node_id}] (ccf-forwarding/1)"
            if not should_use_tls or (consensus in text and forwarding in text):
                break
            assert time.monotonic() < deadline, text
            time.sleep(0.1)
        if not should_use_tls:
            assert consensus not in text and forwarding not in text


def run(args):
    for host in args.nodes:
        for interface in host.rpc_interfaces.values():
            interface.redirections = None
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        exercise_traffic(network, 100)
        assert_tls_streams(network)

        primary, _ = network.find_primary()
        valid_from = datetime.datetime.now(datetime.UTC).isoformat()
        network.consortium.set_all_nodes_certificate_validity(primary, valid_from, 30)
        network.consortium.set_service_certificate_validity(primary, valid_from, 30)
        network.consortium.trigger_ledger_rekey(primary)
        exercise_traffic(network, 200)

        # Idle expiry must be recoverable on both forwarding and consensus
        # streams. Consensus remains busy, but forwarding is idle here.
        time.sleep(args.election_timeout_ms * 4 / 1000 + 1)
        exercise_traffic(network, 300)

        replacement = network.create_node(args.nodes[0])
        network.join_node(
            replacement,
            args.package,
            args,
            from_snapshot=False,
            node_id_format="did:key",
        )
        assert replacement.node_id.startswith("did:key:")
        network.trust_node(replacement, args)
        exercise_traffic(network, 400)
        assert_tls_streams(network)
        network.retire_node(primary, primary)
        primary.stop()
        network.wait_for_new_primary(primary)
        exercise_traffic(network, 500)

        # Recover encrypted ledger state into fresh service/node identities.
        primary, _ = network.find_primary()
        network.save_service_identity(args)
        network.stop_all_nodes()
        ledger, committed = primary.get_ledger()
        with infra.network.network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            pdb=args.pdb,
            existing_network=network,
        ) as recovered:
            recovered.start_in_recovery(
                args, ledger_dir=ledger, committed_ledger_dirs=committed
            )
            recovered.recover(args)
            for node in recovered.get_joined_nodes():
                with node.client("user0") as client:
                    response = client.get("/app/log/private?id=500")
                    assert response.status_code == http.HTTPStatus.OK, response
                    assert response.body.json()["msg"].startswith("n2n-500-")
            exercise_traffic(recovered, 600)
            assert_tls_streams(recovered)


if __name__ == "__main__":
    runner = ConcurrentRunner()
    runner.args.package = "samples/apps/logging/logging"
    hosts = infra.e2e_args.nodes(runner.args, 3)
    for host in hosts:
        host.node_to_node_tls_interface = infra.interfaces.NodeToNodeInterface(
            host=host.get_primary_interface().host
        )
    runner.add(
        "tls",
        run,
        nodes=hosts,
        snapshot_tx_interval=100,
        node_to_node_message_limit=8,
    )
    runner.run()
