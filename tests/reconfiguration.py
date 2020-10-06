# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import time

from loguru import logger as LOG


def node_configs(network):
    configs = {}
    for node in network.nodes:
        try:
            with node.client() as nc:
                configs[node.node_id] = nc.get("/node/config").body.json()
        except Exception:
            pass
    return configs


def count_nodes(configs, network):
    nodes = set(str(k) for k in configs.keys())
    stopped = {str(n.node_id) for n in network.nodes if n.is_stopped()}
    for node_id, node_config in configs.items():
        nodes_in_config = set(node_config.keys()) - stopped
        assert nodes == nodes_in_config, f"{nodes} {nodes_in_config} {node_id}"
    return len(nodes)


def check_can_progress(node, timeout=3):
    with node.client() as c:
        r = c.get("/node/commit")
        with node.client("user0") as uc:
            uc.post("/app/log/private", {"id": 42, "msg": "Hello world"})
        end_time = time.time() + timeout
        while time.time() < end_time:
            if c.get("/node/commit").body.json()["seqno"] > r.body.json()["seqno"]:
                return
            time.sleep(0.1)
        assert False, f"Stuck at {r}"


@reqs.description("Adding a valid node from primary")
def test_add_node(network, args):
    new_node = network.create_and_trust_node(args.package, "localhost", args)
    with new_node.client() as c:
        s = c.get("/node/state")
        assert s.body.json()["id"] == new_node.node_id
    assert new_node
    return network


@reqs.description("Adding a valid node from a backup")
@reqs.at_least_n_nodes(2)
def test_add_node_from_backup(network, args):
    backup = network.find_any_backup()
    new_node = network.create_and_trust_node(
        args.package, "localhost", args, target_node=backup
    )
    assert new_node
    return network


@reqs.description("Adding a valid node from snapshot")
@reqs.at_least_n_nodes(2)
def test_add_node_from_snapshot(network, args):
    new_node = network.create_and_trust_node(
        args.package, "localhost", args, from_snapshot=True
    )
    assert new_node
    return network


@reqs.description("Adding as many pending nodes as current number of nodes")
@reqs.supports_methods("log/private")
def test_add_as_many_pending_nodes(network, args):
    # Should not change the raft consensus rules (i.e. majority)
    number_new_nodes = len(network.nodes)
    LOG.info(
        f"Adding {number_new_nodes} pending nodes - consensus rules should not change"
    )

    for _ in range(number_new_nodes):
        network.create_and_add_pending_node(args.package, "localhost", args)
    check_can_progress(network.find_primary()[0])
    return network


@reqs.description("Add node with untrusted code version")
def test_add_node_untrusted_code(network, args):
    if args.enclave_type != "virtual":
        LOG.info("Adding an invalid node (unknown code id)")
        code_not_found_exception = None
        try:
            network.create_and_add_pending_node(
                "liblua_generic", "localhost", args, timeout=3
            )
        except infra.network.CodeIdNotFound as err:
            code_not_found_exception = err

        assert (
            code_not_found_exception is not None
        ), "Adding node with unknown code id should fail"

    else:
        LOG.warning("Skipping unknown code id test with virtual enclave")
    return network


@reqs.description("Retiring a backup")
@reqs.at_least_n_nodes(2)
def test_retire_backup(network, args):
    primary, _ = network.find_primary()
    backup_to_retire = network.find_any_backup()
    network.consortium.retire_node(primary, backup_to_retire)
    backup_to_retire.stop()
    return network


@reqs.description("Retiring the primary")
@reqs.can_kill_n_nodes(1)
def test_retire_primary(network, args):
    pre_count = count_nodes(node_configs(network), network)

    primary, backup = network.find_primary_and_any_backup()
    network.consortium.retire_node(primary, primary)
    new_primary, new_term = network.wait_for_new_primary(primary.node_id)
    LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")
    check_can_progress(backup)
    network.nodes.remove(primary)
    post_count = count_nodes(node_configs(network), network)
    assert pre_count == post_count + 1
    primary.stop()
    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        if args.snapshot_tx_interval is not None:
            test_add_node_from_snapshot(network, args)

        test_add_node_from_backup(network, args)
        test_add_node(network, args)
        test_add_node_untrusted_code(network, args)
        test_retire_backup(network, args)
        test_add_as_many_pending_nodes(network, args)
        test_add_node(network, args)
        test_retire_primary(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
