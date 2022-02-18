# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
from ccf.ledger import NodeStatus
import http
import suite.test_requirements as reqs


from loguru import logger as LOG


@reqs.description("Primary and redirection")
@reqs.at_least_n_nodes(2)
def test_primary(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.head("/node/primary")
        assert r.status_code == http.HTTPStatus.OK.value

    backup = network.find_any_backup()
    for interface_name in backup.host.rpc_interfaces.keys():
        with backup.client(interface_name=interface_name) as c:
            r = c.head("/node/primary", allow_redirects=False)
            assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
            primary_interface = primary.host.rpc_interfaces[interface_name]
            assert (
                r.headers["location"]
                == f"https://{primary_interface.public_host}:{primary_interface.public_port}/node/primary"
            )
            LOG.info(
                f'Successfully redirected to {r.headers["location"]} on primary {primary.local_node_id}'
            )
    return network


@reqs.description("Network node info")
@reqs.at_least_n_nodes(2)
def test_network_node_info(network, args):
    primary, backups = network.find_nodes()

    all_nodes = [primary, *backups]

    with primary.client() as c:
        r = c.get("/node/network/nodes", allow_redirects=False)
        assert r.status_code == http.HTTPStatus.OK
        nodes = r.body.json()["nodes"]
        nodes_by_id = {node["node_id"]: node for node in nodes}
        for n in all_nodes:
            node = nodes_by_id[n.node_id]
            assert infra.interfaces.HostSpec.to_json(n.host) == node["rpc_interfaces"]
            del nodes_by_id[n.node_id]

        assert nodes_by_id == {}

    # Populate node_infos by calling self
    node_infos = {}
    for node in all_nodes:
        for interface_name in node.host.rpc_interfaces.keys():
            primary_interface = primary.host.rpc_interfaces[interface_name]
            with node.client(interface_name=interface_name) as c:
                # /node/network/nodes/self is always a redirect
                r = c.get("/node/network/nodes/self", allow_redirects=False)
                assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                node_interface = node.host.rpc_interfaces[interface_name]
                assert (
                    r.headers["location"]
                    == f"https://{node_interface.public_host}:{node_interface.public_port}/node/network/nodes/{node.node_id}"
                ), r.headers["location"]

                # Following that redirect gets you the node info
                r = c.get("/node/network/nodes/self", allow_redirects=True)
                assert r.status_code == http.HTTPStatus.OK.value
                body = r.body.json()
                assert body["node_id"] == node.node_id
                assert (
                    infra.interfaces.HostSpec.to_json(node.host)
                    == body["rpc_interfaces"]
                )
                assert body["primary"] == (node == primary)

                node_infos[node.node_id] = body

    for node in all_nodes:
        for interface_name in node.host.rpc_interfaces.keys():
            node_interface = node.host.rpc_interfaces[interface_name]
            primary_interface = primary.host.rpc_interfaces[interface_name]
            with node.client(interface_name=interface_name) as c:
                # /node/primary is a 200 on the primary, and a redirect (to a 200) elsewhere
                r = c.head("/node/primary", allow_redirects=False)
                if node != primary:
                    assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                    assert (
                        r.headers["location"]
                        == f"https://{primary_interface.public_host}:{primary_interface.public_port}/node/primary"
                    ), r.headers["location"]
                    r = c.head("/node/primary", allow_redirects=True)

                assert r.status_code == http.HTTPStatus.OK.value

                # /node/network/nodes/primary is always a redirect
                r = c.get("/node/network/nodes/primary", allow_redirects=False)
                assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                actual = r.headers["location"]
                expected = f"https://{node_interface.public_host}:{node_interface.public_port}/node/network/nodes/{primary.node_id}"
                assert actual == expected, f"{actual} != {expected}"

                # Following that redirect gets you the primary's node info
                r = c.get("/node/network/nodes/primary", allow_redirects=True)
                assert r.status_code == http.HTTPStatus.OK.value
                body = r.body.json()
                assert body == node_infos[primary.node_id]

                # Node info can be retrieved directly by node ID, from and about every node, without redirection
                for target_node in all_nodes:
                    r = c.get(
                        f"/node/network/nodes/{target_node.node_id}",
                        allow_redirects=False,
                    )
                    assert r.status_code == http.HTTPStatus.OK.value
                    body = r.body.json()
                    assert body == node_infos[target_node.node_id]

    return network


@reqs.description("Check network/nodes endpoint")
def test_node_ids(network, args):
    nodes = network.get_joined_nodes()
    for node in nodes:
        for _, interface in node.host.rpc_interfaces.items():
            with node.client() as c:
                r = c.get(
                    f"/node/network/nodes?host={interface.public_host}&port={interface.public_port}"
                )

                assert r.status_code == http.HTTPStatus.OK.value
                info = r.body.json()["nodes"]
                assert len(info) == 1
                assert info[0]["node_id"] == node.node_id
                assert info[0]["status"] == NodeStatus.TRUSTED.value
                assert len(info[0]["rpc_interfaces"]) == len(node.host.rpc_interfaces)
    return network


@reqs.description("Memory usage")
def test_memory(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/node/memory")
        assert r.status_code == http.HTTPStatus.OK.value
        assert (
            r.body.json()["peak_allocated_heap_size"]
            <= r.body.json()["max_total_heap_size"]
        )
        assert (
            r.body.json()["current_allocated_heap_size"]
            <= r.body.json()["peak_allocated_heap_size"]
        )
    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        network = test_primary(network, args)
        network = test_network_node_info(network, args)
        network = test_node_ids(network, args)
        network = test_memory(network, args)
