# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
from ccf.ledger import NodeStatus
import http
import random
import suite.test_requirements as reqs


from loguru import logger as LOG


@reqs.description("Primary and redirection")
@reqs.at_least_n_nodes(2)
def test_primary(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.head("/node/primary")
        assert r.status_code == http.HTTPStatus.OK.value
        r = c.get("/node/primary")
        assert r.status_code == http.HTTPStatus.OK.value
        r = c.get("/node/backup")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value
        assert r.body.json()["error"]["code"] == "ResourceNotFound"
        assert r.body.json()["error"]["message"] == "Node is not backup"

    interface_name = "only_exists_on_this_node"
    host_spec = infra.interfaces.HostSpec(
        rpc_interfaces={
            infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface.from_args(
                args
            ).parse_from_str(
                "local://localhost"
            ),
            interface_name: infra.interfaces.RPCInterface.from_args(
                args
            ).parse_from_str("local://localhost"),
        }
    )
    new_backup = network.create_node(host_spec)
    network.join_node(new_backup, args.package, args)
    network.trust_node(new_backup, args)

    primary_interfaces = primary.host.rpc_interfaces
    for interface_name in new_backup.host.rpc_interfaces.keys():
        LOG.info(f"Testing interface {interface_name}")
        with new_backup.client(interface_name=interface_name) as c:
            r = c.head("/node/primary", allow_redirects=False)

            if interface_name in primary_interfaces:
                assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                primary_interface = primary_interfaces[interface_name]
                assert (
                    r.headers["location"]
                    == f"https://{primary_interface.public_host}:{primary_interface.public_port}/node/primary"
                )
                LOG.info(
                    f'Successfully redirected to {r.headers["location"]} on primary {primary.local_node_id}'
                )
            else:
                # If there is no matching interface name on the primary, then we cannot redirect and return an error
                assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value

            r = c.get("/node/primary", allow_redirects=False)
            assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r
            assert r.body.json()["error"]["code"] == "ResourceNotFound"
            assert r.body.json()["error"]["message"] == "Node is not primary"

            r = c.get("/node/backup", allow_redirects=False)
            assert r.status_code == http.HTTPStatus.OK.value, r

    network.retire_node(primary, new_backup)
    new_backup.stop()

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
                r = c.get("/node/network/nodes/self", allow_redirects=False)
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
            primary_interface = primary.host.rpc_interfaces[interface_name]
            with node.client(interface_name=interface_name) as c:
                # HEAD /node/primary is a 200 on the primary, and a redirect (to a 200) elsewhere
                r = c.head("/node/primary", allow_redirects=False)
                if node != primary:
                    assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                    assert (
                        r.headers["location"]
                        == f"https://{primary_interface.public_host}:{primary_interface.public_port}/node/primary"
                    ), r.headers["location"]
                    r = c.head("/node/primary", allow_redirects=True)
                assert r.status_code == http.HTTPStatus.OK.value

                r = c.get("/node/network/nodes/primary", allow_redirects=False)
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

    # Create a PENDING node and check that /node/network/nodes/self
    # returns the correct information from configuration
    operator_rpc_interface = "operator_rpc_interface"
    host = infra.net.expand_localhost()
    new_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    host=host, app_protocol="HTTP2" if args.http2 else "HTTP1"
                ),
                operator_rpc_interface: infra.interfaces.RPCInterface(
                    host=host,
                    app_protocol="HTTP2" if args.http2 else "HTTP1",
                    endorsement=infra.interfaces.Endorsement(
                        authority=infra.interfaces.EndorsementAuthority.Node
                    ),
                ),
            }
        )
    )
    network.join_node(new_node, args.package, args)

    with new_node.client(interface_name=operator_rpc_interface) as c:
        r = c.get("/node/network/nodes/self", allow_redirects=False)
        assert r.status_code == http.HTTPStatus.OK.value
        body = r.body.json()
        assert body["node_id"] == new_node.node_id
        assert (
            infra.interfaces.HostSpec.to_json(new_node.host) == body["rpc_interfaces"]
        )
        assert body["status"] == NodeStatus.PENDING.value
        assert body["primary"] is False
    new_node.stop()

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


@reqs.description("Frontend readiness")
def test_readiness(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/node/ready/app")
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r
        r = c.get("/node/ready/gov")
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r

    return network


@reqs.description("Write/Read large messages on primary")
def test_large_messages(network, args):
    primary, _ = network.find_primary()

    def get_main_interface_errors():
        with primary.client() as c:
            return c.get("/node/metrics").body.json()["sessions"]["interfaces"][
                infra.interfaces.PRIMARY_RPC_INTERFACE
            ]["errors"]

    def run_large_message_test(
        threshold,
        expected_status,
        expected_code,
        metrics_name,
        length,
        *args,
        **kwargs,
    ):
        with primary.client("user0") as client:
            before_errors_count = get_main_interface_errors()[metrics_name]
            # Note: endpoint does not matter as request parsing is done before dispatch
            try:
                r = client.get(
                    "/node/commit",
                    *args,
                    **kwargs,
                )
            except infra.clients.CCFIOException:
                # In some cases, the client ends up writing to the now-closed socket first
                # before reading the server error, resulting in a connection error
                assert length > threshold
                assert (
                    get_main_interface_errors()[metrics_name] == before_errors_count + 1
                )
            else:
                if length > threshold:
                    assert r.status_code == expected_status.value
                    assert r.body.json()["error"]["code"] == expected_code
                    assert (
                        get_main_interface_errors()[metrics_name]
                        == before_errors_count + 1
                    )
                else:
                    assert r.status_code == http.HTTPStatus.OK.value
                    assert (
                        get_main_interface_errors()[metrics_name] == before_errors_count
                    )

    def get_sizes(n, http2):
        ns = [n // 2, n - 10, n - 1, n, n + 1, n + 10, n * 2]
        if not http2:
            # nghttp2 does not currently allow header larger than 64KB
            # https://github.com/nghttp2/nghttp2/issues/1841
            ns.append(n * 20)
        random.shuffle(ns)
        return ns

    for s in get_sizes(args.max_http_body_size, args.http2):
        long_msg = "X" * s
        LOG.info(f"Verifying cap on max body size, sending a {s} byte body")
        run_large_message_test(
            args.max_http_body_size,
            http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "RequestBodyTooLarge",
            "request_payload_too_large",
            len(long_msg),
            long_msg,
            headers={"content-type": "application/json"},
        )

    for s in get_sizes(args.max_http_header_size, args.http2):
        long_header = "X" * s
        LOG.info(f"Verifying cap on max header value, sending a {s} byte header value")
        run_large_message_test(
            args.max_http_header_size,
            http.HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
            "RequestHeaderTooLarge",
            "request_header_too_large",
            len(long_header),
            headers={"some-header": long_header},
        )

        LOG.info(f"Verifying on cap on max header key, sending a {s} byte header key")
        run_large_message_test(
            args.max_http_header_size,
            http.HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
            "RequestHeaderTooLarge",
            "request_header_too_large",
            len(long_header),
            headers={long_header: "some header value"},
        )

    # Note: infra generally inserts extra headers (eg, content type and length, user-agent, accept)
    extra_headers_count = infra.clients.CCFClient.default_impl_type.extra_headers_count(
        args.http2
    )
    for s in get_sizes(args.max_http_headers_count, args.http2):
        LOG.info(f"Verifying on cap on max headers count, sending {s} headers")
        headers = {f"header-{h}": str(h) for h in range(s - extra_headers_count)}
        run_large_message_test(
            args.max_http_headers_count,
            http.HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
            "RequestHeaderTooLarge",
            "request_header_too_large",
            len(headers) + extra_headers_count,
            headers=headers,
        )

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        test_primary(network, args)
        test_network_node_info(network, args)
        test_node_ids(network, args)
        test_memory(network, args)
        test_large_messages(network, args)
        test_readiness(network, args)
