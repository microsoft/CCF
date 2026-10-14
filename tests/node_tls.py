# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http

import infra.e2e_args
import infra.interfaces
import infra.network
from infra.runner import ConcurrentRunner


def run(args):
    for host, mode in zip(args.nodes, args.node_modes):
        host.node_to_node_interface = {}
        if mode in ("legacy", "bridge"):
            host.node_to_node_interface["bind_address"] = "127.0.0.1:0"
        if mode in ("tls", "bridge"):
            host.node_to_node_interface["tls_bind_address"] = "127.0.0.1:0"
        host.rpc_interfaces[infra.interfaces.PRIMARY_RPC_INTERFACE].redirections = (
            infra.interfaces.RedirectionConfig(
                to_primary=infra.interfaces.NodeByRoleResolver()
            )
        )

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        def replicate(identifier):
            primary, backups = network.find_nodes()
            message = f"{args.node_modes} replication {identifier}"
            with primary.client("user0") as client:
                response = client.post(
                    "/app/log/private", {"id": identifier, "msg": message}
                )
                assert response.status_code == http.HTTPStatus.OK, response
            for node in network.get_joined_nodes():
                with node.client("user0") as client:
                    client.wait_for_commit(response)
                    result = client.get(f"/app/log/private?id={identifier}")
                    assert result.status_code == http.HTTPStatus.OK, result
                    assert result.body.json()["msg"] == message
            with backups[0].client("user0") as client:
                result = client.post(
                    "/app/log/private",
                    {"id": identifier + 100, "msg": "redirect"},
                    allow_redirects=False,
                )
                assert result.status_code == http.HTTPStatus.TEMPORARY_REDIRECT
            return primary

        original_primary = replicate(1)
        for node, mode in zip(network.nodes, args.node_modes):
            out, _ = node.get_logs()
            with open(out, encoding="utf-8") as log:
                contents = log.read()
            if mode == "tls":
                assert "Node TLS 1.3 mutually authenticated with " in contents
                assert "Node transport legacy received from " not in contents
            if "tls" not in args.node_modes:
                assert "Node TLS 1.3 mutually authenticated with " not in contents
        if args.node_modes == ["bridge", "legacy", "tls"]:
            # This intentionally non-fully-connected topology only replicates
            # while the bridge is primary. There is no transparent routing
            # between the incompatible legacy-only and TLS-only nodes.
            assert original_primary == network.nodes[0]
            out, _ = original_primary.get_logs()
            with open(out, encoding="utf-8") as log:
                contents = log.read()
            assert (
                f"Node transport legacy received from n[{network.nodes[1].node_id}]"
                in contents
            )
            assert (
                f"Node transport TLS received from n[{network.nodes[2].node_id}]"
                in contents
            )
            replicate(2)
        else:
            original_primary.stop()
            network.wait_for_new_primary(original_primary)
            replicate(2)


if __name__ == "__main__":
    runner = ConcurrentRunner()
    for name, modes in (
        ("legacy", ["legacy"] * 3),
        ("tls", ["tls"] * 3),
        ("bridge_star", ["bridge", "legacy", "tls"]),
        ("mixed", ["bridge", "bridge", "tls"]),
        ("tls_primary_mixed", ["tls", "bridge", "bridge"]),
        ("all_bridge", ["bridge"] * 3),
    ):
        runner.add(
            name,
            run,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.min_nodes(runner.args, f=1),
            node_modes=modes,
        )
    runner.run()
