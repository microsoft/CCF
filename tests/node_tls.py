# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http

import infra.e2e_args
import infra.interfaces
import infra.network
from infra.runner import ConcurrentRunner


def run(args):
    for host in args.nodes:
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
            message = f"{args.node_to_node_transport} replication {identifier}"
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
        if args.node_to_node_transport == "tls":
            for node in network.get_joined_nodes():
                out, _ = node.get_logs()
                with open(out, encoding="utf-8") as log:
                    assert "Node TLS 1.3 mutually authenticated with " in log.read()
        original_primary.stop()
        network.wait_for_new_primary(original_primary)
        replicate(2)


if __name__ == "__main__":
    runner = ConcurrentRunner()
    for transport in ("legacy", "tls"):
        runner.add(
            transport,
            run,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.min_nodes(runner.args, f=1),
            node_to_node_transport=transport,
            node_to_node_tls_record_limit=4,
        )
    runner.run()
