# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Minimal compatibility coverage for deprecated HTTP/1 forwarding."""

import http

import infra.e2e_args
import infra.interfaces
import infra.network
from infra.runner import ConcurrentRunner


def run(args):
    for host in args.nodes:
        for interface in host.rpc_interfaces.values():
            interface.redirections = None
            interface.app_protocol = "HTTP1"
            assert "redirections" not in infra.interfaces.RPCInterface.to_json(
                interface
            )

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, backups = network.find_nodes()
        backup = backups[0]
        with backup.client("user0") as client:
            path = "/app/log/private?scope=legacy-forwarding"
            response = client.post(
                path, {"id": 42, "msg": "Forwarded"}, allow_redirects=False
            )
            assert response.status_code == http.HTTPStatus.OK, response
            network.wait_for_all_nodes_to_commit(primary=primary)
            response = client.get(f"{path}&id=42", allow_redirects=False)
            assert response.status_code == http.HTTPStatus.OK, response
            assert response.body.json()["msg"] == "Forwarded", response
            response = client.post(
                path, {"id": 43, "msg": "Same connection"}, allow_redirects=False
            )
            assert response.status_code == http.HTTPStatus.OK, response


if __name__ == "__main__":
    runner = ConcurrentRunner()
    runner.add(
        "legacy_forwarding",
        run,
        nodes=infra.e2e_args.min_nodes(runner.args, f=1),
    )
    runner.run()
