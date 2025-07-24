# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.checker
import infra.jwt_issuer
import infra.proc
import http
import infra.clients
import infra.crypto
from infra.runner import ConcurrentRunner
import copy


def test_forward_larger_than_default_requests(network, args):
    new_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    max_http_body_size=10 * 1024 * 1024,
                    # Deliberately large because some builds (eg. SGX Debug) take
                    # a long time to process large requests
                    forwarding_timeout_ms=8000,
                )
            }
        )
    )
    network.join_node(new_node, args.package, args)
    network.trust_node(new_node, args)

    primary, _ = network.find_primary()

    # Big request, but under the cap
    with primary.client("user0") as c:
        msg = "A" * 512 * 1024
        r = c.post("/app/log/private", {"id": 42, "msg": msg})
        assert r.status_code == http.HTTPStatus.OK.value, r

    # Big request, over the cap for the primary
    with primary.client("user0") as c:
        msg = "A" * 2 * 1024 * 1024
        r = c.post("/app/log/private", {"id": 42, "msg": msg})
        assert r.status_code == http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE.value, r

    # Big request, over the cap for the primary, but under the cap for the new node
    with new_node.client("user0") as c:
        msg = "A" * 2 * 1024 * 1024
        r = c.post("/app/log/private", {"id": 42, "msg": msg})
        assert r.status_code == http.HTTPStatus.OK.value, r


def run_parser_limits_checks(args):
    new_args = copy.copy(args)
    # Deliberately large because some builds take
    # a long time to process large requests
    new_args.election_timeout_ms = 10000
    new_args.log_level = "info"
    with infra.network.network(
        new_args.nodes,
        new_args.binary_dir,
        new_args.debug_nodes,
        new_args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(new_args)

        test_forward_larger_than_default_requests(network, new_args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    if not cr.args.http2:
        # No support for forwarding with HTTP/2
        cr.add(
            "parser_limits",
            run_parser_limits_checks,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        )

    cr.run()
