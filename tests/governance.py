# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import http
import subprocess
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import infra.logging_app as app

from loguru import logger as LOG


@reqs.description("Test quotes")
@reqs.supports_methods("quote", "quotes")
def test_quote(network, args, verify=True):
    primary, _ = network.find_nodes()
    with primary.client() as c:
        oed = subprocess.run(
            [
                args.oesign,
                "dump",
                "-e",
                infra.path.build_lib_path(args.package, args.enclave_type),
            ],
            capture_output=True,
            check=True,
        )
        lines = [
            line
            for line in oed.stdout.decode().split(os.linesep)
            if line.startswith("mrenclave=")
        ]
        expected_mrenclave = lines[0].strip().split("=")[1]

        r = c.get("/node/quote")
        quotes = r.body["quotes"]
        assert len(quotes) == 1
        primary_quote = quotes[0]
        assert primary_quote["node_id"] == 0
        primary_mrenclave = primary_quote["mrenclave"]
        assert primary_mrenclave == expected_mrenclave, (
            primary_mrenclave,
            expected_mrenclave,
        )

        r = c.get("/node/quotes")
        quotes = r.body["quotes"]
        assert len(quotes) == len(network.find_nodes())
        for quote in quotes:
            mrenclave = quote["mrenclave"]
            assert mrenclave == expected_mrenclave, (mrenclave, expected_mrenclave)

    return network


@reqs.description("Add user, remove user")
@reqs.supports_methods("log/private")
def test_user(network, args, verify=True):
    primary, _ = network.find_nodes()
    new_user_id = 3
    network.create_users([new_user_id], args.participants_curve)
    user_data = {"lifetime": "temporary"}
    network.consortium.add_user(primary, new_user_id, user_data)
    txs = app.LoggingTxs(user_id=3)
    txs.issue(
        network=network,
        number_txs=1,
        consensus=args.consensus,
    )
    if verify:
        txs.verify(network)
    network.consortium.remove_user(primary, new_user_id)
    with primary.client(f"user{new_user_id}") as c:
        r = c.get("/app/log/private")
        assert r.status_code == http.HTTPStatus.FORBIDDEN.value
    return network


@reqs.description("Add untrusted node, check no quote is returned")
def test_no_quote(network, args, notifications_queue=None, verify=True):
    untrusted_node = network.create_and_add_pending_node(
        args.package, "localhost", args
    )
    with untrusted_node.client(
        ca=os.path.join(untrusted_node.common_dir, f"{untrusted_node.node_id}.pem")
    ) as uc:
        r = uc.get("/node/quote")
        assert r.status_code == http.HTTPStatus.NOT_FOUND


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "bft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_quote(network, args)
        network = test_user(network, args)
        network = test_no_quote(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--oesign", help="Path oesign binary", type=str, required=True
        )

    args = infra.e2e_args.cli_args(add=add)

    if args.enclave_type == "virtual":
        LOG.warning("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    run(args)
