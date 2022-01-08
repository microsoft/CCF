# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import subprocess
import os


def cond_removal(file):
    if os.path.exists(file):
        os.remove(file)


@reqs.description("Running TLS test against CCF")
@reqs.at_least_n_nodes(1)
def test(network, args):
    node = network.nodes[0]
    endpoint = f"https://{node.get_public_rpc_host()}:{node.get_public_rpc_port()}"
    cond_removal("tls_report.csv")
    cond_removal("tls_report.html")
    cond_removal("tls_report.json")
    cond_removal("tls_report.log")
    r = subprocess.run(
        ["testssl/testssl.sh", "--outfile", "tls_report", endpoint], check=False
    )
    assert r.returncode == 0


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        test(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.nodes(args, 1)
    run(args)
