# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import subprocess


@reqs.description("Running TLS test against CCF")
@reqs.at_least_n_nodes(1)
def test(network, args):
    node = network.nodes[0]
    endpoint = f"https://{node.pubhost}:{node.pubport}"
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
    args.package = "liblogging"
    args.nodes = ["local://localhost"]
    run(args)
