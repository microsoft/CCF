# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import subprocess


@reqs.description("HTTP fuzzing with ZAP")
@reqs.at_least_n_nodes(1)
def test(network, args):
    node = network.nodes[0]
    openapi_endpoint = f"https://{node.pubhost}:{node.pubport}/node/api"

    args = [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-v",
        f"{args.binary_dir}:/zap/wrk",
        "-t",
        "owasp/zap2docker-stable",
        "zap-api-scan.py",
        "-t",
        openapi_endpoint,
        "-f",
        "openapi",
        "-c",
        "zap.config",
        "-l",
        "INFO",
        "-r",
        "zap_report.html",
    ]

    subprocess.run(args, check=True)


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
