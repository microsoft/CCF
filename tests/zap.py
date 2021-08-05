# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import subprocess
import os


@reqs.description("HTTP fuzzing with ZAP")
@reqs.at_least_n_nodes(1)
def test(network, args):
    node = network.nodes[0]
    openapi_endpoint = f"https://127.0.0.1:{node.pubport}/node/api"

    vm_binary_dir = args.binary_dir
    local_path = os.getenv("BUILD_REPOSITORY_LOCALPATH")
    if local_path:
        vm_path = local_path.replace("__w", "mnt/vss/_work")
        vm_binary_dir = args.binary_dir.replace(local_path, vm_path)

    args = [
        "sudo",
        "docker",
        "run",
        "--rm",
        "-v",
        f"{vm_binary_dir}:/zap/wrk",
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
    args.nodes = ["local://127.0.0.1:45000"]
    run(args)
