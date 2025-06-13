# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import subprocess
import signal
import sys
import time
import os

from loguru import logger as LOG


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        targets = [
            f"https://{n.get_public_rpc_address()}" for n in network.get_joined_nodes()
        ]
        cli = [sys.executable, "../tests/tvc.py"]
        for target in targets:
            cli.append("-t")
            cli.append(target)
        cli.append("--ca")
        cli.append(network.cert_path)

        # Create consistency-specific output directory
        output_dir = os.path.join("consistency")
        os.makedirs(output_dir, exist_ok=True)

        with open("consistency/trace.ndjson", "w") as trace_file:
            LOG.info(f"Starting {' '.join(cli)} > {trace_file.name}")
            tvc = subprocess.Popen(cli, stdout=trace_file)
            # Do some normal transactions
            time.sleep(2)
            # Suspend the primary long enough to cause an election
            primary, _ = network.find_primary()
            primary.suspend()
            time.sleep(network.election_duration * 2)
            primary.resume()
            # Do some more transactions
            time.sleep(5)
            tvc.poll()
            if tvc.returncode is not None:
                raise Exception(f"tvc failed with rc {tvc.returncode}")
            tvc.send_signal(signal.SIGINT)
            tvc.wait()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.js_app_bundle = "../samples/apps/basic_tv/js/"
    args.nodes = infra.e2e_args.nodes(args, 3)
    # Long signature interval to maximise the chance of an InvalidStatus transaction
    args.sig_ms_interval = 1000
    run(args)
