# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import time

from loguru import logger as LOG


def run(args):
    hosts = args.nodes or ["localhost", "localhost"]

    with infra.ccf.network(hosts, args.build_dir, args.debug_nodes) as network:
        primary, followers = network.start_and_join(args)

        LOG.info("Network started")
        LOG.info("Primary node is at {}:{}".format(primary.host, primary.tls_port))

        LOG.info("Started network with the following nodes:")
        LOG.info("  Primary = {}:{}".format(primary.pubhost, primary.tls_port))
        for i, f in enumerate(followers):
            LOG.info("  Follower[{}] = {}:{}".format(i, f.pubhost, f.tls_port))

        try:
            while True:
                time.sleep(60)

        except KeyboardInterrupt:
            LOG.info("Terminating")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-n",
            "--nodes",
            help="List of hostnames[,pub_hostnames:ports]. If empty, two nodes are spawned locally",
            action="append",
        )
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libloggingenc)",
            required=True,
        )

    args = e2e_args.cli_args(add)
    run(args)
