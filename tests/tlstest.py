# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import getpass
import time
import logging
import shutil
import infra.ccf
import infra.proc
import infra.notification
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import subprocess

from loguru import logger as LOG


@reqs.description("Running TLS test against CCF")
@reqs.at_least_n_nodes(1)
def test(network, args, notifications_queue=None):
    node = network.nodes[0]
    endpoint = f"https://{node.host}:{node.rpc_port}"
    r = subprocess.run(["testssl/testssl.sh", "--outfile", "tls_report", endpoint])
    assert r.returncode == 0


def run(args):
    hosts = ["localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:
        notifications_queue = (
            notifications.get_queue()
            if (args.package == "liblogging" and args.consensus == "raft")
            else None
        )

        with infra.ccf.network(
            hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            network.start_and_join(args)
            test(network, args, notifications_queue)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script or "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
