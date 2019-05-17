# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import getpass
import time
import logging
import multiprocessing
import shutil
import subprocess
from random import seed
import infra.ccf
import infra.proc
import infra.jsonrpc
import infra.notification
import infra.net
import e2e_args

from loguru import logger as LOG


def wait_for_node_commit_sync(nodes):
    """
    Wait for commit level to get in sync on all nodes. This is expected to
    happen once CFTR has been established, in the absence of new transactions.
    """
    for _ in range(3):
        commits = []
        for node in nodes:
            with node.management_client() as c:
                id = c.request("getCommit", {})
                commits.append(c.response(id).commit)
        if [commits[0]] * len(commits) == commits:
            break
        time.sleep(1)
    assert [commits[0]] * len(commits) == commits, "All nodes at the same commit"


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            primary, (follower,) = network.start_and_join(args)

            with primary.management_client() as mc:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()
                r = mc.rpc("getQuotes", {})
                mrenclave = r.result["quotes"]["0"]["parsed"]["mrenclave"].decode()

                oed = subprocess.run(
                    [args.oesign, "dump", "-e", f"{args.package}.so.signed"],
                    capture_output=True,
                    check=True,
                )
                lines = [
                    line
                    for line in oed.stdout.decode().split(os.linesep)
                    if line.startswith("mrenclave=")
                ]
                expected_mrenclave = lines[0].strip().split("=")[1]
                assert mrenclave == expected_mrenclave, (mrenclave, expected_mrenclave)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--oesign", help="Path oesign binary", type=str, required=True
        )

    args = e2e_args.cli_args(add=add)
    args.package = "libloggingenc"
    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
