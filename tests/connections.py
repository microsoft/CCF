# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
import infra.proc

import e2e_args
import getpass
import os
import time
import logging
import multiprocessing
from random import seed
import infra.ccf
import infra.proc
import infra.jsonrpc
import json
import contextlib
import resource
import psutil

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        primary_pid = primary.remote.remote.proc.pid
        max_fds = 50
        num_fds = psutil.Process(primary_pid).num_fds()
        LOG.info(f"{primary_pid} has {num_fds} open file descriptors")

        resource.prlimit(primary_pid, resource.RLIMIT_NOFILE, (max_fds, max_fds))
        LOG.info(f"set max fds to {max_fds} on {primary_pid}")

        nb_conn = max_fds - num_fds
        clients = []

        with contextlib.ExitStack() as es:
            for i in range(nb_conn - 1):
                clients.append(es.enter_context(primary.user_client(format="json")))
                LOG.info(f"Connected client {i}")
            
            num_fds = psutil.Process(primary_pid).num_fds()
            LOG.info(f"{primary_pid} has {num_fds} open file descriptors")
            LOG.info(f"Disconnecting clients")
        
        time.sleep(1)
        num_fds = psutil.Process(primary_pid).num_fds()
        LOG.info(f"{primary_pid} has {num_fds} open file descriptors")

        clients = []
        with contextlib.ExitStack() as es:
            for i in range(nb_conn - 1):
                clients.append(es.enter_context(primary.user_client(format="json")))
                LOG.info(f"Connected client {i}")
            
            num_fds = psutil.Process(primary_pid).num_fds()
            LOG.info(f"{primary_pid} has {num_fds} open file descriptors")
            LOG.info(f"Disconnecting clients")

        time.sleep(1)
        num_fds = psutil.Process(primary_pid).num_fds()
        LOG.info(f"{primary_pid} has {num_fds} open file descriptors")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libloggingenc)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)
    run(args)
