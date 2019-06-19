# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import time
import socket
import infra.ccf
from subprocess import check_call, Popen
from contextlib import contextmanager
from random import randrange as rr
from glob import glob

import e2e_args
from loguru import logger as LOG


def verify_quote(args, host, quote_path, quoted_path, should_fail=False):

    verifying_node_id = 0
    with infra.ccf.node(
        verifying_node_id, host, args.build_dir, False, False, False, True
    ) as verifying_node:

        failed = False
        try:
            verifying_node.start(
                args.package,
                args.enclave_type,
                args.workspace,
                args.label,
                quote_path,
                quoted_path,
            )
            failed = should_fail
        except RuntimeError:
            failed = not should_fail
        finally:
            if failed:
                raise RuntimeError("Quote verification did not behave as expected")


def run(args):

    host = "localhost"
    node_id_1 = 1
    node_id_2 = 2

    with infra.ccf.node(node_id_1, host, args.build_dir) as node1:
        node1.start(args.package, args.enclave_type, args.workspace, args.label)

        with infra.ccf.node(node_id_2, host, args.build_dir) as node2:
            node2.start(args.package, args.enclave_type, args.workspace, args.label)

            node1_quote_path = node1.remote.get_quote()
            node1_cert_path = node1.remote.get_cert()
            node2_quote_path = node2.remote.get_quote()
            node2_cert_path = node2.remote.get_cert()

            verify_quote(args, host, node1_quote_path, node1_cert_path)
            verify_quote(args, host, node2_quote_path, node2_cert_path)
            verify_quote(args, host, node1_quote_path, node2_cert_path, True)
            verify_quote(args, host, node2_quote_path, node1_cert_path, True)


if __name__ == "__main__":
    args = e2e_args.cli_args()

    if args.enclave_type != "debug":
        LOG.error("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "libloggingenc"
    run(args)
