# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os


def cli_args(add=lambda x: None, parser=None, accept_unknown=False):
    if parser is None:
        parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--build-dir", help="Build directory", default=".")
    parser.add_argument(
        "-d",
        "--debug-nodes",
        help="List of node ids. Nodes that are specified will need to be started manually",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--perf-nodes",
        help="List of node ids. Nodes that should be run under perf, capturing performance data",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-e",
        "--enclave-type",
        help="Enclave type",
        default=os.getenv("TEST_ENCLAVE", "debug"),
        choices=("simulate", "debug", "virtual"),
    )
    parser.add_argument(
        "-l",
        "--log-level",
        help="Runtime log level",
        default="info",
        choices=("trace", "debug", "info", "fail", "fatal"),
    )
    parser.add_argument(
        "-g", "--gov-script", help="Path to governance script", required=True
    )
    parser.add_argument("-s", "--app-script", help="Path to app script")
    parser.add_argument(
        "-q",
        "--expect-quote",
        help="Expect a quote when starting node.",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--network-only",
        help="Only start the network, do not run the client, and wait.",
        action="store_true",
    )
    parser.add_argument(
        "--sig-max-tx", help="Max transactions between signatures", type=int
    )
    parser.add_argument(
        "--sig-max-ms", help="Max milliseconds between signatures", type=int
    )
    parser.add_argument(
        "--memory-reserve-startup",
        help="Reserve this many bytes of memory on startup, to simulate memory restrictions",
        type=int,
    )
    parser.add_argument(
        "--wait-with-client",
        help="If set, the python client is used to query joining nodes",
        action="store_true",
    )
    parser.add_argument(
        "--node-status", help="pending, trusted, retired", type=str, action="append"
    )
    parser.add_argument(
        "--election-timeout",
        help="Maximum election timeout for each node in the network",
        type=int,
        default=100000,
    )
    parser.add_argument(
        "--pdb", help="Break to debugger on exception", action="store_true"
    )
    parser.add_argument(
        "--notify-server", help="Server host to notify progress to (host:port)"
    )
    add(parser)

    if accept_unknown:
        return parser.parse_known_args()
    else:
        return parser.parse_args()
