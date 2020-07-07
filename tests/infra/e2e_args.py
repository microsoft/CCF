# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.path
import infra.network
import sys


def cli_args(add=lambda x: None, parser=None, accept_unknown=False):
    if parser is None:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument(
        "-b",
        "--binary-dir",
        help="Path to CCF binaries (cchost, scurl, keygenerator)",
        default=".",
    )
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
        default=os.getenv("TEST_ENCLAVE", os.getenv("DEFAULT_ENCLAVE_TYPE", "release")),
        choices=("release", "debug", "virtual"),
    )
    parser.add_argument(
        "-l",
        "--host-log-level",
        help="Runtime host log level",
        default="info",
        choices=("trace", "debug", "info", "fail", "fatal"),
    )
    parser.add_argument(
        "--log-format-json",
        help="Set node stdout log format to JSON",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-g", "--gov-script", help="Path to governance script",
    )
    parser.add_argument("-s", "--app-script", help="Path to app script")
    parser.add_argument("-j", "--js-app-script", help="Path to js app script")
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
        "--raft-election-timeout",
        help="Raft maximum election timeout for each node in the network",
        type=int,
        default=100000,
    )
    parser.add_argument(
        "--pbft-view-change-timeout",
        help="Pbft maximum view change timeout for each node in the network",
        type=int,
        default=5000,
    )
    parser.add_argument(
        "--consensus", help="Consensus", default="raft", choices=("raft", "pbft"),
    )
    parser.add_argument(
        "--worker-threads",
        help="number of worker threads inside the enclave",
        type=int,
        default=0,
    )
    parser.add_argument(
        "--pdb", help="Break to debugger on exception", action="store_true"
    )
    parser.add_argument(
        "--notify-server", help="Server host to notify progress to (host:port)"
    )
    parser.add_argument(
        "--workspace",
        help="Temporary directory where nodes store their logs, ledgers, quotes, etc.",
        default=infra.path.default_workspace(),
    )

    default_label = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    parser.add_argument(
        "--label", help="Unique identifier for the test", default=default_label
    )
    parser.add_argument(
        "--enforce-reqs",
        help="Enforce test requirements (useful when running the test suite)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--domain",
        help="Domain name used for node certificate verification, eg. example.com",
    )
    parser.add_argument(
        "--participants-curve",
        help="Curve to use for member and user identities",
        default=infra.network.ParticipantsCurve.secp384r1.name,
        type=lambda curve: infra.network.ParticipantsCurve[curve],
        choices=list(infra.network.ParticipantsCurve),
    )
    parser.add_argument(
        "--join-timer",
        help="Timer period when trying to join an existing network (ms)",
        type=int,
        default=4000,  # Set higher than cchost default to avoid swamping joinee with requests during slow quote verification
    )
    parser.add_argument(
        "--initial-member-count",
        help="Number of members when intializing the network",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--initial-user-count",
        help="Number of users when intializing the network",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--ledger-recovery-timeout",
        help="On recovery, maximum timeout (s) while reading the ledger",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--ledger-chunk-max-bytes",
        help="Minimum size (bytes) at which a new ledger chunk is created.",
        default="20KB",
    )

    add(parser)

    if accept_unknown:
        return parser.parse_known_args()
    else:
        return parser.parse_args()
