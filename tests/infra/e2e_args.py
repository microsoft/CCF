# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.path
import infra.network
import sys

from loguru import logger as LOG


def absolute_path_to_existing_file(arg):
    if not os.path.isabs(arg):
        raise argparse.ArgumentTypeError("Must provide absolute path")
    if not os.path.isfile(arg):
        raise argparse.ArgumentTypeError(f"{arg} is not a file")
    return arg


def min_nodes(args, f):
    """
    Minimum number of nodes allowing 'f' faults for the
    consensus variant.
    """
    if args.consensus == "bft":
        return ["local://localhost"] * (3 * f + 1)
    else:
        return ["local://localhost"] * (2 * f + 1)


def max_nodes(args, f):
    """
    Maximum number of nodes allowing no more than 'f'
    faults for the consensus variant.
    """
    return min_nodes(args, f + 1)[:-1]


def cli_args(add=lambda x: None, parser=None, accept_unknown=False):
    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<green>{time:HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )

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
        "--oe-binary",
        help="Path to Open Enclave binary folder",
        type=str,
        default="/opt/openenclave/bin/",
    )
    parser.add_argument(
        "--library-dir",
        help="Path to CCF libraries (enclave images)",
        default=None,
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
        "-p",
        "--package",
        help="The enclave package to load (e.g., liblogging)",
    )
    parser.add_argument(
        "-g",
        "--gov-script",
        help="Path to governance script",
        type=absolute_path_to_existing_file,
    )
    parser.add_argument("-j", "--js-app-script", help="Path to js app script")
    parser.add_argument("--js-app-bundle", help="Path to js app bundle")
    parser.add_argument(
        "--jwt-issuer",
        help="Path to JSON file with JWT issuer definition",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-o",
        "--network-only",
        help="Only start the network, do not run the client, and wait.",
        action="store_true",
    )
    parser.add_argument(
        "--sig-tx-interval",
        help="Number of transactions between signatures",
        type=int,
        default=5000,
    )
    parser.add_argument(
        "--sig-ms-interval",
        help="Milliseconds between signatures",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--memory-reserve-startup",
        help="Reserve this many bytes of memory on startup, to simulate memory restrictions",
        type=int,
    )
    parser.add_argument(
        "--raft-election-timeout-ms",
        help="Raft maximum election timeout for each node in the network",
        type=int,
        default=4000,
    )
    parser.add_argument(
        "--bft-view-change-timeout-ms",
        help="bft maximum view change timeout for each node in the network",
        type=int,
        default=5000,
    )
    parser.add_argument(
        "--consensus",
        help="Consensus",
        default="cft",
        choices=("cft", "bft"),
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
        "--sn",
        help="Subject Name in node certificate, eg. CN=CCF Node",
    )
    parser.add_argument(
        "--san",
        help="Subject Alternative Name in node certificate. Can be either iPAddress:xxx.xxx.xxx.xxx, or dNSName:sub.domain.tld",
        action="append",
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
        help="Number of members when initializing the network",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--initial-operator-count",
        help="Number of additional members with is_operator set in their member_data when initializing the network",
        type=int,
        default=0,
    )
    parser.add_argument(
        "--initial-user-count",
        help="Number of users when initializing the network",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--initial-recovery-member-count",
        help="Number of initial members that are handed recovery shares",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--ledger-recovery-timeout",
        help="On recovery, maximum timeout (s) while reading the ledger",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--ledger-chunk-bytes",
        help="Size (bytes) at which a new ledger chunk is created",
        default="20KB",
    )
    parser.add_argument(
        "--snapshot-tx-interval",
        help="Number of transactions between two snapshots",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--jwt-key-refresh-interval-s",
        help="JWT key refresh interval in seconds",
        default=None,
    )
    parser.add_argument(
        "--disable-member-session-auth",
        help="Disable session auth for members",
        action="store_true",
    )
    parser.add_argument(
        "--common-read-only-ledger-dir",
        help="Location of read-only ledger directory available to all nodes",
        type=str,
        default=None,
    )

    add(parser)

    if accept_unknown:
        args, unknown_args = parser.parse_known_args()
    else:
        args = parser.parse_args()

    args.binary_dir = os.path.abspath(args.binary_dir)

    if args.library_dir is None:
        if os.path.basename(args.binary_dir) == "bin":
            args.library_dir = os.path.join(args.binary_dir, os.pardir, "lib")
        else:
            args.library_dir = args.binary_dir

    # js_app_script is deprecated
    if not args.package and (args.js_app_script or args.js_app_bundle):
        args.package = "libjs_generic"

    if accept_unknown:
        return args, unknown_args
    else:
        return args
