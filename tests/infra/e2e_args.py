# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.interfaces
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


def nodes(args, n):
    return [
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface.from_args(
                    args
                )
            }
        )
        for _ in range(n)
    ]


def min_nodes(args, f):
    """
    Minimum number of nodes allowing 'f' faults
    """
    n = 2 * f + 1
    return nodes(args, n)


def max_nodes(args, f):
    """
    Maximum number of nodes allowing no more than 'f'
    faults for the consensus variant.
    """
    return min_nodes(args, f + 1)[:-1]


def max_f(args, number_nodes):
    return (number_nodes - 1) // 2


def default_platform():
    return "virtual"


def cli_args(
    add=lambda x: None,
    parser=None,
    accept_unknown=False,
    ledger_chunk_bytes_override=None,
):
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
    # "virtual" is deprecated (use enclave-platform)
    parser.add_argument(
        "-e",
        "--enclave-type",
        help="Enclave type",
        default=os.getenv("TEST_ENCLAVE", os.getenv("DEFAULT_ENCLAVE_TYPE", "release")),
        choices=("release", "debug", "virtual"),
    )
    parser.add_argument(
        "-t",
        "--enclave-platform",
        help="Enclave platform (Trusted Execution Environment)",
        default=os.getenv(
            "TEST_ENCLAVE", os.getenv("DEFAULT_ENCLAVE_PLATFORM", default_platform())
        ),
        choices=("sgx", "snp", "virtual"),
    )
    log_level_choices = ("trace", "debug", "info", "fail", "fatal")
    default_log_level = "info"
    parser.add_argument(
        "--host-log-level",
        help="Runtime host log level",
        default=default_log_level,
        choices=log_level_choices,
    )
    parser.add_argument(
        "--enclave-log-level",
        help="Runtime enclave log level",
        default=default_log_level,
        choices=log_level_choices,
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
        "--constitution",
        help="One or more paths to constitution script fragments",
        action="append",
        default=[],
    )
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
        default=100,
    )
    parser.add_argument(
        "--memory-reserve-startup",
        help="Reserve this many bytes of memory on startup, to simulate memory restrictions",
        type=int,
    )
    parser.add_argument(
        "--election-timeout-ms",
        help="Raft maximum election timeout for each node in the network",
        type=int,
        default=os.getenv("ELECTION_TIMEOUT_MS") or 4000,
    )
    parser.add_argument(
        "--consensus-update-timeout-ms",
        help="Raft maximum timeout before primary sends updates",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--consensus",
        help="Consensus",
        default="CFT",
        choices=("CFT",),
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
        default=os.getenv("WORKSPACE", os.path.join(os.getcwd(), "workspace")),
    )

    default_label = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    parser.add_argument(
        "--label",
        help="Unique identifier for the test. Must be a valid directory name.",
        default=default_label,
    )
    parser.add_argument(
        "--perf-label",
        help="Performance test label, not necessarily unique, nor a valid directory name.",
    )
    parser.add_argument(
        "--throws-if-reqs-not-met",
        help="Throws if test requirements are not met, skip test otherwise",
        action="store_true",
        default=True,
    )
    parser.add_argument(
        "--subject-name",
        help="Subject Name in node certificate, eg. CN=CCF Node",
        default="CN=CCF Node",
    )
    parser.add_argument(
        "--subject-alt-names",
        help="Subject Alternative Name in node certificate. Can be either iPAddress:xxx.xxx.xxx.xxx, or dNSName:sub.domain.tld",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--participants-curve",
        help="Curve to use for member and user identities",
        default=infra.network.EllipticCurve.secp384r1.name,
        type=lambda curve: infra.network.EllipticCurve[curve],
        choices=list(infra.network.EllipticCurve),
    )
    parser.add_argument(
        "--join-timer-s",
        help="Timer period when trying to join an existing network",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--initial-member-count",
        help="Number of members when initializing the network",
        type=int,
        default=int(os.getenv("INITIAL_MEMBER_COUNT", "3")),
    )
    parser.add_argument(
        "--initial-operator-provisioner-count",
        help="Number of additional members with is_operator_provisioner set in their member_data when initializing the network",
        type=int,
        default=0,
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
        "--initial-recovery-participant-count",
        help="Number of initial members that are handed partial recovery shares",
        type=int,
        default=int(os.getenv("INITIAL_MEMBER_COUNT", "3")),
    )
    parser.add_argument(
        "--initial-recovery-owner-count",
        help="Number of initial members that are handed full recovery shares",
        type=int,
        default=int(os.getenv("INITIAL_RECOVERY_OWNER_COUNT", "0")),
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
        type=str,
        default=ledger_chunk_bytes_override or "20KB",
    )
    parser.add_argument(
        "--snapshot-tx-interval",
        help="Number of transactions between two snapshots",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--max-open-sessions",
        help="Soft cap on max open TLS sessions on each node",
        default=1000,
    )
    parser.add_argument(
        "--max-open-sessions-hard",
        help="Hard cap on max open TLS sessions on each node",
        default=1010,
    )
    parser.add_argument(
        "--jwt-key-refresh-interval-s",
        help="JWT key refresh interval in seconds",
        type=int,
        default=1800,
    )
    parser.add_argument(
        "--common-read-only-ledger-dir",
        help="Location of read-only ledger directory available to all nodes",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--curve-id",
        help="Elliptic curve to use as for node and network identities",
        default=infra.network.EllipticCurve.secp384r1,
        type=lambda curve: infra.network.EllipticCurve[curve],
        choices=list(infra.network.EllipticCurve),
    )
    parser.add_argument(
        "--ccf-version",
        help="CCF version of local checkout",
        type=str,
    )
    parser.add_argument(
        "--initial-node-cert-validity-days",
        help="Initial validity period in days for certificates of nodes before the first certificate renewal",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--initial-service-cert-validity-days",
        help="Initial validity period in days for service certificate before the first certificate renewal",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--maximum-node-certificate-validity-days",
        help="Maximum allowed validity period in days for certificates of trusted nodes",
        type=int,
        default=365,
    )
    parser.add_argument(
        "--maximum-service-certificate-validity-days",
        help="Maximum allowed validity period in days for service certificate",
        type=int,
        default=365,
    )
    parser.add_argument(
        "--reconfiguration-type",
        help="Reconfiguration type",
        default="OneTransaction",
        choices=("OneTransaction", "TwoTransaction"),
    )
    parser.add_argument(
        "--previous-service-identity-file",
        help="Path to previous service identity file",
        type=str,
        default="",
    )
    parser.add_argument(
        "--config-file",
        help="Absolute path to node JSON configuration file",
        default=None,
    )
    parser.add_argument(
        "--max-http-body-size",
        help="Maximum allowed size for body of single HTTP request",
        default=1024 * 1024,  # 1MB
    )
    parser.add_argument(
        "--max-http-header-size",
        help="Maximum allowed size of single header in single HTTP request",
        default=1024 * 16,  # 16KB
    )
    parser.add_argument(
        "--max-http-headers-count",
        help="Maximum number of headers in single HTTP request",
        default=256,
        type=int,
    )
    parser.add_argument(
        "--http2",
        help="Enable HTTP/2 for all interfaces",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--snp-endorsements-servers",
        help="Servers used to retrieve attestation report endorsement certificates (AMD SEV-SNP only)",
        action="append",
        # ACI default
        default=(
            ["THIM:$Fabric_NodeIPOrFQDN:2377"]
            if os.getenv("DEFAULT_ENCLAVE_PLATFORM") == "snp"
            else []
        ),
    )
    parser.add_argument(
        "--forwarding-timeout-ms",
        help="Timeout for forwarded RPC calls (in milliseconds)",
        type=int,
        default=infra.interfaces.DEFAULT_FORWARDING_TIMEOUT_MS,
    )
    parser.add_argument(
        "--tick-ms",
        help="Tick period (in milliseconds)",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--max-msg-size-bytes",
        help="Maximum message size (bytes) allowed on the ring buffer",
        type=str,
        default="64MB",
    )
    parser.add_argument(
        "--gov-api-version",
        help="api-version to be used for accessing /gov endpoints",
        type=str,
        default=infra.clients.API_VERSION_01,
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

    if not args.package and args.js_app_bundle:
        args.package = "libjs_generic"

    if accept_unknown:
        return args, unknown_args
    else:
        return args
