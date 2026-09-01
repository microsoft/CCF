# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import json
import os
import re
import sys
from pathlib import Path

from loguru import logger as LOG

import infra.interfaces
import infra.network
import infra.path

# Every argument registered directly by cli_args must appear here. None means
# that no single host configuration schema property applies to the argument.
CLI_ARGUMENT_CONFIG_PATHS = {
    "binary_dir": None,
    "library_dir": None,
    "debug_nodes": None,
    "log_level": None,
    "log_format_json": "logging.format",
    "package": None,
    "constitution": None,
    "js_app_bundle": None,
    "jwt_issuer": None,
    "jwt_key_refresh_max_response_size": "jwt.key_refresh_max_response_size",
    "network_only": None,
    "sig_tx_interval": "ledger_signatures.tx_count",
    "sig_ms_interval": "ledger_signatures.delay",
    "memory_reserve_startup": None,
    "election_timeout_ms": "consensus.election_timeout",
    "consensus_update_timeout_ms": "consensus.message_timeout",
    "worker_threads": "worker_threads",
    "pdb": None,
    "workspace": None,
    "label": None,
    "perf_label": None,
    "throws_if_reqs_not_met": None,
    "subject_name": "node_certificate.subject_name",
    "subject_alt_names": None,
    "participants_curve": None,
    "join_timer_s": "command.join.retry_timeout",
    "initial_member_count": None,
    "initial_operator_provisioner_count": None,
    "initial_operator_count": None,
    "initial_user_count": None,
    "initial_recovery_participant_count": None,
    "initial_recovery_owner_count": None,
    "ledger_recovery_timeout": None,
    "ledger_chunk_bytes": "ledger.chunk_size",
    "ledger_max_transaction_bytes": "ledger.max_transaction_size",
    "snapshot_tx_interval": "snapshots.tx_count",
    "snapshot_min_tx_interval": "snapshots.min_tx_count",
    "snapshot_time_interval": "snapshots.time_interval",
    "max_open_sessions": "network.rpc_interfaces.*.max_open_sessions_soft",
    "max_open_sessions_hard": "network.rpc_interfaces.*.max_open_sessions_hard",
    "jwt_key_refresh_interval_s": "jwt.key_refresh_interval",
    "common_read_only_ledger_dir": None,
    "curve_id": "node_certificate.curve_id",
    "ccf_version": None,
    "initial_node_cert_validity_days": "node_certificate.initial_validity_days",
    "initial_service_cert_validity_days": (
        "command.start.initial_service_certificate_validity_days"
    ),
    "maximum_node_certificate_validity_days": (
        "command.start.service_configuration.maximum_node_certificate_validity_days"
    ),
    "maximum_service_certificate_validity_days": (
        "command.start.service_configuration.maximum_service_certificate_validity_days"
    ),
    "reconfiguration_type": None,
    "previous_service_identity_file": None,
    "config_file": None,
    "max_http_body_size": ("network.rpc_interfaces.*.http_configuration.max_body_size"),
    "max_http_header_size": (
        "network.rpc_interfaces.*.http_configuration.max_header_size"
    ),
    "max_http_headers_count": (
        "network.rpc_interfaces.*.http_configuration.max_headers_count"
    ),
    "http2": "network.rpc_interfaces.*.app_protocol",
    "snp_endorsements_servers": None,
    "forwarding_timeout_ms": "network.rpc_interfaces.*.forwarding_timeout_ms",
    "tick_ms": "tick_interval",
    "max_msg_size_bytes": "memory.max_msg_size",
    "gov_api_version": None,
}

_TIME_UNITS_IN_US = {
    "us": 1,
    "ms": 1000,
    "s": 1000 * 1000,
    "min": 60 * 1000 * 1000,
    "h": 60 * 60 * 1000 * 1000,
}

_SIZE_UNITS_IN_BYTES = {
    "B": 1,
    "KB": 1024,
    "MB": 1024 * 1024,
    "GB": 1024 * 1024 * 1024,
    "TB": 1024 * 1024 * 1024 * 1024,
}


def _convert_time_string(value, target_unit):
    match = re.fullmatch(r"(\d+)(us|ms|s|min|h)", value)
    if match is None:
        raise ValueError(f"Invalid time string in host config schema: {value}")

    source_value, source_unit = match.groups()
    value_in_us = int(source_value) * _TIME_UNITS_IN_US[source_unit]
    target_unit_in_us = _TIME_UNITS_IN_US[target_unit]
    if value_in_us % target_unit_in_us != 0:
        raise ValueError(
            f"Host config default {value} cannot be represented in {target_unit}"
        )
    return value_in_us // target_unit_in_us


def _convert_size_string_to_bytes(value):
    match = re.fullmatch(r"(\d+)(B|KB|MB|GB|TB)?", value)
    if match is None:
        raise ValueError(f"Invalid size string in host config schema: {value}")

    source_value, source_unit = match.groups()
    return int(source_value) * _SIZE_UNITS_IN_BYTES[source_unit or "B"]


def _convert_curve_id(value):
    return infra.network.EllipticCurve[value.lower()]


_CONFIG_DEFAULT_CONVERTERS = {
    "log_format_json": lambda value: value == "Json",
    "sig_ms_interval": lambda value: _convert_time_string(value, "ms"),
    "election_timeout_ms": lambda value: _convert_time_string(value, "ms"),
    "consensus_update_timeout_ms": lambda value: _convert_time_string(value, "ms"),
    "join_timer_s": lambda value: _convert_time_string(value, "s"),
    "jwt_key_refresh_interval_s": lambda value: _convert_time_string(value, "s"),
    "curve_id": _convert_curve_id,
    "max_http_body_size": _convert_size_string_to_bytes,
    "max_http_header_size": _convert_size_string_to_bytes,
    "http2": lambda value: value == "HTTP2",
    "tick_ms": lambda value: _convert_time_string(value, "ms"),
}


def _load_host_config_schema():
    candidates = (
        Path(__file__).with_name("host_config.json"),
        Path(__file__).parents[2] / "doc/host_config_schema/host_config.json",
    )
    for candidate in candidates:
        if candidate.is_file():
            with candidate.open(encoding="utf-8") as schema_file:
                return json.load(schema_file)

    raise FileNotFoundError(
        "Cannot find host configuration schema in "
        + " or ".join(str(candidate) for candidate in candidates)
    )


def _get_schema_property(schema, config_path):
    current = schema
    for name in config_path.split("."):
        if name == "*":
            additional_properties = current.get("additionalProperties")
            if not isinstance(additional_properties, dict):
                raise KeyError(
                    f"Expected additionalProperties while resolving {config_path}"
                )
            current = additional_properties
            continue

        matches = []
        properties = current.get("properties", {})
        if name in properties:
            matches.append(properties[name])

        for condition in current.get("allOf", []):
            for branch_name in ("then", "else"):
                branch = condition.get(branch_name, {})
                branch_properties = branch.get("properties", {})
                if name in branch_properties:
                    matches.append(branch_properties[name])

        if len(matches) != 1:
            raise KeyError(
                f"Expected one schema property for {config_path}, found {len(matches)}"
            )
        current = matches[0]

    return current


def _apply_host_config_metadata(
    parser,
    use_host_config_defaults=False,
    additional_cli_argument_config_paths=None,
):
    schema = _load_host_config_schema()
    argument_config_paths = CLI_ARGUMENT_CONFIG_PATHS.copy()
    if additional_cli_argument_config_paths:
        duplicate_arguments = (
            argument_config_paths.keys() & additional_cli_argument_config_paths.keys()
        )
        if duplicate_arguments:
            raise ValueError(
                "Additional host configuration mappings duplicate CLI arguments: "
                + ", ".join(sorted(duplicate_arguments))
            )
        argument_config_paths.update(additional_cli_argument_config_paths)

    actions = {action.dest: action for action in parser._actions}
    actions.pop("help", None)
    unmapped_arguments = actions.keys() - argument_config_paths.keys()
    missing_arguments = argument_config_paths.keys() - actions.keys()
    if (use_host_config_defaults and unmapped_arguments) or missing_arguments:
        errors = []
        if use_host_config_defaults and unmapped_arguments:
            errors.append(
                "CLI arguments missing host configuration mappings: "
                + ", ".join(sorted(unmapped_arguments))
            )
        if missing_arguments:
            errors.append(
                "Host configuration mappings without CLI arguments: "
                + ", ".join(sorted(missing_arguments))
            )
        raise ValueError("; ".join(errors))

    for destination, config_path in argument_config_paths.items():
        if config_path is None:
            continue
        config_property = _get_schema_property(schema, config_path)
        required_metadata = {"description"}
        if use_host_config_defaults:
            required_metadata.add("default")
        missing_metadata = required_metadata - config_property.keys()
        if missing_metadata:
            raise KeyError(
                f"Host config schema property {config_path} for CLI argument "
                f"{destination} is missing: {', '.join(sorted(missing_metadata))}"
            )
        actions[destination].help = config_property["description"]
        if use_host_config_defaults:
            converter = _CONFIG_DEFAULT_CONVERTERS.get(destination, lambda value: value)
            actions[destination].default = converter(config_property["default"])


_LOG_LEVEL_DISPLAY = {
    "TRACE": "TRC ",
    "DEBUG": "DBG ",
    "INFO": "INFO",
    "SUCCESS": "SUCC",
    "WARNING": "WARN",
    "ERROR": "ERR ",
    "CRITICAL": "CRIT",
}

_LOG_MESSAGE_MARKERS = {
    "SUCCESS": "\u2705 ",
    "WARNING": "\u26a0\ufe0f ",
    "ERROR": "\u274c ",
}


def format_log_record(record, include_thread=False):
    level_name = record["level"].name
    display_level = _LOG_LEVEL_DISPLAY[level_name]
    marker = _LOG_MESSAGE_MARKERS.get(level_name, "")
    time_format = "YYYY-MM-DD HH:mm:ss.SSS" if include_thread else "HH:mm:ss.SSS"
    thread = "{{{thread.name}}} " if include_thread else ""
    return (
        f"{{time:{time_format}}} | {display_level} | {thread}"
        f"{{name}}:{{function}}:{{line}} - {marker}{{message}}\n{{exception}}"
    )


def absolute_path_to_existing_file(arg):
    if not os.path.isabs(arg):
        raise argparse.ArgumentTypeError("Must provide absolute path")
    if not os.path.isfile(arg):
        raise argparse.ArgumentTypeError(f"{arg} is not a file")
    return arg


def nodes(args, n):
    return [infra.interfaces.HostSpec().with_args(args) for _ in range(n)]


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
    use_host_config_defaults=False,
    additional_cli_argument_config_paths=None,
):
    LOG.remove()
    LOG.add(
        sys.stdout,
        format=format_log_record,
    )

    if parser is None:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument(
        "-b",
        "--binary-dir",
        help="Path to CCF binaries (node executable, scurl, keygenerator)",
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
    log_level_choices = ("trace", "debug", "info", "fail", "fatal")
    default_log_level = "info"
    parser.add_argument(
        "--log-level",
        help="Runtime log level",
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
        help="The enclave package to load (e.g., logging)",
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
        "--jwt-key-refresh-max-response-size",
        help="Maximum response body size accepted when fetching JWT issuer OpenID metadata and JWKS",
        default="1MB",
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
        # _GLIBCXX_DEBUG significantly slows down ledger replay, so allow
        # more time when running tests against a debug build.
        default=120 if os.getenv("CCF_GLIBCXX_DEBUG") else 30,
    )
    parser.add_argument(
        "--ledger-chunk-bytes",
        help="Size (bytes) at which a new ledger chunk is created",
        type=str,
        default=ledger_chunk_bytes_override or "20KB",
    )
    parser.add_argument(
        "--ledger-max-transaction-bytes",
        help=(
            "Maximum total serialised ledger entry size, including its header "
            "(size string)"
        ),
        type=str,
        default="32MB",
    )
    parser.add_argument(
        "--snapshot-tx-interval",
        help="Number of transactions between two snapshots",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--snapshot-min-tx-interval",
        help="Minimum number of transactions before a time-based snapshot can trigger",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--snapshot-time-interval",
        help="Time interval after which a snapshot should be triggered (e.g. 30s, 5min)",
        type=str,
        default="0s",
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
        default=(["THIM:$Fabric_NodeIPOrFQDN:2377"]),
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
        default=infra.clients.API_VERSION_LATEST,
    )
    add(parser)

    _apply_host_config_metadata(
        parser,
        use_host_config_defaults=use_host_config_defaults,
        additional_cli_argument_config_paths=additional_cli_argument_config_paths,
    )

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
        args.package = "js_generic"

    if accept_unknown:
        return args, unknown_args
    else:
        return args
