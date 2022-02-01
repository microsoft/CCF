# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import configparser
import sys
import json
from typing import Dict, Any

from loguru import logger as LOG


DEFAULT_OUTPUT_PATH = "2_x_config.json"
DEFAULT_INI_SECTION = "default"
DEFAULT_RPC_INTERFACE_NAME = "primary_rpc_interface"


SECTIONS_2_X = [
    "enclave",
    "network",
    "node_certificate",
    "command",
    "ledger",
    "snapshots",
    "logging",
    "consensus",
    "ledger_signatures",
    "jwt",
    "memory",
    "output_files",
]

DEFAULT_MAX_RPC_SESSIONS_SOFT = 1000


def human_readable_size(n):
    suffixes = ("B", "KB", "MB", "GB")
    i = 0
    while n >= 1024 and i < len(suffixes) - 1:
        n //= 1024
        i += 1
    return f"{n}{suffixes[i]}"


def make_key_json_compatible(key):
    return key.replace("-", "_")


def split_member_info(member_info_str):
    cert_file, *other = member_info_str.split(",")
    member = {"certificate_file": cert_file}
    if not other:
        return member
    elif other[0]:
        member["encryption_public_key_file"] = other[0]

    if len(other) > 1 and other[1]:
        member["data_json_file"] = other[1]

    return member


if __name__ == "__main__":

    input_path = sys.argv[1]
    try:
        output_path = sys.argv[2]
    except IndexError:
        output_path = DEFAULT_OUTPUT_PATH
    LOG.info(f"Reading 1.x configuration file: {input_path}")

    # configparser requires section for all entries to make one up
    # before parsing config file
    with open(input_path, encoding="utf-8") as f:
        input_file = f"[{DEFAULT_INI_SECTION}]" + f.read()
    config = configparser.RawConfigParser(strict=False)
    config.read_string(input_file)
    LOG.debug(f"Found sections: {config.sections()}")

    # Init output
    output: Dict[str, Any] = {}
    for s in SECTIONS_2_X:
        output[s] = {}
    output["network"]["rpc_interfaces"] = {}
    output["network"]["node_to_node_interface"] = {}
    output["network"]["rpc_interfaces"][DEFAULT_RPC_INTERFACE_NAME] = {
        "max_open_sessions_soft": DEFAULT_MAX_RPC_SESSIONS_SOFT,
        "max_open_sessions_hard": DEFAULT_MAX_RPC_SESSIONS_SOFT + 10,
    }
    output["command"]["start"] = {}
    output["command"]["start"]["constitution_files"] = []
    output["command"]["start"]["members"] = []
    output["command"]["start"]["service_configuration"] = {
        "maximum_node_certificate_validity_days": 365
    }
    output["command"]["join"] = {}
    output["command"]["type"] = "Start" if "start" in config.sections() else "Join"

    LOG.info(f'Command type: {output["command"]["type"]}')

    for s in config.sections():
        for k_, v_ in config.items(s):
            k = make_key_json_compatible(k_)
            v = v_.strip('"')
            rpc_interface = output["network"]["rpc_interfaces"][
                DEFAULT_RPC_INTERFACE_NAME
            ]

            # sub-commands
            # start
            if k == "constitution":
                output["command"]["start"]["constitution_files"] = json.loads(v)
            elif k == "member_info":
                for m in json.loads(v):
                    output["command"]["start"]["members"].append(split_member_info(m))
            elif k == "recovery_threshold":
                output["command"]["start"]["service_configuration"][k] = int(v)
            # join
            elif k == "target_rpc_address":
                output["command"][s][k] = v
            elif k == "join_timer":
                output["command"][s]["retry_timeout"] = f"{v}ms"

            # enclave
            elif k == "enclave_file":
                output["enclave"]["file"] = v
            elif k == "enclave_type":
                output["enclave"]["type"] = v.title()

            # network
            elif k == "rpc_address":
                rpc_interface["bind_address"] = v
            elif k == "public_rpc_address":
                rpc_interface["published_address"] = v
            elif k == "max_open_sessions":
                rpc_interface["max_open_sessions_soft"] = int(v)
                rpc_interface["max_open_sessions_soft"] = int(v) + 10
            elif k == "node_address":
                output["network"]["node_to_node_interface"]["bind_address"] = v
            elif k == "network_cert_file":
                output["service_certificate_file"] = v

            # node certificate
            elif k == "san":
                output["node_certificate"][k] = json.loads(v)
            elif k == "sn":
                output["node_certificate"][k] = v
            elif k == "curve_id":
                output["node_certificate"][k] = v.title()

            # ledger
            elif k == "ledger_dir":
                output["ledger"]["directory"] = v
            elif k == "read_only_ledger_dir":
                output["ledger"]["read_only_directories"] = [v]
            elif k == "ledger_chunk_bytes":
                output["ledger"]["chunk_size"] = human_readable_size(int(v))

            # snapshots
            elif k == "snapshot_dir":  # plural
                output["snapshots"]["directory"] = v
            elif k == "snapshot_tx_interval":
                output["snapshots"]["tx_count"] = int(v)

            # logging
            elif k == "log_format_json":
                output["logging"]["log_format"] = "Json" if bool(v) else "Text"
            elif k == "host_log_level":
                output["logging"]["host_level"] = v.title()

            # consensus
            elif k == "consensus":
                output["consensus"]["type"] = str.upper(v)
            elif k == "raft_timeout_ms":
                output["consensus"]["message_timeout"] = f"{v}ms"
            elif k == "raft_election_timeout_ms":
                output["consensus"]["election_timeout"] = f"{v}ms"

            elif k == "sig_tx_interval":
                output["ledger_signatures"]["tx_count"] = int(v)
            elif k == "sig_ms_interval":
                output["ledger_signatures"]["delay"] = f"{v}ms"
            elif k == "jwt_key_refresh_interval_s":
                output["jwt"]["key_refresh_interval"] = f"{v}s"

            # memory
            elif "size" in k:
                # Remove shift suffix if it exists
                suffix = "_shift"
                k = k[: -len(suffix)] if k.endswith(suffix) else k
                output["memory"][k] = f"{human_readable_size(1 << int(v))}"

            # output files
            elif k == "node_cert_file":
                output["output_files"]["node_certificate_file"] = v
            elif k == "node_pid_file":
                output["output_files"]["pid_file"] = v
            elif k == "rpc_address_file":
                output["output_files"]["rpc_addresses_file"] = v
            elif k == "node_address_file":
                output["output_files"]["node_to_node_address_file"] = v

            elif k == "tick_period_ms":
                output["tick_interval"] = f"{v}ms"

            elif k == "worker_threads":
                output[k] = int(v)

            # all other options are converted at the top level
            else:
                output[k] = v

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(output, output_file, indent=2)

    LOG.success(f"JSON configuration successfully written to: {output_path}")
