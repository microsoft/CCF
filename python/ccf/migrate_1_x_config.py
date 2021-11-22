# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import configparser
import sys
import json
from typing import Dict, Any

from loguru import logger as LOG


DEFAULT_OUTPUT_PATH = "2_x_config.json"
DEFAULT_INI_SECTION = "default"


SECTIONS_2_X = [
    "enclave",
    "network",
    "node_certificate",
    "start",
    "join",
    "ledger",
    "snapshots",
    "logging",
    "consensus",
    "intervals",
    "jwt",
    "memory",
]

DEFAULT_MAX_RPC_SESSIONS_SOFT = 1000


def make_key_json_compatible(key):
    return key.replace("-", "_")


def split_address(addr, default_port="0"):
    host, *port = addr.split(":")
    return {"hostname": host, "port": (port[0] if port else default_port)}


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
    output["network"]["rpc_interfaces"] = [{}]
    output["start"]["constitution_files"] = []
    output["network"]["rpc_interfaces"][0] = {
        "max_open_sessions_soft": DEFAULT_MAX_RPC_SESSIONS_SOFT,
        "max_open_sessions_hard": DEFAULT_MAX_RPC_SESSIONS_SOFT + 10,
    }
    output["start"]["members"] = []
    output["start"]["service_configuration"] = {
        "maximum_node_certificate_validity_days": 365
    }

    for s in config.sections():
        for k_, v_ in config.items(s):
            k = make_key_json_compatible(k_)
            v = v_.strip('"')

            # sub-commands
            # start
            if k == "constitution":
                output["start"]["constitution_files"] = json.loads(v)
            elif k == "member_info":
                for m in json.loads(v):
                    output["start"]["members"].append(split_member_info(m))
            elif k == "recovery_threshold":
                output["start"]["service_configuration"][k] = int(v)
            # join
            elif k == "target_rpc_address":
                output[s][k] = split_address(v)
            elif k == "join_timer":
                output[s]["timer_ms"] = int(v)

            # enclave
            elif k == "enclave_file":
                output["enclave"]["file"] = v
            elif k == "enclave_type":
                output["enclave"]["type"] = v

            # network
            elif k == "rpc_address":
                output["network"]["rpc_interfaces"][0]["bind_address"] = split_address(
                    v
                )
            elif k == "public_rpc_address":
                output["network"]["rpc_interfaces"][0][
                    "published_address"
                ] = split_address(v)
            elif k == "max_open_sessions":
                output["network"]["rpc_interfaces"][0]["max_open_sessions_soft"] = int(
                    v
                )
                output["network"]["rpc_interfaces"][0]["max_open_sessions_soft"] = (
                    int(v) + 10
                )
            elif k == "node_address":
                output["network"]["node_address"] = split_address(v)
            elif k == "network_cert_file":
                output["network_certificate_file"] = v

            # node certificate
            elif k == "san":
                output["node_certificate"][k] = json.loads(v)
            elif k == "sn":
                output["node_certificate"][k] = v
            elif k == "curve_id":
                output["node_certificate"][k] = v

            # ledger
            elif k == "ledger_dir":
                output["ledger"]["directory"] = v
            elif k == "read_only_ledger_dir":
                output["ledger"]["read_only_directories"] = [v]
            elif k == "ledger_chunk_bytes":
                output["ledger"]["chunk_size"] = int(v)

            # snapshots
            elif k == "snapshot_dir":  # plural
                output["snapshots"]["directory"] = v
            elif k == "snapshot_tx_interval":
                output["snapshots"]["interval_size"] = int(v)

            # logging
            elif k == "log_format_json":
                output["logging"]["log_format"] = "json" if bool(v) else "text"
            elif k == "host_log_level":
                output["logging"]["host_level"] = v

            # consensus
            elif k == "consensus":
                output["consensus"]["type"] = str.upper(v)
            elif k == "raft_timeout_ms":
                output["consensus"]["timeout_ms"] = int(v)
            elif k == "raft_election_timeout_ms":
                output["consensus"]["election_timeout_ms"] = int(v)

            elif k == "sig_tx_interval":
                output["intervals"]["signature_interval_size"] = int(v)
            elif k == "sig_ms_interval":
                output["intervals"]["signature_interval_duration_ms"] = int(v)
            elif k == "jwt_key_refresh_interval_s":
                output["jwt"]["key_refresh_interval_s"] = int(v)

            # memory
            elif "size" in k:
                output["memory"][k] = int(v)

            elif k in ("worker_threads", "tick_period_ms"):
                output[k] = int(v)

            # all other options are converted at the top level
            else:
                output[k] = v

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(output, output_file, indent=2)

    LOG.success(f"JSON configuration successfully written to: {output_path}")
