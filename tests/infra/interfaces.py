# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass
from typing import Optional, List


def split_address(addr, default_port=0):
    host, *port = addr.split(":")
    return host, (int(port[0]) if port else default_port)


def make_address(host, port=0):
    return f"{host}:{port}"


DEFAULT_MAX_OPEN_SESSIONS_SOFT = 1000
DEFAULT_MAX_OPEN_SESSIONS_HARD = DEFAULT_MAX_OPEN_SESSIONS_SOFT + 10


@dataclass
class RPCInterface:
    protocol: str = "local"
    rpc_host: str = "localhost"
    rpc_port: int = 0
    public_rpc_host: Optional[str] = None
    public_rpc_port: Optional[int] = None
    max_open_sessions_soft: Optional[int] = DEFAULT_MAX_OPEN_SESSIONS_SOFT
    max_open_sessions_hard: Optional[int] = DEFAULT_MAX_OPEN_SESSIONS_HARD

    @staticmethod
    def to_json(interface):
        return {
            "bind_address": {
                "hostname": interface.rpc_host,
                "port": str(interface.rpc_port),
            },
            "published_address": {
                "hostname": interface.public_rpc_host,
                "port": str(interface.public_rpc_port),
            },
            "max_open_sessions_soft": interface.max_open_sessions_soft,
            "max_open_sessions_hard": interface.max_open_sessions_hard,
        }

    @staticmethod
    def from_json(json):
        interface = RPCInterface()
        bind_address = json.get("bind_address")
        interface.rpc_host = bind_address["hostname"]
        interface.rpc_port = bind_address["port"]
        published_address = json.get("published_address")
        if published_address is not None:
            interface.public_rpc_host = published_address["hostname"]
            interface.public_rpc_port = published_address["port"]
        interface.max_open_sessions_soft = json.get(
            "max_open_sessions_soft", DEFAULT_MAX_OPEN_SESSIONS_SOFT
        )
        interface.max_open_sessions_hard = json.get(
            "max_open_sessions_hard", DEFAULT_MAX_OPEN_SESSIONS_HARD
        )
        return interface


@dataclass
class HostSpec:
    rpc_interfaces: List[RPCInterface] = RPCInterface()

    @staticmethod
    def to_json(host_spec):
        return [
            RPCInterface.to_json(rpc_interface)
            for rpc_interface in host_spec.rpc_interfaces
        ]

    @staticmethod
    def from_json(rpc_interfaces_json):
        return HostSpec(
            rpc_interfaces=[
                RPCInterface.from_json(rpc_interface)
                for rpc_interface in rpc_interfaces_json
            ]
        )

    @staticmethod
    def from_str(s):
        protocol, address = s.split("://")
        host, port = split_address(address)
        return HostSpec(rpc_interfaces=[RPCInterface(protocol, host, port)])
