# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass
from typing import Optional, List


def split_address(addr, default_port=0):
    host, *port = addr.split(":")
    return host, (int(port[0]) if port else default_port)


@dataclass
class RPCInterface:
    protocol: str = "local"
    rpc_host: str = "localhost"
    rpc_port: int = 0
    public_rpc_host: Optional[str] = None
    public_rpc_port: Optional[int] = None
    max_open_sessions_soft: Optional[int] = 1000
    max_open_sessions_hard: Optional[int] = 1010

    def json(self):
        return {
            "rpc_address": {"hostname": self.rpc_host, "port": str(self.rpc_port)},
            "public_rpc_address": {
                "hostname": self.public_rpc_host,
                "port": str(self.public_rpc_port),
            },
            "max_open_sessions_soft": self.max_open_sessions_soft,
            "max_open_sessions_hard": self.max_open_sessions_hard,
        }


@dataclass
class HostSpec:
    rpc_interfaces: List[RPCInterface] = RPCInterface()

    def json(self):
        return [rpc_interface.json() for rpc_interface in self.rpc_interfaces]

    @staticmethod
    def from_str(s):
        protocol, address = s.split("://")
        host, port = split_address(address)
        return HostSpec(rpc_interfaces=[RPCInterface(protocol, host, port)])
