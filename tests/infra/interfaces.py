# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass
from typing import Optional, Dict
from enum import Enum, auto


def split_address(addr, default_port=0):
    host, *port = addr.split(":")
    return host, (int(port[0]) if port else default_port)


def make_address(host, port=0):
    return f"{host}:{port}"


DEFAULT_TRANSPORT_PROTOCOL = "tcp"
DEFAULT_MAX_OPEN_SESSIONS_SOFT = 1000
DEFAULT_MAX_OPEN_SESSIONS_HARD = DEFAULT_MAX_OPEN_SESSIONS_SOFT + 10


PRIMARY_RPC_INTERFACE = "primary_rpc_interface"
SECONDARY_RPC_INTERFACE = "secondary_rpc_interface"
NODE_TO_NODE_INTERFACE_NAME = "node_to_node_interface"


class EndorsementAuthority(Enum):
    Service = auto()
    Node = auto()
    ACME = auto()


@dataclass
class Endorsement:
    authority: EndorsementAuthority = EndorsementAuthority.Service

    @staticmethod
    def to_json(endorsement):
        return {
            "authority": endorsement.authority.name,
        }

    @staticmethod
    def from_json(json):
        endorsement = Endorsement()
        endorsement.authority = json["authority"]
        return endorsement


@dataclass
class Interface:
    host: str = "localhost"
    port: int = 0


@dataclass
class RPCInterface(Interface):
    # How nodes are created (local, ssh, ...)
    protocol: str = "local"
    # Underlying transport layer protocol (tcp, udp)
    transport: str = "tcp"
    # Host name/IP
    public_host: Optional[str] = None
    # Host port
    public_port: Optional[int] = None
    max_open_sessions_soft: Optional[int] = DEFAULT_MAX_OPEN_SESSIONS_SOFT
    max_open_sessions_hard: Optional[int] = DEFAULT_MAX_OPEN_SESSIONS_HARD
    endorsement: Optional[Endorsement] = Endorsement()
    acme_configuration: Optional[str] = None

    @staticmethod
    def to_json(interface):
        r = {
            "bind_address": f"{interface.host}:{interface.port}",
            "protocol": f"{interface.transport}",
            "published_address": f"{interface.public_host}:{interface.public_port or 0}",
            "max_open_sessions_soft": interface.max_open_sessions_soft,
            "max_open_sessions_hard": interface.max_open_sessions_hard,
            "endorsement": Endorsement.to_json(interface.endorsement),
        }
        if interface.acme_configuration:
            r["acme_configuration"] = interface.acme_configuration
        return r

    @staticmethod
    def from_json(json):
        interface = RPCInterface()
        interface.transport = json.get("protocol", DEFAULT_TRANSPORT_PROTOCOL)
        interface.host, interface.port = split_address(json.get("bind_address"))
        published_address = json.get("published_address")
        if published_address is not None:
            interface.public_host, interface.public_port = split_address(
                published_address
            )
        interface.max_open_sessions_soft = json.get(
            "max_open_sessions_soft", DEFAULT_MAX_OPEN_SESSIONS_SOFT
        )
        interface.max_open_sessions_hard = json.get(
            "max_open_sessions_hard", DEFAULT_MAX_OPEN_SESSIONS_HARD
        )
        if "endorsement" in json:
            interface.endorsement = Endorsement.from_json(json["endorsement"])
        if "acme_configuration" in json:
            interface.acme_configuration = json.get("acme_configuration")
        return interface


def make_secondary_interface(transport="tcp", interface_name=SECONDARY_RPC_INTERFACE):
    return {
        interface_name: RPCInterface(
            endorsement=Endorsement(EndorsementAuthority.Node), transport=transport
        )
    }


@dataclass
class HostSpec:
    rpc_interfaces: Dict[str, RPCInterface] = RPCInterface()

    def get_primary_interface(self):
        return self.rpc_interfaces[PRIMARY_RPC_INTERFACE]

    @staticmethod
    def to_json(host_spec):
        return {
            name: RPCInterface.to_json(rpc_interface)
            for name, rpc_interface in host_spec.rpc_interfaces.items()
        }

    @staticmethod
    def from_json(rpc_interfaces_json):
        return HostSpec(
            rpc_interfaces={
                name: RPCInterface.from_json(rpc_interface)
                for name, rpc_interface in rpc_interfaces_json.items()
            }
        )

    @staticmethod
    def from_str(s):
        # Format: local|ssh(,tcp|udp)://hostname:port
        protocol, address = s.split("://")
        transport = DEFAULT_TRANSPORT_PROTOCOL
        if "," in protocol:
            protocol, transport = protocol.split(",")
        pub_host, pub_port = None, None
        if "," in address:
            address, published_address = address.split(",")
            pub_host, pub_port = split_address(published_address)
        host, port = split_address(address)
        return HostSpec(
            rpc_interfaces={
                PRIMARY_RPC_INTERFACE: RPCInterface(
                    protocol=protocol,
                    transport=transport,
                    host=host,
                    port=port,
                    public_host=pub_host,
                    public_port=pub_port,
                )
            }
        )
