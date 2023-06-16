# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass
from typing import Optional, Dict
from enum import Enum, auto
import urllib.parse

from loguru import logger as LOG


def split_netloc(netloc, default_port=0):
    url = f"http://{netloc}"
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname, (parsed.port if parsed.port else default_port)


def make_address(host, port=0):
    if ":" in host:
        return f"[{host}]:{port}"
    else:
        return f"{host}:{port}"


DEFAULT_TRANSPORT_PROTOCOL = "tcp"
DEFAULT_MAX_OPEN_SESSIONS_SOFT = 1000
DEFAULT_MAX_OPEN_SESSIONS_HARD = DEFAULT_MAX_OPEN_SESSIONS_SOFT + 10

DEFAULT_MAX_HTTP_BODY_SIZE = 1024 * 1024
DEFAULT_MAX_HTTP_HEADER_SIZE = 16 * 1024
DEFAULT_MAX_HTTP_HEADERS_COUNT = 256

DEFAULT_MAX_CONCURRENT_STREAMS_COUNT = 100
DEFAULT_INITIAL_WINDOW_SIZE = 64 * 1024
DEFAULT_MAX_FRAME_SIZE = 16 * 1024

DEFAULT_FORWARDING_TIMEOUT_MS = 3000

PRIMARY_RPC_INTERFACE = "primary_rpc_interface"
SECONDARY_RPC_INTERFACE = "secondary_rpc_interface"
NODE_TO_NODE_INTERFACE_NAME = "node_to_node_interface"


class EndorsementAuthority(Enum):
    Service = auto()
    Node = auto()
    ACME = auto()
    Unsecured = auto()


@dataclass
class Endorsement:
    authority: EndorsementAuthority = EndorsementAuthority.Service

    acme_configuration: Optional[str] = None

    @staticmethod
    def to_json(endorsement):
        r = {"authority": endorsement.authority.name}
        if endorsement.acme_configuration:
            r["acme_configuration"] = endorsement.acme_configuration
        return r

    @staticmethod
    def from_json(json):
        endorsement = Endorsement()
        endorsement.authority = json["authority"]
        endorsement.acme_configuration = json["acme_configuration"]
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
    max_http_body_size: Optional[int] = DEFAULT_MAX_HTTP_BODY_SIZE
    max_http_header_size: Optional[int] = DEFAULT_MAX_HTTP_HEADER_SIZE
    max_http_headers_count: Optional[int] = DEFAULT_MAX_HTTP_HEADERS_COUNT
    max_concurrent_streams_count: Optional[int] = DEFAULT_MAX_CONCURRENT_STREAMS_COUNT
    initial_window_size: Optional[int] = DEFAULT_INITIAL_WINDOW_SIZE
    max_frame_size: Optional[int] = DEFAULT_MAX_FRAME_SIZE
    endorsement: Optional[Endorsement] = Endorsement()
    acme_configuration: Optional[str] = None
    accepted_endpoints: Optional[str] = None
    forwarding_timeout_ms: Optional[int] = None
    app_protocol: str = "HTTP1"

    @staticmethod
    def from_args(args):
        return RPCInterface(
            max_open_sessions_soft=args.max_open_sessions,
            max_open_sessions_hard=args.max_open_sessions_hard,
            max_http_body_size=args.max_http_body_size,
            max_http_header_size=args.max_http_header_size,
            max_http_headers_count=args.max_http_headers_count,
            forwarding_timeout_ms=args.forwarding_timeout_ms,
            app_protocol="HTTP2" if args.http2 else "HTTP1",
        )

    def parse_from_str(self, s):
        # Format: local|ssh(,tcp|udp)://hostname:port

        self.protocol, address = s.split("://")
        self.transport = DEFAULT_TRANSPORT_PROTOCOL
        if "," in self.protocol:
            self.protocol, self.transport = self.protocol.split(",")

        if "," in address:
            address, published_address = address.split(",")
            self.public_host, self.public_port = split_netloc(published_address)

        self.host, self.port = split_netloc(address)

    @staticmethod
    def to_json(interface):
        http_config = {
            "max_body_size": str(interface.max_http_body_size),
            "max_header_size": str(interface.max_http_header_size),
            "max_headers_count": interface.max_http_headers_count,
        }
        if interface.app_protocol == "HTTP2":
            http_config.update(
                {
                    "max_concurrent_streams_count": interface.max_concurrent_streams_count,
                    "initial_window_size": str(interface.initial_window_size),
                    "max_frame_size": str(interface.max_frame_size),
                }
            )
        r = {
            "bind_address": make_address(interface.host, interface.port),
            "protocol": f"{interface.transport}",
            "app_protocol": interface.app_protocol,
            "published_address": f"{interface.public_host}:{interface.public_port or 0}",
            "max_open_sessions_soft": interface.max_open_sessions_soft,
            "max_open_sessions_hard": interface.max_open_sessions_hard,
            "http_configuration": http_config,
            "endorsement": Endorsement.to_json(interface.endorsement),
        }
        if interface.accepted_endpoints:
            r["accepted_endpoints"] = interface.accepted_endpoints
        if interface.forwarding_timeout_ms:
            r["forwarding_timeout_ms"] = interface.forwarding_timeout_ms
        return r

    @staticmethod
    def from_json(json):
        interface = RPCInterface()
        interface.transport = json.get("protocol", DEFAULT_TRANSPORT_PROTOCOL)
        interface.host, interface.port = split_netloc(json.get("bind_address"))
        LOG.warning(
            f"Converted {json.get('bind_address')} to {interface.host} and {interface.port}"
        )
        published_address = json.get("published_address")
        if published_address is not None:
            interface.public_host, interface.public_port = split_netloc(
                published_address
            )
        interface.max_open_sessions_soft = json.get(
            "max_open_sessions_soft", DEFAULT_MAX_OPEN_SESSIONS_SOFT
        )
        interface.max_open_sessions_hard = json.get(
            "max_open_sessions_hard", DEFAULT_MAX_OPEN_SESSIONS_HARD
        )
        interface.forwarding_timeout_ms = json.get(
            "forwarding_timeout_ms", DEFAULT_FORWARDING_TIMEOUT_MS
        )
        if "endorsement" in json:
            interface.endorsement = Endorsement.from_json(json["endorsement"])
        interface.accepted_endpoints = json.get("accepted_endpoints")
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
    acme_challenge_server_interface: Optional[str] = None

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
