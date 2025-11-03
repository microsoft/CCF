# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Union
from enum import Enum
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


class EndorsementAuthority(str, Enum):
    Service = "Service"
    Node = "Node"
    Unsecured = "Unsecured"


@dataclass
class Endorsement:
    authority: EndorsementAuthority = EndorsementAuthority.Service

    @staticmethod
    def to_json(endorsement):
        r = {"authority": endorsement.authority.name}
        return r

    @staticmethod
    def from_json(json):
        endorsement = Endorsement()
        endorsement.authority = EndorsementAuthority(json["authority"])
        return endorsement


@dataclass
class Interface:
    host: str = "localhost"
    port: int = 0


class NodeRole(str, Enum):
    primary = "primary"
    backup = "backup"


@dataclass
class TargetRole:
    role: NodeRole

    @staticmethod
    def to_json(tr):
        return asdict(tr)

    @staticmethod
    def from_json(json):
        return TargetRole(role=NodeRole(json["role"]))


@dataclass
class NodeByRoleResolver:
    target: TargetRole = field(default_factory=lambda: TargetRole(NodeRole.primary))
    kind: str = "NodeByRole"

    @staticmethod
    def to_json(nbrr):
        return asdict(nbrr)

    @staticmethod
    def from_json(json):
        nbrr = NodeByRoleResolver()
        nbrr.target = TargetRole.from_json(json["target"])
        return nbrr


@dataclass
class StaticAddressResolver:
    target_address: str
    kind: str = "StaticAddress"

    @staticmethod
    def to_json(sar):
        return {
            "kind": sar.kind,
            "target": {"address": sar.target_address},
        }

    @staticmethod
    def from_json(json):
        return StaticAddressResolver(target_address=json["target"]["address"])


RedirectionResolver = Union[NodeByRoleResolver, StaticAddressResolver]


@dataclass
class RedirectionConfig:
    to_primary: NodeByRoleResolver = field(default_factory=lambda: NodeByRoleResolver())
    to_backup: NodeByRoleResolver = field(
        default_factory=lambda: NodeByRoleResolver(target=TargetRole(NodeRole.backup))
    )

    @staticmethod
    def to_json(rc):
        return {
            "to_primary": rc.to_primary.to_json(rc.to_primary),
            "to_backup": rc.to_backup.to_json(rc.to_backup),
        }

    @staticmethod
    def from_json(json):
        def resolver_from_json(obj):
            if obj["kind"] == "NodeByRole":
                return NodeByRoleResolver.from_json(obj)
            elif obj["kind"] == "StaticAddress":
                return StaticAddressResolver.from_json(obj)

        rc = RedirectionConfig()

        tp = json.get("to_primary", None)
        if tp:
            rc.to_primary = resolver_from_json(tp)

        tb = json.get("to_backup", None)
        if tb:
            rc.to_backup = resolver_from_json(tb)

        return rc


@dataclass
class RPCInterface(Interface):
    # How nodes are created (local, ssh, ...)
    protocol: str = field(default_factory=lambda: "local")
    # Underlying transport layer protocol (tcp, udp)
    transport: str = field(default_factory=lambda: "tcp")
    # Host name/IP
    public_host: Optional[str] = None
    # Host port
    public_port: Optional[int] = None
    max_open_sessions_soft: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_OPEN_SESSIONS_SOFT
    )
    max_open_sessions_hard: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_OPEN_SESSIONS_HARD
    )
    max_http_body_size: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_HTTP_BODY_SIZE
    )
    max_http_header_size: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_HTTP_HEADER_SIZE
    )
    max_http_headers_count: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_HTTP_HEADERS_COUNT
    )
    max_concurrent_streams_count: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_CONCURRENT_STREAMS_COUNT
    )
    initial_window_size: Optional[int] = field(
        default_factory=lambda: DEFAULT_INITIAL_WINDOW_SIZE
    )
    max_frame_size: Optional[int] = field(
        default_factory=lambda: DEFAULT_MAX_FRAME_SIZE
    )
    endorsement: Optional[Endorsement] = field(default_factory=lambda: Endorsement())
    accepted_endpoints: Optional[str] = None
    # TODO: Default should be None
    enabled_optin_features: Optional[list[str]] = field(
        default_factory=lambda: ["FileAccess"]
    )
    forwarding_timeout_ms: Optional[int] = field(
        default_factory=lambda: DEFAULT_FORWARDING_TIMEOUT_MS
    )
    redirections: Optional[RedirectionConfig] = None
    app_protocol: str = field(default_factory=lambda: "HTTP1")

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

        return self

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
            "max_open_sessions_soft": interface.max_open_sessions_soft,
            "max_open_sessions_hard": interface.max_open_sessions_hard,
            "http_configuration": http_config,
            "endorsement": Endorsement.to_json(interface.endorsement),
        }
        if interface.public_host:
            r["published_address"] = (
                f"{interface.public_host}:{interface.public_port or 0}"
            )
        if interface.accepted_endpoints:
            r["accepted_endpoints"] = interface.accepted_endpoints
        if interface.enabled_optin_features:
            r["enabled_optin_features"] = interface.enabled_optin_features
        if interface.forwarding_timeout_ms:
            r["forwarding_timeout_ms"] = interface.forwarding_timeout_ms
        if interface.redirections:
            r["redirections"] = RedirectionConfig.to_json(interface.redirections)
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
        if "redirections" in json:
            interface.redirections = RedirectionConfig.from_json(json["redirections"])
        if "endorsement" in json:
            interface.endorsement = Endorsement.from_json(json["endorsement"])
        interface.accepted_endpoints = json.get("accepted_endpoints")
        interface.enabled_optin_features = json.get("enabled_optin_features")
        return interface


def make_secondary_interface(transport="tcp", interface_name=SECONDARY_RPC_INTERFACE):
    return {
        interface_name: RPCInterface(
            endorsement=Endorsement(EndorsementAuthority.Node), transport=transport
        )
    }


@dataclass
class HostSpec:
    rpc_interfaces: Dict[str, RPCInterface] = field(
        default_factory=lambda: {PRIMARY_RPC_INTERFACE: RPCInterface()}
    )

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


if __name__ == "__main__":
    # Test some roundtrip conversions
    def test_roundtrip(before):
        j = before.to_json(before)
        after = before.from_json(j)
        assert before == after, f"Inaccurate JSON roundtrip:\n {before}\n!=\n {after}"

    rc = RedirectionConfig()
    test_roundtrip(rc)

    rc.to_primary = StaticAddressResolver("1.2.3.4")
    test_roundtrip(rc)

    rc.to_backup = NodeByRoleResolver(target=TargetRole(NodeRole.backup))
    test_roundtrip(rc)

    hc = HostSpec()
    test_roundtrip(hc)
