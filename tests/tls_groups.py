# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import re
import subprocess

import infra.e2e_args
import infra.network
import suite.test_requirements as reqs
from loguru import logger as LOG

# Hybrid groups offered by src/tls/context.h, in the order they are offered
HYBRID_GROUPS = ["SecP384r1MLKEM1024", "SecP256r1MLKEM768", "X25519MLKEM768"]

# Weakest classical fallback, and the name OpenSSL reports for it
WEAKEST_GROUP = "P-256"
WEAKEST_GROUP_REPORTED = "prime256v1"

# TLS NamedGroup IDs reported by OpenSSL 3.3
# Match IANA Group IDs defined in
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
GROUP_IDS = {
    "23": WEAKEST_GROUP_REPORTED,
    "4587": "SecP256r1MLKEM768",
    "4588": "X25519MLKEM768",
    "4589": "SecP384r1MLKEM1024",
}

# A group CCF does not offer
UNSUPPORTED_GROUP = "X448"

# s_client output varies between OpenSSL 3.3 and 3.5
NEGOTIATED_GROUP = re.compile(r"^Negotiated TLS1\.3 group: (\S+)$", re.MULTILINE)
TRACED_GROUP_ID = re.compile(
    r"extension_type=key_share\(51\),[^\n]*\n" r"\s+NamedGroup: [^\n]*\((\d+)\)"
)
PEER_TEMP_KEY = re.compile(r"^Peer Temp Key: ECDH, ([^,]+),", re.MULTILINE)


def negotiate_group(address, groups):
    """
    Handshakes with the node at address, offering only groups, and returns the
    group they agreed on, or None if they could not agree.
    """
    completed = subprocess.run(
        ["openssl", "s_client", "-trace", "-connect", address, "-groups", groups],
        input="",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = completed.stdout + completed.stderr

    match = NEGOTIATED_GROUP.search(output)
    if match is not None and match.group(1) != "<NULL>":
        return match.group(1)

    for record in output.split("Received TLS Record")[1:]:
        if "ServerHello," in record:
            match = TRACED_GROUP_ID.search(record)
            if match is not None:
                group_id = match.group(1)
                return GROUP_IDS.get(group_id, group_id)
            break

    match = PEER_TEMP_KEY.search(output)
    if match is not None:
        return match.group(1)

    return None


@reqs.description("Node negotiates hybrid post-quantum TLS groups")
def test_tls_groups(network, args):
    primary, _ = network.find_primary()
    address = primary.get_public_rpc_address()

    for group in HYBRID_GROUPS:
        negotiated = negotiate_group(address, group)
        LOG.info(f"Offered {group}, negotiated {negotiated}")
        assert negotiated == group, f"Offered {group}, negotiated {negotiated}"

    # The node offers HYBRID_GROUPS in that order, but the server order is only
    # a filter: OpenSSL picks the first group the client offered that the
    # server also supports, so the client order decides the outcome.
    strongest, weakest = HYBRID_GROUPS[0], HYBRID_GROUPS[-1]
    for first, second in ((weakest, strongest), (strongest, weakest)):
        offered = f"{first}:{second}"
        negotiated = negotiate_group(address, offered)
        LOG.info(f"Offered {offered}, negotiated {negotiated}")
        assert negotiated == first, f"Offered {offered}, negotiated {negotiated}"

    negotiated = negotiate_group(address, WEAKEST_GROUP)
    LOG.info(f"Offered {WEAKEST_GROUP}, negotiated {negotiated}")
    assert (
        negotiated == WEAKEST_GROUP_REPORTED
    ), f"Offered {WEAKEST_GROUP}, negotiated {negotiated}"

    negotiated = negotiate_group(address, UNSUPPORTED_GROUP)
    LOG.info(f"Offered {UNSUPPORTED_GROUP}, negotiated {negotiated}")
    assert (
        negotiated is None
    ), f"Offered {UNSUPPORTED_GROUP}, but negotiated {negotiated}"

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_tls_groups(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/logging"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
