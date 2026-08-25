# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unit tests for tracking code identities in ccf.ledger_code."""

import json
from collections import defaultdict

from ccf.ledger_code import update_trusted_nodes


def node_info(status: str, code_digest: str) -> bytes:
    """Build a serialised node-table value for a code identity."""
    return json.dumps(
        {
            "status": status,
            "quote_info": {"format": "Virtual"},
            "code_digest": code_digest,
        }
    ).encode()


def test_direct_node_deletion_removes_trusted_code_identity():
    """A disaster-recovery deletion removes a node without a Retired write."""
    trusted_nodes = defaultdict(set)
    first_code = ("Virtual", "first")
    second_code = ("Virtual", "second")

    assert update_trusted_nodes(trusted_nodes, b"node0", node_info("Trusted", "first"))
    assert update_trusted_nodes(trusted_nodes, b"node1", node_info("Trusted", "second"))
    assert trusted_nodes == {
        first_code: {b"node0"},
        second_code: {b"node1"},
    }

    assert update_trusted_nodes(trusted_nodes, b"node0", None)
    assert trusted_nodes == {
        first_code: set(),
        second_code: {b"node1"},
    }


def test_normal_retirement_still_removes_trusted_node():
    """A normal Retired write removes the node from its code identity."""
    trusted_nodes = defaultdict(set)
    code = ("Virtual", "digest")

    assert update_trusted_nodes(trusted_nodes, b"node0", node_info("Trusted", "digest"))
    assert update_trusted_nodes(trusted_nodes, b"node0", node_info("Retired", "digest"))
    assert trusted_nodes == {code: set()}

    assert not update_trusted_nodes(trusted_nodes, b"node0", None)
