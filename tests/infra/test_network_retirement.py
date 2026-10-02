# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from infra.clients import RawResponseBody, Response
from infra.network import Network, PrimaryNotFound


def response(status, body, seqno=None, view=None):
    return Response(
        status,
        RawResponseBody(json.dumps(body).encode()),
        seqno,
        view,
        {},
    )


def node(node_id, delete_response):
    client = Mock()
    client.get.return_value = response(
        http.HTTPStatus.OK, {"nodes": [{"node_id": "retired"}]}
    )
    client.delete.return_value = delete_response
    context = MagicMock()
    context.__enter__.return_value = client
    return (
        SimpleNamespace(
            node_id=node_id, version=None, client=Mock(return_value=context)
        ),
        client,
    )


def network_with_nodes(*nodes):
    network = object.__new__(Network)
    network.consortium = SimpleNamespace(retire_node=Mock(return_value=False))
    network.nodes = list(nodes)
    return network


def test_retire_node_refreshes_primary_after_transient_rejection():
    retired = SimpleNamespace(node_id="retired", version=None)
    stale, stale_client = node(
        "stale",
        response(
            http.HTTPStatus.BAD_REQUEST,
            {"error": {"code": "NodeNotRetiredCommitted"}},
        ),
    )
    current, current_client = node(
        "current", response(http.HTTPStatus.OK, True, seqno=132, view=9)
    )
    network = network_with_nodes(retired, stale, current)
    network.wait_for_new_primary = Mock(return_value=(stale, 8))
    network.find_primary = Mock(return_value=(current, 9))

    with patch("infra.checker.wait_for_commit") as wait_for_commit, patch(
        "infra.network.time.sleep"
    ):
        network.retire_node(retired, retired, timeout=2)

    network.find_primary.assert_called_once()
    stale_client.delete.assert_called_once_with("/node/network/nodes/retired")
    current_client.get.assert_called_once_with("/node/network/removable_nodes")
    current_client.delete.assert_called_once_with("/node/network/nodes/retired")
    wait_for_commit.assert_called_once_with(current_client, 132, 9)
    assert retired not in network.nodes


def test_retire_node_checks_commit_on_success():
    retired = SimpleNamespace(node_id="retired", version=None)
    primary, client = node(
        "primary", response(http.HTTPStatus.OK, True, seqno=5, view=1)
    )
    network = network_with_nodes(primary, retired)
    network.find_primary = Mock()

    with patch("infra.checker.wait_for_commit") as wait_for_commit:
        network.retire_node(primary, retired)

    network.find_primary.assert_not_called()
    wait_for_commit.assert_called_once_with(client, 5, 1)
    assert retired not in network.nodes


@pytest.mark.parametrize(
    "status, body",
    [
        (http.HTTPStatus.BAD_REQUEST, {"error": {"code": "InvalidResourceName"}}),
        (http.HTTPStatus.BAD_REQUEST, {"unexpected": "response"}),
        (http.HTTPStatus.SERVICE_UNAVAILABLE, {"error": {"code": "Unavailable"}}),
    ],
)
def test_retire_node_fails_on_other_delete_errors(status, body):
    retired = SimpleNamespace(node_id="retired", version=None)
    primary, _ = node("primary", response(status, body))
    network = network_with_nodes(primary, retired)
    network.find_primary = Mock()

    with patch("infra.checker.wait_for_commit") as wait_for_commit, pytest.raises(
        RuntimeError
    ) as error:
        network.retire_node(primary, retired)

    assert str(status.value) in str(error.value)
    assert json.dumps(body) in str(error.value)
    network.find_primary.assert_not_called()
    wait_for_commit.assert_not_called()
    assert retired in network.nodes


def test_retire_node_uses_remaining_timeout_when_primary_is_unknown():
    retired = SimpleNamespace(node_id="retired", version=None)
    stale, _ = node(
        "stale",
        response(
            http.HTTPStatus.BAD_REQUEST,
            {"error": {"code": "NodeNotRetiredCommitted"}},
        ),
    )
    network = network_with_nodes(stale, retired)
    network.find_primary = Mock(side_effect=PrimaryNotFound)

    with patch("infra.network.time.time", side_effect=[100, 100, 101, 102]), patch(
        "infra.network.time.sleep"
    ), patch("infra.checker.wait_for_commit") as wait_for_commit, pytest.raises(
        TimeoutError, match="NodeNotRetiredCommitted"
    ):
        network.retire_node(stale, retired, timeout=2)

    network.find_primary.assert_called_once_with(timeout=1)
    wait_for_commit.assert_not_called()
    assert retired in network.nodes
