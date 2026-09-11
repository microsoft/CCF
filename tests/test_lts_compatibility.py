# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from types import SimpleNamespace
from unittest import mock

import lts_compatibility


def test_create_and_join_node_passes_container_image_to_join():
    network = mock.Mock()
    node = mock.sentinel.node
    network.create_node.return_value = node
    args = SimpleNamespace(package="js_generic")

    result = lts_compatibility.create_and_join_node(
        network,
        args,
        "/opt/ccf/bin",
        "/opt/ccf/lib",
        "ccf-8.0.0",
        node_container_image="ccf:al4",
        fetch_recent_snapshot=True,
    )

    assert result is node
    network.create_node.assert_called_once_with(
        binary_dir="/opt/ccf/bin",
        library_dir="/opt/ccf/lib",
        version="ccf-8.0.0",
    )
    network.join_node.assert_called_once_with(
        node,
        "js_generic",
        args,
        node_container_image="ccf:al4",
        fetch_recent_snapshot=True,
    )
