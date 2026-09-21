# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import hashlib
import http

from loguru import logger as LOG

import infra.node


def key_body(key: str) -> str:
    """The value written for a given key. Fixed per key, so that a write is
    idempotent and the value can be recomputed without storing it."""
    return hashlib.sha256(key.encode()).hexdigest()


def create_and_fill_key_space(size: int, primary: infra.node.Node) -> list[str]:
    LOG.info(f"Creating and filling key space of size {size}")
    space = [f"{i}" for i in range(size)]
    mapping = {key: key_body(key) for key in space}
    with primary.client("user0") as c:
        r = c.post("/records", mapping)
        assert r.status_code == http.HTTPStatus.NO_CONTENT, r
        # Quick sanity check
        for j in [0, -1]:
            r = c.get(f"/records/{space[j]}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.text() == mapping[space[j]], r
    LOG.info("Key space created and filled")
    return space
