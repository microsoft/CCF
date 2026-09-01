# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import itertools
import json
import os
import re
import time
from hashlib import sha256

import infra.checker
import infra.e2e_args
import infra.net
import infra.network
import infra.proc
import suite.test_requirements as reqs
from loguru import logger as LOG

id_gen = itertools.count()

SIZE_SUFFIXES = {
    "": 1,
    "b": 1,
    "kb": 1024,
    "mb": 1024**2,
    "gb": 1024**3,
    "tb": 1024**4,
    "pb": 1024**5,
}


def size_string_to_bytes(size):
    match = re.fullmatch(r"(\d+)([a-zA-Z]*)", size)
    if match is None:
        raise ValueError(f"Invalid size string: {size}")

    value, suffix = match.groups()
    try:
        multiplier = SIZE_SUFFIXES[suffix.lower()]
    except KeyError as e:
        raise ValueError(f"Invalid size suffix: {suffix}") from e
    return int(value) * multiplier


def get_node_response_sizes(node):
    config_path = os.path.join(node.common_dir, f"{node.local_node_id}.config.json")
    with open(config_path, encoding="utf-8") as f:
        memory_config = json.load(f)["memory"]

    ringbuffer_capacity = size_string_to_bytes(memory_config["circuit_size"])
    max_ringbuffer_message_size = size_string_to_bytes(memory_config["max_msg_size"])

    return (
        ringbuffer_capacity,
        # Leave headroom for the QuickJS string and response serialization.
        max_ringbuffer_message_size // 2,
    )


@reqs.description("Generate responses at and above ringbuffer capacity")
def test_large_responses(network, args):
    primary, _ = network.find_primary()
    ringbuffer_capacity, max_response_size = get_node_response_sizes(primary)
    large_response_sizes = (ringbuffer_capacity, max_response_size)
    invalid_response_sizes = (-1, 1.5, max_response_size + 1)

    with primary.client("member0") as c:
        response = c.post(
            "/app/batch/generate/config",
            {"max_response_size": max_response_size},
        )
        assert response.status_code == http.HTTPStatus.NO_CONTENT, (
            f"Expected {http.HTTPStatus.NO_CONTENT}, got {response.status_code}: "
            f"{response.body.data()[:200]!r}"
        )

    with primary.client("user0") as c:
        for response_size in large_response_sizes:
            LOG.info(f"Generating a {response_size} byte response")
            response = c.post(
                "/app/batch/generate", {"size": response_size}, timeout=30
            )
            assert response.status_code == http.HTTPStatus.OK, (
                f"Expected {http.HTTPStatus.OK}, got {response.status_code}: "
                f"{response.body.data()[:200]!r}"
            )
            body = response.body.data()
            assert len(body) == response_size
            assert body[:1] == b"X"
            assert body[-1:] == b"X"

        for response_size in invalid_response_sizes:
            response = c.post("/app/batch/generate", {"size": response_size})
            assert response.status_code == http.HTTPStatus.BAD_REQUEST, (
                f"Expected {http.HTTPStatus.BAD_REQUEST}, got {response.status_code}: "
                f"{response.body.data()[:200]!r}"
            )

    return network, ringbuffer_capacity


@reqs.description("Running batch submission of new entries")
def test(
    network,
    args,
    batch_size=100,
    write_key_divisor=1,
    write_size_multiplier=1,
    expect_transaction_too_large=False,
):
    LOG.info(f"Number of batched entries: {batch_size}")
    primary, _ = network.find_primary()

    # Set extended timeout, since some of these successful transactions will take many seconds
    with primary.client("user0") as c:
        check = infra.checker.Checker()

        message_ids = [next(id_gen) for _ in range(batch_size)]
        messages = [
            {"id": i, "msg": f"A unique message: {sha256(i.to_bytes(8)).hexdigest()}"}
            for i in message_ids
        ]

        pre_submit = time.time()
        response = c.post(
            "/app/batch/submit",
            {
                "entries": messages,
                "write_key_divisor": write_key_divisor,
                "write_size_multiplier": write_size_multiplier,
            },
            timeout=30,
        )

        if expect_transaction_too_large:
            assert (
                response.status_code == http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE.value
            )
            assert response.body.json()["error"]["code"] == "TransactionTooLarge"
            return network

        check(response, result=len(messages))
        post_submit = time.time()
        LOG.warning(
            f"Submitting {batch_size} new keys took {post_submit - pre_submit}s"
        )

        fetch_response = c.post("/app/batch/fetch", message_ids, timeout=30)

        if write_key_divisor == 1 and write_size_multiplier == 1:
            check(fetch_response, result=messages)

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        network, ringbuffer_capacity = test_large_responses(network, args)
        network = test(network, args, batch_size=1)
        network = test(network, args, batch_size=10)
        network = test(network, args, batch_size=100)
        network = test(network, args, batch_size=1000)

        network = test(network, args, batch_size=1000, write_key_divisor=10)
        network = test(network, args, batch_size=1000, write_size_multiplier=10)
        network = test(
            network,
            args,
            batch_size=1000,
            write_key_divisor=10,
            write_size_multiplier=10,
        )

        # CI already takes ~25s for batch of 10k, so avoid large batches for now
        # bs = 10000
        # step_size = 10000

        # This tests fails with larger batch sizes, and with any transaction
        # # larger than ~2MB. Investigate why, then expand this test
        # while bs <= 30000:
        #     network = test(network, args, batch_size=bs)
        #     bs += step_size

        return ringbuffer_capacity


def run_to_transaction_limit(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        LOG.warning("About to issue a transaction above the configured limit")
        network = test(network, args, batch_size=10, write_size_multiplier=5000)
        network = test(
            network,
            args,
            batch_size=10,
            write_size_multiplier=105000,
            expect_transaction_too_large=True,
        )

        exit_codes = [node.remote.remote.proc.poll() for node in network.nodes]
        assert all(exit_code is None for exit_code in exit_codes), exit_codes

        # The rejected transaction must not prevent subsequent commits.
        network = test(network, args, batch_size=10)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "js_generic"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)

    ringbuffer_capacity = run(args)

    # Keep this stress test's successful write below the configured transaction
    # limit while allowing the next, much larger write to exercise clean
    # rejection.
    args.max_msg_size_bytes = f"{ringbuffer_capacity}"
    args.ledger_max_transaction_bytes = f"{1024 * 1024 * 15}"  # 15MB

    run_to_transaction_limit(args)
