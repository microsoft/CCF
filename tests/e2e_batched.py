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
def test(network, args, batch_size=100, write_key_divisor=1, write_size_multiplier=1):
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
        check(
            c.post(
                "/app/batch/submit",
                {
                    "entries": messages,
                    "write_key_divisor": write_key_divisor,
                    "write_size_multiplier": write_size_multiplier,
                },
                timeout=30,
            ),
            result=len(messages),
        )
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


def run_to_destruction(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        LOG.warning("About to issue transactions until destruction")
        try:
            wsm = 5000
            while True:
                LOG.info(f"Trying with writes scaled by {wsm}")
                network = test(network, args, batch_size=10, write_size_multiplier=wsm)
                if wsm > 1000000:
                    LOG.error(
                        f"Run to destruction still hasn't caused exception with write sizes multiplied by {wsm}. Infinite loop, or not actually submitting?"
                    )
                    raise ValueError(wsm)
                else:
                    wsm += 100000  # Grow very quickly, expect to fail on the second iteration
        except Exception as e:
            timeout = 120

            LOG.info("Large write set caused an exception, as expected")
            LOG.info(f"Exception was: {e}")
            LOG.info(f"Polling for {timeout}s for node to terminate")

            end_time = time.time() + timeout
            while time.time() < end_time:
                time.sleep(0.1)
                exit_codes = [node.remote.remote.proc.poll() for node in network.nodes]
                if any(exit_codes):
                    LOG.info(
                        f"One or more nodes terminated with exit codes {exit_codes}"
                    )
                    break

            if time.time() > end_time:
                raise TimeoutError(
                    f"Node took longer than {timeout}s to terminate"
                ) from e

            network.ignore_errors_on_shutdown()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "js_generic"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)

    ringbuffer_capacity = run(args)

    # Helps ensure expected destruction workflow. See #6373 for details.
    args.max_msg_size_bytes = f"{ringbuffer_capacity}"
    run_to_destruction(args)
