# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import itertools
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

    # Keep this stress test's successful write below the configured transaction
    # limit while allowing the next, much larger write to exercise clean
    # rejection.
    args.max_msg_size_bytes = f"{1024 * 1024 * 16}"  # 16MB
    args.ledger_max_transaction_bytes = f"{1024 * 1024 * 15}"  # 15MB

    run(args)
    run_to_transaction_limit(args)
