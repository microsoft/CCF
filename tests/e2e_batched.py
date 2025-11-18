# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from hashlib import sha256
import itertools
import time

import infra.network
import infra.proc
import infra.net
import infra.checker
import suite.test_requirements as reqs
import infra.e2e_args

from loguru import logger as LOG

id_gen = itertools.count()


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

    # Helps ensure expected destruction workflow. See #6373 for details.
    args.max_msg_size_bytes = f"{1024 * 1024 * 16}"  # 16MB

    run(args)
    run_to_destruction(args)
