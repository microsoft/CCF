# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from hashlib import md5
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
@reqs.supports_methods("batch/submit", "batch/fetch")
def test(network, args, batch_size=100, write_key_divisor=1, write_size_multiplier=1):
    LOG.info(f"Number of batched entries: {batch_size}")
    primary, _ = network.find_primary()

    # Set extended timeout, since some of these successful transactions will take many seconds
    with primary.client("user0") as c:
        check = infra.checker.Checker()

        message_ids = [next(id_gen) for _ in range(batch_size)]
        messages = [
            {"id": i, "msg": f"A unique message: {md5(bytes(i)).hexdigest()}"}
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
        args.nodes, args.consensus, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

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
        args.nodes, args.consensus, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        LOG.warning("About to issue transactions until destruction")
        try:
            wsm = 5000
            while True:
                LOG.info(f"Trying with writes scaled by {wsm}")
                network = test(network, args, batch_size=10, write_size_multiplier=wsm)
                wsm += (
                    50000  # Grow very quickly, expect to fail on the second iteration
                )
        except Exception as e:
            timeout = 10

            LOG.info("Large write set caused an exception, as expected")
            LOG.info(f"Exception was: {e}")
            LOG.info(f"Polling for {timeout}s for node to terminate")

            end_time = time.time() + timeout
            while time.time() < end_time:
                time.sleep(0.1)
                exit_code = network.nodes[0].remote.remote.proc.poll()
                if exit_code is not None:
                    LOG.info(f"Node terminated with exit code {exit_code}")
                    assert exit_code != 0
                    break

            if time.time() > end_time:
                raise TimeoutError(
                    f"Node took longer than {timeout}s to terminate"
                ) from e

            network.ignore_errors_on_shutdown()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.enforce_reqs = True
    args.nodes = infra.e2e_args.min_nodes(args, f=1)

    run(args)
    run_to_destruction(args)
