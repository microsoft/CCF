# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from hashlib import md5
import itertools
import time

import infra.ccf
import infra.proc
import infra.notification
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args

from loguru import logger as LOG

id_gen = itertools.count()


@reqs.description("Running batch submission of new entries")
@reqs.supports_methods("BATCH_submit", "BATCH_fetch")
def test(network, args, batch_size=100, write_key_divisor=1, write_size_multiplier=1):
    LOG.info(f"Number of batched entries: {batch_size}")
    primary, _ = network.find_primary()

    # Set extended timeout, since some of these successful transactions will take many seconds
    with primary.user_client(request_timeout=30) as c:
        check = infra.checker.Checker()

        message_ids = [next(id_gen) for _ in range(batch_size)]
        messages = [
            {"id": i, "msg": f"A unique message: {md5(bytes(i)).hexdigest()}"}
            for i in message_ids
        ]

        pre_submit = time.time()
        check(
            c.rpc(
                "BATCH_submit",
                {
                    "entries": messages,
                    "write_key_divisor": write_key_divisor,
                    "write_size_multiplier": write_size_multiplier,
                },
            ),
            result=len(messages),
        )
        post_submit = time.time()
        LOG.warning(
            f"Submitting {batch_size} new keys took {post_submit - pre_submit}s"
        )

        fetch_response = c.rpc("BATCH_fetch", message_ids)

        if write_key_divisor == 1 and write_size_multiplier == 1:
            check(fetch_response, result=messages)

    return network


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
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
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        try:
            wsm = 5000
            while True:
                LOG.info(f"Trying with writes scaled by {wsm}")
                network = test(network, args, batch_size=10, write_size_multiplier=wsm)
                wsm += 5000
        except Exception as e:
            sleep_time = 3
            LOG.info(f"Large write set caused an exception, as expected")
            LOG.info(f"Exception was: {e}")
            LOG.info(f"Waiting {sleep_time}s for node to terminate")

            time.sleep(sleep_time)
            assert (
                network.nodes[0].remote.remote.proc.poll() is not None
            ), "Primary should have been terminated"

            network.ignore_errors_on_shutdown()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblua_generic"
    args.enforce_reqs = True

    run(args)

    run_to_destruction(args)
