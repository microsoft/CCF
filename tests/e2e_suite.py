# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.import test_suite

import infra.e2e_args
import infra.ccf
import suite.test_suite as s
import suite.test_requirements as reqs
import infra.logging_app as app
import time
import json
import sys
from enum import Enum
import random
import os

from loguru import logger as LOG


class TestStatus(Enum):
    success = 1
    failure = 2
    skipped = 3


def run(args):

    if os.getenv("SHUFFLE_SUITE"):
        seed = os.getenv("SHUFFLE_SUITE_SEED", int(time.time()))
        LOG.info(f"Shuffling suite with seed: {seed}")
        random.seed(seed)
        random.shuffle(s.tests)
    s.validate_tests_signature(s.tests)

    if args.enforce_reqs is False:
        LOG.warning("Test requirements will be ignored")

    hosts = ["localhost", "localhost"]
    txs = app.LoggingTxs()
    network = infra.ccf.Network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, txs=txs
    )
    network.start_and_join(args)

    LOG.info(f"Running {len(s.tests)} tests for {args.test_duration} seconds")

    run_tests = {}
    success = True
    elapsed = args.test_duration

    for i, test in enumerate(s.tests):
        status = None
        reason = None

        if elapsed <= 0:
            LOG.warning(f"Test duration time ({args.test_duration} seconds) is up!")
            break

        try:
            LOG.debug(f"Running {s.test_name(test)}...")
            test_time_before = time.time()

            # Actually run the test
            new_network = test(network, args)
            status = TestStatus.success

        except reqs.TestRequirementsNotMet as ce:
            LOG.warning(f"Test requirements for {s.test_name(test)} not met")
            status = TestStatus.skipped
            reason = str(ce)
            new_network = network

        except Exception as e:
            LOG.exception(f"Test {s.test_name(test)} failed")
            status = TestStatus.failure
            new_network = network

        test_elapsed = time.time() - test_time_before

        # Construct test report
        run_tests[i] = {
            "name": s.test_name(test),
            "status": status.name,
            "elapsed (s)": round(test_elapsed, 2),
        }

        if reason is not None:
            run_tests[i]["reason"] = reason

        # If the test function did not return a network, it is not possible to continue
        if new_network is None:
            raise ValueError(f"Network returned by {s.test_name(test)} is None")

        # If the network was changed (e.g. recovery test), stop the previous network
        # and use the new network from now on
        if new_network != network:
            network.stop_all_nodes()
            network = new_network

        LOG.debug(f"Test {s.test_name(test)} took {test_elapsed:.2f} secs")

        # For now, if a test fails, the entire test suite if stopped
        if status is TestStatus.failure:
            success = False
            break

        elapsed -= test_elapsed

    network.stop_all_nodes()

    LOG.success(f"Ran {len(run_tests)}/{len(s.tests)} tests:")
    LOG.success(f"\n{json.dumps(run_tests, indent=4)}")

    if not success:
        sys.exit(1)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--test-duration", help="Duration of suite of tests (s)", type=int
        )

    args = infra.e2e_args.cli_args(add)
    args.package = args.app_script and "liblua_generic" or "liblogging"

    run(args)
