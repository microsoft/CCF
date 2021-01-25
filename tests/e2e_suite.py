# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import infra.network
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


def mem_stats(network):
    mem = {}
    for node in network.get_joined_nodes():
        try:
            with node.client() as c:
                r = c.get("/node/memory", 0.1)
                mem[node.node_id] = r.body.json()
        except Exception:
            pass
    return mem


def run(args):

    chosen_suite = []

    if not args.test_suite:
        args.test_suite = ["all"]

    for choice in args.test_suite:
        try:
            chosen_suite.extend(s.suites[choice])
        except KeyError as e:
            raise ValueError(f"Unhandled choice: {choice}") from e

    seed = None
    if os.getenv("SHUFFLE_SUITE"):
        seed = os.getenv("SHUFFLE_SUITE_SEED")
        if seed is None:
            seed = time.time()
        seed = int(seed)
        LOG.success(f"Shuffling full suite with seed {seed}")
        random.seed(seed)
        random.shuffle(chosen_suite)
    s.validate_tests_signature(chosen_suite)

    if args.enforce_reqs is False:
        LOG.warning("Test requirements will be ignored")

    txs = app.LoggingTxs()
    network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, txs=txs
    )
    network.start_and_join(args)

    LOG.info(f"Running {len(chosen_suite)} tests for {args.test_duration} seconds")

    run_tests = {}
    success = True
    elapsed = args.test_duration

    for i, test in enumerate(chosen_suite):
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

        except Exception:
            LOG.exception(f"Test {s.test_name(test)} failed")
            status = TestStatus.failure
            new_network = network

        test_elapsed = time.time() - test_time_before

        # Construct test report
        run_tests[i] = {
            "name": s.test_name(test),
            "status": status.name,
            "elapsed (s)": round(test_elapsed, 2),
            "memory": mem_stats(network),
        }

        if reason is not None:
            run_tests[i]["reason"] = reason

        # If the test function did not return a network, it is not possible to continue
        if new_network is None:
            raise ValueError(f"Network returned by {s.test_name(test)} is None")

        # If the network was changed (e.g. recovery test), stop the previous network
        # and use the new network from now on
        if new_network != network:
            # network.stop_all_nodes()
            network = new_network

        LOG.debug(f"Test {s.test_name(test)} took {test_elapsed:.2f} secs")

        # For now, if a test fails, the entire test suite if stopped
        if status is TestStatus.failure:
            success = False
            break

        elapsed -= test_elapsed

    network.stop_all_nodes()

    if success:
        LOG.success(f"Full suite passed. Ran {len(run_tests)}/{len(chosen_suite)}")
    else:
        LOG.error(f"Suite failed. Ran {len(run_tests)}/{len(chosen_suite)}")

    if seed:
        LOG.info(f"Full suite was shuffled with seed: {seed}")

    for idx, test in run_tests.items():
        status = test["status"]
        if status == TestStatus.success.name:
            log_fn = LOG.success
        elif status == TestStatus.skipped.name:
            log_fn = LOG.warning
        else:
            log_fn = LOG.error
        log_fn(f"Test #{idx}:\n{json.dumps(test, indent=4)}")

    if not success:
        sys.exit(1)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--test-duration", help="Duration of full suite (s)", type=int
        )
        parser.add_argument(
            "--test-suite",
            help="List of test suites should be run",
            action="append",
            choices=s.suites.keys(),
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 3
    run(args)
