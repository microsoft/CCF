# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import infra.network
import suite.test_suite as s
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.jwt_issuer
import time
import json
import sys
from enum import Enum, auto
import random
import os
import re

from loguru import logger as LOG


class TestStatus(Enum):
    success = auto()
    failure = auto()
    skipped = auto()


def mem_stats(network):
    mem = {}
    for node in network.get_joined_nodes():
        try:
            with node.client() as c:
                r = c.get("/node/memory", timeout=0.1)
                mem[node.local_node_id] = r.body.json()
        except Exception:
            pass
    return mem


def run(args):
    chosen_suite = []

    if args.dry_run:
        LOG.warning("--dry-run set. Test execution will be skipped")

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

    args.throws_if_reqs_not_met = True

    jwt_issuer = infra.jwt_issuer.JwtIssuer("https://localhost")

    if not args.dry_run:
        jwt_server = jwt_issuer.start_openid_server()

    txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
    network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        txs=txs,
        jwt_issuer=jwt_issuer,
    )

    if not args.dry_run:
        network.start_and_open(args)

    LOG.info(f"Running {len(chosen_suite)} tests for {args.test_duration} seconds")

    run_tests = {}
    success = True
    elapsed = args.test_duration

    if args.filter is not None:
        filter_re = re.compile(args.filter)

        def filter_fun(x):
            return filter_re is None or filter_re.match(x[1].__name__)

        tests_to_run = filter(filter_fun, enumerate(chosen_suite))
    else:
        tests_to_run = enumerate(chosen_suite)

    for i, test in tests_to_run:
        status = None
        reason = None

        if elapsed <= 0:
            LOG.warning(f"Test duration time ({args.test_duration} seconds) is up!")
            break

        try:
            if not args.dry_run:
                LOG.debug(f"Running {s.test_name(test)}...")
            test_time_before = time.time()

            # Actually run the test
            if not args.dry_run:
                new_network = test(network, args)
            else:
                new_network = network
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
        run_tests[i] = {"name": s.test_name(test)}

        if not args.dry_run:
            run_tests[i].update(
                {
                    "status": status.name,
                    "elapsed (s)": round(test_elapsed, 2),
                    "memory": mem_stats(new_network),
                }
            )

        if reason is not None:
            run_tests[i]["reason"] = reason

        # If the test function did not return a network, it is not possible to continue
        if new_network is None:
            raise ValueError(f"Network returned by {s.test_name(test)} is None")

        # If the network was changed (e.g. recovery test), use the new network from now on
        if new_network != network:
            network = new_network

        if not args.dry_run:
            LOG.debug(f"Test {s.test_name(test)} took {test_elapsed:.2f} secs")

        # For now, if a test fails, the entire test suite if stopped
        if status is TestStatus.failure:
            success = False
            break

        elapsed -= test_elapsed

    if not args.dry_run:
        network.stop_all_nodes(skip_verification=True)
        jwt_server.stop()

    if success:
        LOG.success(f"Full suite passed. Ran {len(run_tests)}/{len(chosen_suite)}")
    else:
        LOG.error(f"Suite failed. Ran {len(run_tests)}/{len(chosen_suite)}")

    if seed:
        LOG.info(f"Full suite was shuffled with seed: {seed}")

    for idx, test in run_tests.items():
        if "status" not in test:
            log_fn = LOG.info
        else:
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
        parser.add_argument(
            "--filter",
            help="Regular expression specifying which tests of a test suite to run",
            type=str,
            default=None,
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="If set, tests execution is skipped",
            default=False,
        )
        parser.add_argument(
            "--jinja-templates-path",
            help="Path to directory containing sample Jinja templates",
            required=True,
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 3
    args.jwt_key_refresh_interval_s = 1
    run(args)
