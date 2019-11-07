# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.import test_suite

import e2e_args
import infra.ccf
import test_suite
import time
import json

from inspect import signature, Parameter
from loguru import logger as LOG


def test_name(test):
    return f"{test.__module__}.{test.__name__}"


def validate_tests_signature(suite):
    """
    Validates that the test functions signatures are in the correct format
    """
    valid_sig = signature(test_suite.test_example)

    for test in suite:
        sig = signature(test)

        assert len(sig.parameters) >= len(
            valid_sig.parameters
        ), f"{test_name(test)} should have at least {len(valid_sig.parameters)} parameters"

        p_index = 0
        for p, v in zip(sig.parameters.items(), valid_sig.parameters.items()):
            assert (
                p[0] == v[0]
            ), f'Signature of {test_name(test)} does not contain "{v[0]}" parameter in the right order'
            p_index += 1

        for p in list(sig.parameters.values())[p_index:]:
            assert (
                p.default is not Parameter.empty
            ), f'Signature of {test_name(test)} includes custom non-defaulted parameter "{p}"'


def run(args):

    validate_tests_signature(test_suite.tests)

    hosts = ["localhost", "localhost"]
    network = infra.ccf.Network(hosts, args.debug_nodes, args.perf_nodes)
    network.start_and_join(args)

    LOG.info(f"Running {len(test_suite.tests)} tests for {args.test_duration} seconds")

    run_tests = {}
    elapsed = args.test_duration

    for test in test_suite.tests:
        success = False

        if elapsed <= 0:
            LOG.warning(f"Test duration time ({args.test_duration} seconds) is up!")
            break

        try:
            LOG.info(f"Running {test_name(test)}...")
            test_time_before = time.time()
            new_network = test(network, args)
            success = True
        except Exception as e:
            LOG.exception(f"Test {test_name(test)} failed")
            new_network = network
        finally:
            test_elapsed = time.time() - test_time_before
            run_tests[test_name(test)] = {
                "success": success,
                "elapsed": round(test_elapsed, 2),
            }

            if new_network is None:
                raise ValueError(f"Network returned by {test_name(test)} is None")

            # If the network was changed (e.g. recovery test), stop the previous network
            # and use the new network from now on
            if new_network != network:
                network.stop_all_nodes()
                network = new_network

            LOG.info(f"Test {test_name(test)} took {test_elapsed:.2f} secs")

            # For now, if a test fails, the entire test suite if stopped
            if success is not True:
                break

            elapsed -= test_elapsed

    LOG.success(f"Ran {len(run_tests)}/{len(test_suite.tests)} tests:")
    LOG.success(f"\n{json.dumps(run_tests, indent=4)}")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--test-duration", help="Duration of suite of tests (s)", type=int
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"

    run(args)
