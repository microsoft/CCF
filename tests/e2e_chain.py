import e2e_logging
import reconfiguration
import recovery
import e2e_args
import infra.ccf
import time
import json

from loguru import logger as LOG


# TODO: Move this and includes to a different file
tests = [
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_from_backup,
    reconfiguration.test_add_as_many_pending_nodes,
    reconfiguration.test_add_node_untrusted_code,
    reconfiguration.test_retire_node,
    e2e_logging.test,
    e2e_logging.test_update_lua,
    recovery.test,
]


def run(args):

    hosts = ["localhost", "localhost"]
    network = infra.ccf.Network(hosts, args.debug_nodes, args.perf_nodes)
    network.start_and_join(args)

    LOG.info(f"Running {len(tests)} tests for {args.test_duration} seconds")

    run_tests = {}
    elapsed = args.test_duration

    for test in tests:
        test_name = f"{test.__module__}.{test.__name__}"
        success = False

        if elapsed <= 0:
            LOG.warning(f"Test duration time ({args.test_duration} seconds) is up!")
            break

        try:
            LOG.info(f"Running {test_name}...")
            test_time_before = time.time()
            new_network = test(network, args)
            success = True
        except Exception as e:
            LOG.exception(f"Test {test_name} failed")
            new_network = network
        finally:
            test_elapsed = time.time() - test_time_before
            run_tests[test_name] = {
                "success": success,
                "elapsed": round(test_elapsed, 2),
            }

            # If the network was changed (e.g. recovery test), stop the previous network
            # and use the new network from now on
            if new_network != network:
                network.stop_all_nodes()
                network = new_network

            LOG.info(f"Test {test_name} took {test_elapsed:.2f} secs")

            # For now, if a test fails, the entire test suite if stopped
            if success is not True:
                break

            elapsed -= test_elapsed

    LOG.success(f"Ran {len(run_tests)}/{len(tests)} tests:")
    LOG.success(f"\n{json.dumps(run_tests, indent=4)}")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--test-duration", help="Duration of suite of tests (s)", type=int
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"

    run(args)
