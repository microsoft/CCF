import e2e_logging
import reconfiguration
import e2e_args
import infra.ccf
import time
import json

from loguru import logger as LOG


tests = [
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_from_backup,
    reconfiguration.test_add_as_many_pending_nodes,
    reconfiguration.test_add_node_untrusted_code,
    reconfiguration.test_retire_node,
    e2e_logging.test,
]


def run(args):

    hosts = ["localhost", "localhost"]
    network = infra.ccf.Network(hosts, args.debug_nodes, args.perf_nodes)
    network.start_and_join(args)

    tests_run = {}
    elapsed = args.test_time
    for test in tests:
        test_name = f"{test.__module__}.{test.__name__}"

        if elapsed <= 0:
            LOG.info("Timeout elapsed")
            break

        try:
            LOG.success(f"Running {test_name}")
            test_time_before = time.time()
            new_network = test(network, args)
            success = "OK"
        except AssertionError:
            LOG.error("Test failed")
            new_network = network
            success = "FAIL (Assertion)"
            # TODO: If the network was modified in a bad way, should we stop the test?
        finally:
            test_elapsed = time.time() - test_time_before
            tests_run[test_name] = {
                "success": success,
                "elapsed": round(test_elapsed, 2),
            }
            if new_network == network:
                LOG.success("Network unchanged")
            else:
                LOG.success("Network has changed")

            LOG.warning(f"Test {test_name} took {test_elapsed:.2f} secs")

            elapsed -= test_elapsed

    LOG.success(f"Ran {len(tests_run)} tests:")
    LOG.success(f"\n{json.dumps(tests_run, indent=4)}")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--test-time", help="Time to run the suite of test for (s)", type=int
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"

    run(args)
