import e2e_logging
import e2e_args
import infra.ccf
import time

from loguru import logger as LOG


tests = [e2e_logging.test]


def run(args):

    hosts = ["localhost", "localhost"]

    network = infra.ccf.Network(hosts, args.debug_nodes, args.perf_nodes)

    network.start_and_join(args)

    elapsed = args.test_time

    for test in tests:
        if elapsed <= 0:
            LOG.info("Timeout elapsed")
            break

        LOG.success(f"Running {test.__module__}")
        test_time_before = time.time()
        new_network = test(network, args)
        test_elapsed = time.time() - test_time_before
        LOG.warning(f"Test {test.__module__} took {test_elapsed} secs")

        elapsed -= test_elapsed

        if new_network == network:
            LOG.success("Network unchanged")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--test-time", help="Time to run the suite of test for (s)", type=int
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"

    run(args)
