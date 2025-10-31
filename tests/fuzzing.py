# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import struct
import boofuzz
import datetime
from loguru import logger as LOG


class CCFFuzzLogger(boofuzz.IFuzzLogger):
    def __init__(self, print_period=datetime.timedelta(seconds=3), keep_lines=50):
        self.log_lines = []
        self.print_period = print_period
        self.last_printed = None
        self.keep_lines = keep_lines
        self.last_fuzzed_count = 0

        self.session = None

    def _store_line(self, s):
        self.log_lines.append(s)
        self.log_lines = self.log_lines[-self.keep_lines :]

        if self.session is not None:
            now = datetime.datetime.now()
            if self.last_printed is None or now - self.last_printed > self.print_period:
                fuzzed_this_period = (
                    self.session.num_cases_actually_fuzzed - self.last_fuzzed_count
                )
                fuzzing_rate = fuzzed_this_period / self.print_period.seconds
                LOG.info(
                    f"Fuzzed {self.session.num_cases_actually_fuzzed} total cases in {self.session.runtime:.2f}s (current rate={fuzzing_rate:.2f}/s)"
                )
                self.last_printed = now
                self.last_fuzzed_count = self.session.num_cases_actually_fuzzed

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._store_line(f"Test case: {name} ({index=})")

    def open_test_step(self, description):
        self._store_line(f" Test step: {description}")

    def log_send(self, data):
        self._store_line(infra.clients.escape_loguru_tags(f"  Sent: {data}"))

    def log_recv(self, data):
        self._store_line(infra.clients.escape_loguru_tags(f"  Received: {data}"))

    def log_check(self, description):
        self._store_line(f"  Checking: {description}")

    def log_pass(self, description=""):
        self._store_line(f"  Passed: {description}")

    def log_fail(self, description=""):
        self._store_line(f"  Fail: {description}")

    def log_info(self, description):
        self._store_line(f"  {description}")

    def log_error(self, description):
        self._store_line(f"  Error: {description}")

    def close_test_case(self):
        pass

    def close_test(self):
        pass


def ccf_node_post_send(node):
    def post_send_callback(fuzz_data_logger=None, *args, **kwargs):
        done = node.remote.check_done()
        if done:
            fuzz_data_logger.log_error("Node has exited")
        return done

    return post_send_callback


def ccf_node_restart_callback(*args, **kwargs):
    raise boofuzz.exception.BoofuzzRestartFailedError(
        "CCF nodes cannot be restarted - see earlier failure"
    )


def fuzz_node_to_node(network, args):
    req = boofuzz.Request(
        "N2N",
        children=[
            boofuzz.Block(
                "Header",
                children=[
                    boofuzz.Size(
                        "TotalSize",
                        block_name="N2N",
                        length=4,
                        # Non-inclusive. inclusive=False doesn't work, so manually offset
                        offset=-4,
                    ),
                    boofuzz.Group(
                        "MessageType",
                        values=[struct.pack("<Q", msg_type) for msg_type in (0, 1, 2)],
                    ),
                    boofuzz.Block(
                        "SenderID",
                        children=[
                            boofuzz.Size(
                                "SenderSize",
                                block_name="SenderContent",
                                length=8,
                                inclusive=False,
                            ),
                            boofuzz.RandomData(
                                "SenderContent",
                                default_value="OtherNode".encode(),
                                max_length=32,
                            ),
                        ],
                    ),
                ],
            ),
            boofuzz.Block(
                "Body",
                children=[
                    boofuzz.RandomData(
                        "BodyContent",
                        max_length=128,
                    ),
                ],
            ),
        ],
    )

    primary, _ = network.find_primary()
    interface = primary.n2n_interface

    fuzz_logger = CCFFuzzLogger()
    session = boofuzz.Session(
        target=boofuzz.Target(
            connection=boofuzz.TCPSocketConnection(interface.host, interface.port),
        ),
        # Check if the node process is alive after each send
        post_test_case_callbacks=[ccf_node_post_send(primary)],
        # Fail if ever asked to restart a node
        restart_callbacks=[ccf_node_restart_callback],
        # Use loguru output formatted like everything else
        fuzz_loggers=[fuzz_logger],
        # Don't try to host a web UI
        web_port=None,
        # Don't try to read any responses
        receive_data_after_fuzz=False,
        receive_data_after_each_request=False,
    )
    fuzz_logger.session = session

    LOG.info(f"Loggers before monkey-patch: {session._fuzz_data_logger._fuzz_loggers}")
    # Monkey-patch: Remove any Db loggers from the boofuzz session. We never
    # use them, and they're reliant on disk IO (for db commits) so sometimes very slow
    session._fuzz_data_logger._fuzz_loggers = [
        logger
        for logger in session._fuzz_data_logger._fuzz_loggers
        if not isinstance(logger, boofuzz.fuzz_logger_db.FuzzLoggerDb)
    ]
    session._db_logger = None
    LOG.info(f"Loggers after monkey-patch: {session._fuzz_data_logger._fuzz_loggers}")

    session.connect(req)

    LOG.warning("These tests are verbose and run for a long time")
    LOG.warning(
        f"Limiting spam by summarising every {fuzz_logger.print_period.total_seconds()}s"
    )

    LOG.info("Confirming non-fuzzed request format")
    try:
        session.feature_check()
    except:
        LOG.error("Error during feature check")
        LOG.error(
            "Recent fuzz session output was:\n" + "\n".join(fuzz_logger.log_lines)
        )
        raise

    LOG.info("Fuzzing")
    try:
        session.fuzz(max_depth=2)
    except:
        LOG.error("Error during fuzzing")
        LOG.error(
            "Recent fuzz session output was:\n" + "\n".join(fuzz_logger.log_lines)
        )
        raise

    LOG.info(f"Fuzzed {session.num_cases_actually_fuzzed} cases")


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        # Don't fill the output with failure messages from fuzzing
        network.ignore_error_pattern_on_shutdown(
            "Exception in bool ccf::Channel::recv_key_exchange_message"
        )
        network.ignore_error_pattern_on_shutdown(
            "Exception in void ccf::Forwarder<ccf::NodeToNode>::recv_message"
        )
        network.ignore_error_pattern_on_shutdown("Unknown node message type")
        network.ignore_error_pattern_on_shutdown("Unhandled AFT message type")
        network.ignore_error_pattern_on_shutdown("Unknown frontend msg type")

        fuzz_node_to_node(network, args)
