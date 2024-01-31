# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import struct
import boofuzz

from loguru import logger as LOG


class CCFFuzzLogger(boofuzz.IFuzzLogger):
    def __init__(self):
        self.indent_level = 0

    def _indent(self):
        return "  " * self.indent_level

    def _fuzz_log(self, s, fn="info", **kwargs):
        logger = getattr(LOG.opt(**kwargs), fn)
        logger(s)

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._fuzz_log(f"<yellow>Test case: {name} ({index=})</>", colors=True)
        self.indent_level += 2

    def open_test_step(self, description):
        self.indent_level -= 1
        self._fuzz_log(
            f"<magenta>{self._indent()}Test step: {description}</>", colors=True
        )
        self.indent_level += 1

    def log_send(self, data):
        self._fuzz_log(f"{self._indent()}Sent: {data}", fn="debug")

    def log_recv(self, data):
        self._fuzz_log(f"{self._indent()}Received: {data}", fn="debug")

    def log_check(self, description):
        self._fuzz_log(f"{self._indent()}Checking: {description}", fn="debug")

    def log_pass(self, description=""):
        self._fuzz_log(f"{self._indent()}Passed: {description}", fn="success")

    def log_fail(self, description=""):
        self._fuzz_log(f"{self._indent()}Fail: {description}", fn="warning")

    def log_info(self, description):
        self._fuzz_log(f"{self._indent()}{description}")

    def log_error(self, description):
        self._fuzz_log(f"{self._indent()}Error: {description}", fn="error")

    def close_test_case(self):
        self.indent_level -= 2

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
            # TODO: Different types of body, based on message type?
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

    session = boofuzz.Session(
        target=boofuzz.Target(
            connection=boofuzz.TCPSocketConnection(interface.host, interface.port),
        ),
        # Check if the node process is alive after each send
        post_test_case_callbacks=[ccf_node_post_send(primary)],
        # Fail if ever asked to restart a node
        restart_callbacks=[ccf_node_restart_callback],
        # Use loguru output formatted like everything else
        fuzz_loggers=[CCFFuzzLogger()],
        # Don't try to host a web UI
        web_port=None,
        # Don't try to read any responses
        receive_data_after_fuzz=False,
        receive_data_after_each_request=False,
    )

    session.connect(req)

    LOG.info("Confirming non-fuzzed request format")
    session.feature_check()

    LOG.info(f"Fuzzing")
    session.fuzz(max_depth=2)


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
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


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
