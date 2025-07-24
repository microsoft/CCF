# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import time
import infra.network
import infra.proc
import infra.checker
import infra.interfaces
import contextlib
import resource
import psutil
from infra.log_capture import flush_info
from infra.clients import CCFConnectionException, CCFIOException
import random
import http
import functools
import httpx
import os
import socket
import struct
from infra.runner import ConcurrentRunner

from loguru import logger as LOG


class AllConnectionsCreatedException(Exception):
    """
    Raised if we expected a node to refuse connections, but it didn't
    """


def get_session_metrics(node, timeout=3):
    with node.client() as c:
        end_time = time.time() + timeout
        while time.time() < end_time:
            r = c.get("/node/metrics")
            if r.status_code == http.HTTPStatus.OK:
                return r.body.json()["sessions"]
            time.sleep(0.1)
        assert r.status_code == http.HTTPStatus.OK, r


def interface_caps(i):
    return {
        "first_interface": {
            "bind_address": f"127.{i}.0.1",
            "max_open_sessions_soft": 2,
        },
        "second_interface": {
            "bind_address": f"127.{i}.0.2",
            "max_open_sessions_soft": 5,
        },
    }


def run_connection_caps_tests(args):
    # Listen on additional RPC interfaces with even lower session caps
    for i, node_spec in enumerate(args.nodes):
        caps = interface_caps(i)
        for interface_name, interface in caps.items():
            node_spec.rpc_interfaces[interface_name] = infra.interfaces.RPCInterface(
                host=interface["bind_address"],
                max_open_sessions_soft=interface["max_open_sessions_soft"],
            )

    # Chunk often, so that new fds are regularly requested
    args.ledger_chunk_bytes = "500B"

    supp_file = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "connections.supp"
    )
    args.ubsan_options = "suppressions=" + str(supp_file)

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        check = infra.checker.Checker()
        network.start_and_open(args)
        primary, _ = network.find_nodes()

        caps = interface_caps(primary.local_node_id)

        primary_pid = primary.remote.remote.proc.pid

        initial_fds = psutil.Process(primary_pid).num_fds()
        assert (
            initial_fds < args.max_open_sessions
        ), f"Initial number of file descriptors has already reached session limit: {initial_fds} >= {args.max_open_sessions}"

        num_fds = initial_fds
        LOG.success(f"{primary_pid} has {num_fds} open file descriptors")

        initial_metrics = get_session_metrics(primary)
        assert initial_metrics["active"] <= initial_metrics["peak"], initial_metrics

        for interface_name, rpc_interface in primary.host.rpc_interfaces.items():
            metrics = initial_metrics["interfaces"][interface_name]
            assert metrics["soft_cap"] == rpc_interface.max_open_sessions_soft, metrics
            assert metrics["hard_cap"] == rpc_interface.max_open_sessions_hard, metrics

        max_fds = args.max_open_sessions + (initial_fds * 2)

        def create_connections_until_exhaustion(
            target, continue_to_hard_cap=False, client_fn=primary.client
        ):
            with contextlib.ExitStack() as es:
                clients = []
                LOG.success(f"Creating {target} clients")
                consecutive_failures = 0
                i = 1
                healthy_clients = []
                while i <= target:
                    logs = []
                    try:
                        clients.append(
                            es.enter_context(
                                client_fn(
                                    identity="user0",
                                    connection_timeout=1,
                                    limits=httpx.Limits(
                                        max_connections=1,
                                        max_keepalive_connections=1,
                                        keepalive_expiry=30,
                                    ),
                                )
                            )
                        )
                        r = clients[-1].post(
                            "/log/private",
                            {"id": 42, "msg": "foo"},
                            log_capture=logs,
                        )
                        if r.status_code == http.HTTPStatus.OK:
                            check(
                                r,
                                result=True,
                            )
                            consecutive_failures = 0
                            i += 1
                            healthy_clients.append(clients[-1])
                        elif r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE:
                            if continue_to_hard_cap:
                                consecutive_failures = 0
                                i += 1
                                continue
                            raise RuntimeError(r.body.text())
                        else:
                            flush_info(logs)
                            raise ValueError(
                                f"Unexpected response status code: {r.status_code}"
                            )
                    except (CCFConnectionException, CCFIOException, RuntimeError) as e:
                        flush_info(logs)
                        LOG.warning(f"Hit exception at client {i}/{target}: {e}")
                        clients.pop(-1)
                        if consecutive_failures < 5:
                            # Maybe got unlucky and tried to create a session while many files were open - keep trying
                            consecutive_failures += 1
                            continue
                        else:
                            # Ok you've really hit a wall, stop trying to create clients
                            break
                else:
                    raise AllConnectionsCreatedException(
                        f"Successfully created {target} clients without exception - expected this to exhaust available connections"
                    )

                num_fds = psutil.Process(primary_pid).num_fds()
                LOG.success(
                    f"{primary_pid} has {num_fds}/{max_fds} open file descriptors"
                )
                r = clients[0].get("/node/metrics")
                assert r.status_code == http.HTTPStatus.OK, r.status_code
                peak_metrics = r.body.json()["sessions"]
                assert peak_metrics["active"] <= peak_metrics["peak"], peak_metrics
                assert peak_metrics["active"] == len(healthy_clients), (
                    peak_metrics,
                    len(healthy_clients),
                )

                # Submit many requests, and at least enough to trigger additional snapshots
                more_requests = max(len(clients) * 3, args.snapshot_tx_interval * 2)
                LOG.info(
                    f"Submitting an additional {more_requests} requests from existing clients"
                )
                for _ in range(more_requests):
                    client = random.choice(healthy_clients)
                    logs = []
                    try:
                        client.post(
                            "/log/private",
                            {"id": 42, "msg": "foo"},
                            timeout=1,
                            log_capture=logs,
                        )
                    except Exception as e:
                        flush_info(logs)
                        LOG.error(e)
                        raise e

                time.sleep(1)
                num_fds = psutil.Process(primary_pid).num_fds()
                LOG.success(
                    f"{primary_pid} has {num_fds}/{max_fds} open file descriptors"
                )

                LOG.info("Disconnecting clients")
                clients = []

            time.sleep(1)
            num_fds = psutil.Process(primary_pid).num_fds()
            LOG.success(f"{primary_pid} has {num_fds}/{max_fds} open file descriptors")
            return num_fds

        # For initial safe tests, we have many more fds than the maximum sessions, so file operations should still succeed even when network is saturated
        resource.prlimit(primary_pid, resource.RLIMIT_NOFILE, (max_fds, max_fds))
        LOG.success(f"Setting max fds to safe initial value {max_fds} on {primary_pid}")

        nb_conn = (max_fds - num_fds) * 2
        num_fds = create_connections_until_exhaustion(nb_conn)

        to_create = max_fds - num_fds + 1
        num_fds = create_connections_until_exhaustion(to_create)

        LOG.info("Check that lower caps are enforced on each interface")
        for name, interface in caps.items():
            create_connections_until_exhaustion(
                interface["max_open_sessions_soft"] + 1,
                client_fn=functools.partial(primary.client, interface_name=name),
            )

        try:
            create_connections_until_exhaustion(to_create, True)
        except AllConnectionsCreatedException:
            # This is fine! The soft cap means this test no longer reaches the hard cap.
            # It gets HTTP errors but then _closes_ sockets, fast enough that we never hit the hard cap
            pass

        final_metrics = get_session_metrics(primary)
        assert final_metrics["active"] <= final_metrics["peak"], final_metrics
        assert final_metrics["peak"] > initial_metrics["peak"], (
            initial_metrics,
            final_metrics,
        )
        assert final_metrics["peak"] >= args.max_open_sessions, final_metrics
        assert final_metrics["peak"] < args.max_open_sessions_hard, final_metrics

        LOG.info(
            "Set a low fd limit, so network sessions completely exhaust them - expect this to cause node failures"
        )
        max_fds = args.max_open_sessions // 2
        resource.prlimit(primary_pid, resource.RLIMIT_NOFILE, (max_fds, max_fds))
        LOG.success(f"Setting max fds to dangerously low {max_fds} on {primary_pid}")

        try:
            num_fds = create_connections_until_exhaustion(to_create)
        except Exception as e:
            LOG.warning(
                f"Node with only {max_fds} fds crashed when allowed to created {args.max_open_sessions} sessions, as expected"
            )
            LOG.warning(e)
            network.ignore_errors_on_shutdown()
        else:
            LOG.warning("Expected a fatal crash and saw none!")


def run_idle_timeout_tests(args):
    test_cases = [
        {"timeout": 5, "safe_sleeps": [2, 3], "killed_sleeps": [10]},
        {
            "timeout": None,
            "safe_sleeps": [10],
        },  # With no timeout, idle sessions are never killed
    ]

    def verbose_sleep(sleep_time):
        slept = 0
        step_size = 1
        LOG.info(f"Sleeping {sleep_time}s")
        while slept < sleep_time:
            next_sleep = min(sleep_time - slept, step_size)
            time.sleep(next_sleep)
            slept += next_sleep
            LOG.debug(f"Slept {slept}/{sleep_time}s")

    for test_case in test_cases:
        timeout = test_case.get("timeout")
        args.idle_connection_timeout_s = timeout

        with infra.network.network(
            args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            network.start_and_open(args)

            primary, _ = network.find_primary()

            safe_sleeps = test_case.get("safe_sleeps", None)
            if safe_sleeps:
                for sleep_time in safe_sleeps:
                    with primary.client(
                        "user0",
                        impl_type=infra.clients.RawSocketClient,
                    ) as c:
                        r = c.get("/node/commit")
                        assert r.status_code == http.HTTPStatus.OK, r

                        verbose_sleep(sleep_time)

                        r = c.get("/node/commit")
                        assert r.status_code == http.HTTPStatus.OK, r

            killed_sleeps = test_case.get("killed_sleeps", None)
            if killed_sleeps:
                for sleep_time in killed_sleeps:
                    with primary.client(
                        "user0",
                        impl_type=infra.clients.RawSocketClient,
                    ) as c:
                        r = c.get("/node/commit")
                        assert r.status_code == http.HTTPStatus.OK, r

                        verbose_sleep(sleep_time)

                        try:
                            r = c.get("/node/commit")
                        except http.client.RemoteDisconnected:
                            pass
                        else:
                            assert (
                                False
                            ), f"Expected sleep of {sleep_time}s to result in disconnection (given {timeout}s idle timeout)"


@contextlib.contextmanager
def node_tcp_socket(node):
    interface = node.n2n_interface
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((interface.host, interface.port))
    yield s
    s.close()


# NB: This does rudimentary smoke testing. See fuzzing.py for more thorough test
def run_node_socket_robustness_tests(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_nodes()

        # Protocol is:
        # - 4 byte message size N (remainder is not processed until this many bytes arrive)
        # - 8 byte message type (valid values are only 0, 1, or 2)
        # - Sender node ID (length-prefixed string), consisting of:
        #   - 8 byte string length S
        #   - S bytes of string content
        # - Message body, of N - 16 - S bytes
        # Note number serialization is little-endian!

        def encode_msg(
            msg_type=0,
            sender="OtherNode",
            body=b"",
            sender_len_override=None,
            total_len_override=None,
        ):
            b_type = struct.pack("<Q", msg_type)
            sender_len = sender_len_override or len(sender)
            b_sender = struct.pack("<Q", sender_len) + sender.encode()
            total_len = total_len_override or len(b_type) + len(b_sender) + len(body)
            b_size = struct.pack("<I", total_len)
            encoded_msg = b_size + b_type + b_sender + body
            return encoded_msg

        def try_write(msg_bytes):
            with node_tcp_socket(primary) as sock:
                LOG.debug(
                    f"Sending raw TCP bytes to {primary.local_node_id}'s node-to-node port: {msg_bytes}"
                )
                sock.send(msg_bytes)
                assert (
                    not primary.remote.check_done()
                ), f"Crashed node with N2N message: {msg_bytes}"
                LOG.success(f"Node {primary.local_node_id} tolerated this message")

        LOG.info("Sending messages which do not contain initial size")
        try_write(b"")
        try_write(b"\x00")
        for size in range(1, 4):
            # NB: Regardless of what these bytes contain!
            for i in range(5):
                msg = random.getrandbits(8 * size).to_bytes(size, byteorder="little")
                try_write(msg)

        LOG.info("Sending messages which do not contain initial header")
        for size in range(0, 16):
            try_write(struct.pack("<I", size) + b"\x00" * size)

        LOG.info("Sending plausible messages")
        try_write(encode_msg())
        try_write(encode_msg(msg_type=1))
        try_write(encode_msg(msg_type=100))
        try_write(encode_msg(sender="a"))
        try_write(encode_msg(sender="ab"))
        try_write(encode_msg(sender="abc"))
        try_write(encode_msg(sender="abcd"))
        try_write(encode_msg(sender="abcde"))
        try_write(encode_msg(sender="abcdef"))
        try_write(encode_msg(sender="abcdefg"))
        try_write(encode_msg(body=struct.pack("<QQQQ", 100, 200, 300, 400)))
        try_write(
            encode_msg(
                msg_type=2, sender="abcd", body=struct.pack("<QQQQ", 100, 200, 300, 400)
            )
        )

        LOG.info("Sending messages with incorrect sender length")
        try_write(encode_msg(sender="abcd", sender_len_override=0))
        try_write(encode_msg(sender="abcd", sender_len_override=1))
        try_write(encode_msg(sender="abcd", sender_len_override=5))
        try_write(
            b"\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00bbbb"
        )

        LOG.info("Sending messages with randomised bodies")
        for _ in range(10):
            body_len = random.randrange(10, 100)
            body = random.getrandbits(body_len * 8).to_bytes(body_len, "little")
            try_write(encode_msg(msg_type=random.randrange(0, 3), body=body))

        # Don't fill the output with failure messages from this probing
        network.ignore_error_pattern_on_shutdown(
            "Exception in bool ccf::Channel::recv_key_exchange_message"
        )
        network.ignore_error_pattern_on_shutdown("Unknown node message type")
        network.ignore_error_pattern_on_shutdown("Unhandled AFT message type")
        network.ignore_error_pattern_on_shutdown("Unknown frontend msg type")


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "robustness",
        run_node_socket_robustness_tests,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.nodes(cr.args, 1),
    )

    cr.add(
        "idletimeout",
        run_idle_timeout_tests,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.nodes(cr.args, 1),
    )

    # Need to modify args.max_open_sessions _before_ calling e2e_args.nodes for
    # the connection_caps runner, but _after_ constructing nodes args for other
    # runners.
    # In other words, make sure this is run last.
    cr.args.max_open_sessions = 40
    cr.args.max_open_sessions_hard = cr.args.max_open_sessions + 5
    cr.add(
        "caps",
        run_connection_caps_tests,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.nodes(cr.args, 1),
        initial_user_count=1,
    )

    cr.run()
