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
from infra.snp import IS_SNP

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


def run(args):
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
                            timeout=3 if IS_SNP else 1,
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


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"

    # Set a relatively low cap on max open sessions, so we can saturate it in a reasonable amount of time
    args.max_open_sessions = 40
    args.max_open_sessions_hard = args.max_open_sessions + 5

    args.nodes = infra.e2e_args.nodes(args, 1)
    args.initial_user_count = 1
    run(args)
