# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import time
import infra.network
import infra.proc
import infra.checker
import contextlib
import resource
import psutil
from ccf.log_capture import flush_info
from ccf.clients import CCFConnectionException, client as ccf_client
import random
import http

from loguru import logger as LOG


class AllConnectionsCreatedException(Exception):
    """
    Raised if we expected a node to refuse connections, but it didn't
    """


def get_session_metrics(node):
    with node.client() as c:
        r = c.get("/node/metrics")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        return r.body.json()["sessions"]


def interface_caps(i):
    return {
        f"127.{i}.0.1": 2,
        f"127.{i}.0.2": 5,
    }


def run(args):
    # Set a relatively low cap on max open sessions, so we can saturate it in a reasonable amount of time
    args.max_open_sessions = 100
    args.max_open_sessions_hard = args.max_open_sessions + 20

    # Listen on additional RPC interfaces with even lower session caps
    for i, node_spec in enumerate(args.nodes):
        additional_args = []
        caps = interface_caps(i)
        for address, cap in caps.items():
            additional_args.append(f"--rpc-interface={address},,{cap}")
        node_spec.additional_raw_node_args = additional_args

    # Chunk often, so that new fds are regularly requested
    args.ledger_chunk_bytes = "500B"

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        check = infra.checker.Checker()
        network.start_and_join(args)
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
        main_session_metrics = initial_metrics["interfaces"][
            f"{primary.host}:{primary.rpc_port}"
        ]
        assert (
            main_session_metrics["soft_cap"] == args.max_open_sessions
        ), initial_metrics
        assert (
            main_session_metrics["hard_cap"] == args.max_open_sessions_hard
        ), initial_metrics

        max_fds = args.max_open_sessions + (initial_fds * 2)

        def create_connections_until_exhaustion(
            target, continue_to_hard_cap=False, client_fn=primary.client
        ):
            with contextlib.ExitStack() as es:
                clients = []
                LOG.success(f"Creating {target} clients")
                consecutive_failures = 0
                i = 1
                while i <= target:
                    logs = []
                    try:
                        clients.append(
                            es.enter_context(client_fn(identity="user0", connection_timeout=1))
                        )
                        r = clients[-1].post(
                            "/app/log/private",
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
                    except (CCFConnectionException, RuntimeError) as e:
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

                r = clients[-1].get("/node/metrics")
                assert r.status_code == http.HTTPStatus.OK, r.status_code
                peak_metrics = r.body.json()["sessions"]
                assert peak_metrics["active"] <= peak_metrics["peak"], peak_metrics
                assert peak_metrics["active"] >= len(clients), (
                    peak_metrics,
                    len(clients),
                )

                # Submit many requests, and at least enough to trigger additional snapshots
                more_requests = max(len(clients) * 3, args.snapshot_tx_interval * 2)
                LOG.info(
                    f"Submitting an additional {more_requests} requests from existing clients"
                )
                for _ in range(more_requests):
                    client = random.choice(clients)
                    logs = []
                    try:
                        client.post(
                            "/app/log/private",
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

        # Check that lower caps on separate caps are enforced on each interface
        for i, (address, cap) in enumerate(caps.items()):
            create_connections_until_exhaustion(
                cap + 1,
                client_fn=lambda **kwargs: primary.client(interface_idx=i+1, **kwargs),
            )

        try:
            create_connections_until_exhaustion(to_create, True)
        except AllConnectionsCreatedException as e:
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

        # Now set a low fd limit, so network sessions completely exhaust them - expect this to cause failures
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
            raise RuntimeError("Expected a fatal crash and saw none!")


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
