# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import concurrent.futures
import contextlib
import http
import json
import signal
import ssl
import subprocess
import sys
import threading
import time

import httpx
import infra.consistency_trace
import infra.e2e_args
import infra.interfaces
import infra.network
from loguru import logger as LOG

FORWARDING_RPC_INTERFACE = "forwarding_rpc_interface"
N2N_MESSAGE_LIMIT = 40
FORWARDING_TIMEOUT_MS = 10000
MAX_DAISY_ATTEMPTS = 5
CHANNEL_BURST_COUNT = 64
MIN_ELECTION_TIMEOUT_MS = 3000


def make_forwarding_interface(forwarding_timeout_ms=FORWARDING_TIMEOUT_MS):
    return infra.interfaces.RPCInterface(
        app_protocol="HTTP1",
        redirections=None,
        forwarding_timeout_ms=forwarding_timeout_ms,
    )


def wait_for_final_tx_status(client, base_url, tx_id, timeout_s=10):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(f"{base_url}/tx", params={"transaction_id": tx_id})
        if r.status_code == http.HTTPStatus.OK:
            body = r.json()
            if body["status"] in ("Committed", "Invalid"):
                infra.consistency_trace.tx_status(body, time.time_ns())
                return body["status"]
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for final status of {tx_id}")


def wait_for_node_view(client, base_url, min_view, timeout_s=10):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(f"{base_url}/node/network")
        if r.status_code == http.HTTPStatus.OK:
            body = r.json()
            if body["current_view"] >= min_view:
                return body
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for node view >= {min_view}")


def wait_for_unknown_primary(client, base_url, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(f"{base_url}/node/network")
        if r.status_code == http.HTTPStatus.OK:
            body = r.json()
            if body["primary_id"] is None:
                return body
        time.sleep(0.05)
    raise TimeoutError("Timed out waiting for node to observe unknown primary")


def run(args):
    args.node_to_node_message_limit = N2N_MESSAGE_LIMIT
    args.election_timeout_ms = max(
        int(args.election_timeout_ms), MIN_ELECTION_TIMEOUT_MS
    )
    forwarding_timeout_ms = max(FORWARDING_TIMEOUT_MS, args.election_timeout_ms * 3)
    daisy_timeout_s = max(15.0, forwarding_timeout_ms / 1000.0 + 5.0)
    for host in args.nodes:
        host.rpc_interfaces[FORWARDING_RPC_INTERFACE] = make_forwarding_interface(
            forwarding_timeout_ms
        )

    with infra.consistency_trace.recording(args), infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, backups = network.find_nodes()
        primary_url = f"https://{primary.get_public_rpc_address()}"
        tls_ctx = ssl.create_default_context(cafile=network.cert_path)

        with contextlib.ExitStack() as stack:
            primary_client = stack.enter_context(
                httpx.Client(verify=tls_ctx, http2=False)
            )
            initial_view = primary_client.get(f"{primary_url}/node/network").json()[
                "current_view"
            ]

            # Exercise /tx query validation and frontend JSON error handling on
            # live nodes within the trace-validated session.
            r = primary_client.get(f"{primary_url}/tx")
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.text
            assert r.json()["error"]["code"] == "InvalidQueryParameterValue", r.text

            r = primary_client.get(
                f"{primary_url}/tx", params={"transaction_id": "not-a-txid"}
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.text
            assert r.json()["error"]["code"] == "InvalidQueryParameterValue", r.text

            r = primary_client.post(f"{primary_url}/node/join", json={})
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.text
            assert r.json()["error"]["code"] == "InvalidInput", r.text

            r = primary_client.post(
                f"{primary_url}/node/join",
                content=b"{not valid json",
                headers={"content-type": "application/json"},
            )
            assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.text
            assert r.json()["error"]["code"] == "InvalidInput", r.text

            # Establish persistent forwarding sessions on both backups in the
            # initial view before any election occurs.
            backup_sessions = {}
            for backup in backups:
                fwd_url = (
                    f"https://{backup.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"
                )
                fwd_client = stack.enter_context(
                    httpx.Client(
                        verify=tls_ctx,
                        http2=False,
                        limits=httpx.Limits(keepalive_expiry=None),
                    )
                )
                r = fwd_client.put(f"{fwd_url}/records/fwd", content=b"value")
                assert r.status_code == http.HTTPStatus.NO_CONTENT, r.text
                tx_id = r.headers["x-ms-ccf-transaction-id"]
                wait_for_final_tx_status(primary_client, primary_url, tx_id)
                backup_sessions[backup] = (fwd_client, fwd_url)

            # Suspend primary to trigger an election and exercise two
            # forwarding consistency guards across the view change:
            # 1. Pre-warm a keep-alive TLS client on daisy_backup (leaving
            #    is_forwarding == False) and forward PUT /records/daisy
            #    immediately after suspending the current primary. The
            #    forwarded packet queues in the old primary's TCP buffer while
            #    the backups elect a new leader; keeping the old primary
            #    suspended past election_timeout normally causes CheckQuorum
            #    step-down before NodeIngress reads the socket, returning
            #    503 RequestAlreadyForwarded. Because NodeIngress vs
            #    CheckQuorum ordering is not strictly guaranteed on resume,
            #    retry up to MAX_DAISY_ATTEMPTS times (recording any 204
            #    write's final status for consistency-replay) until
            #    RequestAlreadyForwarded is observed.
            # 2. On the first election, reusing the remaining backup's
            #    pre-election persistent forwarding session in the new view
            #    hits !check_session_consistency() -> 500 SessionConsistencyLost.
            daisy_observed = False
            session_consistency_checked = False
            for attempt in range(MAX_DAISY_ATTEMPTS):
                if attempt == 0:
                    cur_primary, cur_backups = primary, backups
                    cur_view = initial_view
                else:
                    cur_primary, cur_backups = network.find_nodes()
                    cur_primary_url = f"https://{cur_primary.get_public_rpc_address()}"
                    cur_view = primary_client.get(
                        f"{cur_primary_url}/node/network"
                    ).json()["current_view"]
                    for node in network.get_joined_nodes():
                        wait_for_node_view(
                            primary_client,
                            f"https://{node.get_public_rpc_address()}",
                            cur_view,
                            timeout_s=network.election_duration * 4,
                        )

                daisy_backup = cur_backups[0]
                daisy_fwd_url = f"https://{daisy_backup.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"

                with httpx.Client(
                    verify=tls_ctx,
                    http2=False,
                    timeout=daisy_timeout_s,
                    limits=httpx.Limits(keepalive_expiry=None),
                ) as daisy_client:
                    # Pre-establish TCP+TLS on daisy_backup while keeping
                    # is_forwarding == False on this session.
                    warm_resp = daisy_client.get(f"{daisy_fwd_url}/node/state")
                    assert warm_resp.status_code == http.HTTPStatus.OK, warm_resp.text

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=1
                    ) as daisy_pool:
                        cur_primary.suspend()
                        suspended_at = time.monotonic()
                        try:
                            daisy_future = daisy_pool.submit(
                                daisy_client.put,
                                f"{daisy_fwd_url}/records/daisy",
                                content=b"value",
                            )
                            new_primary, new_view = network.wait_for_new_primary(
                                cur_primary, nodes=cur_backups
                            )
                            assert new_view > cur_view, (new_view, cur_view)

                            if not session_consistency_checked:
                                remaining_backup = next(
                                    b for b in cur_backups if b != new_primary
                                )
                                remaining_primary_url = f"https://{remaining_backup.get_public_rpc_address()}"
                                wait_for_node_view(
                                    primary_client,
                                    remaining_primary_url,
                                    new_view,
                                    timeout_s=network.election_duration * 4,
                                )
                                fwd_client, fwd_url = backup_sessions[remaining_backup]
                                r = fwd_client.put(
                                    f"{fwd_url}/records/fwd", content=b"value"
                                )
                                assert (
                                    r.status_code
                                    == http.HTTPStatus.INTERNAL_SERVER_ERROR
                                ), (
                                    r.status_code,
                                    r.text,
                                )
                                assert (
                                    r.json()["error"]["code"]
                                    == "SessionConsistencyLost"
                                ), r.text
                                session_consistency_checked = True

                            remaining_sleep = (
                                suspended_at + network.election_duration + 0.5
                            ) - time.monotonic()
                            if remaining_sleep > 0:
                                time.sleep(remaining_sleep)
                        finally:
                            cur_primary.resume()

                        daisy_resp = daisy_future.result(timeout=daisy_timeout_s)

                if (
                    daisy_resp.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE
                    and daisy_resp.json()["error"]["code"] == "RequestAlreadyForwarded"
                ):
                    daisy_observed = True
                    break

                if daisy_resp.status_code == http.HTTPStatus.NO_CONTENT:
                    wait_for_final_tx_status(
                        primary_client,
                        f"https://{new_primary.get_public_rpc_address()}",
                        daisy_resp.headers["x-ms-ccf-transaction-id"],
                        timeout_s=max(10.0, network.election_duration * 2),
                    )
                LOG.warning(
                    f"RequestAlreadyForwarded attempt {attempt + 1}/{MAX_DAISY_ATTEMPTS} "
                    f"returned {daisy_resp.status_code}: {daisy_resp.text}; retrying"
                )

            assert session_consistency_checked
            assert (
                daisy_observed
            ), f"Did not observe RequestAlreadyForwarded within {MAX_DAISY_ATTEMPTS} attempts"

            targets = [
                f"https://{n.get_public_rpc_address()}"
                for n in network.get_joined_nodes()
            ]
            cli = [sys.executable, "../tests/tvc.py"]
            for target in targets:
                cli.append("-t")
                cli.append(target)
            cli.append("--ca")
            cli.append(network.cert_path)

            LOG.info(f"Starting {' '.join(cli)}")
            tvc = subprocess.Popen(cli, stdout=subprocess.PIPE, text=True)
            try:
                # Do some normal transactions
                time.sleep(2)
                # Suspend the current primary long enough to cause an election
                tvc_primary, _ = network.find_primary()
                tvc_primary.suspend()
                try:
                    time.sleep(network.election_duration * 2)
                finally:
                    tvc_primary.resume()

                # Do some more transactions
                time.sleep(5)
                tvc.poll()
                if tvc.returncode is not None:
                    raise RuntimeError(f"tvc failed with rc {tvc.returncode}")
                tvc.send_signal(signal.SIGINT)
                statuses, _ = tvc.communicate()
                for status in map(json.loads, statuses.splitlines()):
                    infra.consistency_trace.tx_status(status, status["ts"])
            finally:
                if tvc.poll() is None:
                    tvc.terminate()
                    tvc.wait(timeout=5)

            # Isolate one backup from the rest of the cluster. Pre-establish
            # CHANNEL_BURST_COUNT (> N2N_MESSAGE_LIMIT + 10) TLS connections
            # before suspending the other nodes, then release the entire burst
            # simultaneously in a single wave so it exceeds the channel message
            # limit and 10-slot unestablished forwarding queue long before the
            # election timer expires (503 "Unable to establish channel to
            # forward to primary."). Then wait for its election timer to clear
            # primary_id and exercise the unknown-primary forwarding path.
            cur_primary, cur_backups = network.find_nodes()
            isolated = cur_backups[0]
            to_suspend = [cur_primary, *cur_backups[1:]]
            isolated_url = f"https://{isolated.get_public_rpc_address()}"
            isolated_fwd_url = (
                f"https://{isolated.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"
            )

            with contextlib.ExitStack() as burst_stack:
                burst_clients = [
                    burst_stack.enter_context(
                        httpx.Client(
                            verify=tls_ctx,
                            http2=False,
                            timeout=15.0,
                            limits=httpx.Limits(keepalive_expiry=None),
                        )
                    )
                    for _ in range(CHANNEL_BURST_COUNT)
                ]
                ready_barrier = threading.Barrier(CHANNEL_BURST_COUNT + 1)
                release_event = threading.Event()

                def send_one(client):
                    try:
                        warm = client.get(f"{isolated_fwd_url}/node/state")
                        assert warm.status_code == http.HTTPStatus.OK, warm.text
                        ready_barrier.wait()
                    except BaseException:
                        ready_barrier.abort()
                        raise
                    release_event.wait()
                    try:
                        return client.put(
                            f"{isolated_fwd_url}/records/chan",
                            content=b"value",
                            timeout=1.5,
                        )
                    except httpx.TimeoutException:
                        return None

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=CHANNEL_BURST_COUNT
                ) as pool:
                    futures = [pool.submit(send_one, c) for c in burst_clients]
                    try:
                        # Wait until all burst connections are established and
                        # parked at the barrier before suspending peers.
                        ready_barrier.wait(timeout=30)
                        for node in to_suspend:
                            node.suspend()
                        release_event.set()
                        responses = [
                            resp for f in futures if (resp := f.result()) is not None
                        ]
                        channel_errors = [
                            resp
                            for resp in responses
                            if resp.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE
                            and resp.json()["error"]["code"] == "InternalError"
                            and "Unable to establish channel to forward to primary."
                            in resp.json()["error"]["message"]
                        ]
                        assert channel_errors, [
                            (resp.status_code, resp.text) for resp in responses
                        ]

                        isolated_client = stack.enter_context(
                            httpx.Client(verify=tls_ctx, http2=False)
                        )
                        wait_for_unknown_primary(
                            isolated_client,
                            isolated_url,
                            timeout_s=network.election_duration * 4,
                        )
                        r = isolated_client.put(
                            f"{isolated_fwd_url}/records/no_primary", content=b"value"
                        )
                        assert (
                            r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE
                        ), r.text
                        assert r.json()["error"]["code"] == "InternalError", r.text
                        assert "unknown primary" in r.json()["error"]["message"], r.text
                    finally:
                        ready_barrier.abort()
                        release_event.set()
                        for node in to_suspend:
                            if node.suspended:
                                node.resume()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "js_generic"
    args.js_app_bundle = "../samples/apps/basic_tv/js/"
    args.nodes = infra.e2e_args.nodes(args, 3)
    # Long signature interval to maximise the chance of an InvalidStatus transaction
    args.sig_ms_interval = 1000
    run(args)
