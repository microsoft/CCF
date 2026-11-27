# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import concurrent.futures
import contextlib
import http
import json
import signal
import subprocess
import sys
import time

import httpx
import infra.consistency_trace
import infra.e2e_args
import infra.interfaces
import infra.network
from loguru import logger as LOG

FORWARDING_RPC_INTERFACE = "forwarding_rpc_interface"
N2N_MESSAGE_LIMIT = 200
FORWARDING_TIMEOUT_MS = 1000


def make_forwarding_interface():
    return infra.interfaces.RPCInterface(
        app_protocol="HTTP1",
        redirections=None,
        forwarding_timeout_ms=FORWARDING_TIMEOUT_MS,
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


def wait_for_follower_in_view(client, base_url, min_view, timeout_s=10):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(f"{base_url}/node/consensus")
        if r.status_code == http.HTTPStatus.OK:
            details = r.json()["details"]
            if (
                details["leadership_state"] == "Follower"
                and details["current_view"] >= min_view
            ):
                return details
        time.sleep(0.05)
    raise TimeoutError(
        f"Timed out waiting for node to become Follower in view >= {min_view}"
    )


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
    for host in args.nodes:
        host.rpc_interfaces[FORWARDING_RPC_INTERFACE] = make_forwarding_interface()

    with infra.consistency_trace.recording(args), infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, backups = network.find_nodes()
        primary_url = f"https://{primary.get_public_rpc_address()}"

        with contextlib.ExitStack() as stack:
            primary_client = stack.enter_context(
                httpx.Client(verify=network.cert_path, http2=False)
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

            # Establish persistent forwarding sessions on all backups in the
            # initial view before any election occurs. Because no backup has
            # established an N2N channel with any other backup yet, this also
            # lets us deterministically trigger both SessionConsistencyLost and
            # RequestAlreadyForwarded across a single election.
            backup_sessions = {}
            for backup in backups:
                fwd_url = (
                    f"https://{backup.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"
                )
                fwd_client = stack.enter_context(
                    httpx.Client(
                        verify=network.cert_path,
                        http2=False,
                        limits=httpx.Limits(keepalive_expiry=None),
                    )
                )
                r = fwd_client.put(f"{fwd_url}/records/fwd", content=b"value")
                assert r.status_code == http.HTTPStatus.NO_CONTENT, r.text
                tx_id = r.headers["x-ms-ccf-transaction-id"]
                wait_for_final_tx_status(primary_client, primary_url, tx_id)
                backup_sessions[backup] = (fwd_client, fwd_url)

            # Freeze frozen_backup (believing primary is leader, with no N2N
            # channel yet to quorum_backups), then suspend primary so the 3
            # quorum_backups elect new_primary in a higher view:
            # 1. Reusing a pre-election persistent forwarding session on a
            #    remaining quorum backup hits !check_session_consistency() in
            #    forward() -> 500 SessionConsistencyLost.
            # 2. Resuming primary makes it step down to Follower. Suspending
            #    new_primary before waking frozen_backup prevents new_primary
            #    from finishing its N2N handshake to frozen_backup, so
            #    frozen_backup forwards to primary (now a Follower) ->
            #    503 RequestAlreadyForwarded.
            frozen_backup = backups[0]
            quorum_backups = backups[1:]
            assert len(quorum_backups) >= 3, len(quorum_backups)
            frozen_fwd_url = f"https://{frozen_backup.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"

            frozen_backup.suspend()
            daisy_new_primary = None
            try:
                primary.suspend()
                new_primary, new_view = network.wait_for_new_primary(
                    primary, nodes=quorum_backups
                )
                daisy_new_primary = new_primary
                assert new_view > initial_view, (new_view, initial_view)

                remaining_backup = next(b for b in quorum_backups if b != new_primary)
                remaining_primary_url = (
                    f"https://{remaining_backup.get_public_rpc_address()}"
                )
                wait_for_node_view(
                    primary_client,
                    remaining_primary_url,
                    new_view,
                    timeout_s=network.election_duration * 4,
                )
                fwd_client, fwd_url = backup_sessions[remaining_backup]
                r = fwd_client.put(f"{fwd_url}/records/fwd", content=b"value")
                assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, (
                    r.status_code,
                    r.text,
                )
                assert r.json()["error"]["code"] == "SessionConsistencyLost", r.text

                primary.resume()
                wait_for_follower_in_view(
                    primary_client,
                    primary_url,
                    new_view,
                    timeout_s=network.election_duration * 4,
                )

                new_primary.suspend()
                frozen_backup.resume()
                with httpx.Client(
                    verify=network.cert_path, http2=False
                ) as daisy_client:
                    r = daisy_client.put(
                        f"{frozen_fwd_url}/records/daisy", content=b"value"
                    )
                    assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE, (
                        r.status_code,
                        r.text,
                    )
                    assert (
                        r.json()["error"]["code"] == "RequestAlreadyForwarded"
                    ), r.text
            finally:
                if daisy_new_primary is not None and daisy_new_primary.suspended:
                    daisy_new_primary.resume()
                if primary.suspended:
                    primary.resume()
                if frozen_backup.suspended:
                    frozen_backup.resume()

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

            # Isolate one backup from the rest of the cluster. First, while it
            # still believes cur_primary is primary, burst forwarded writes
            # past node_to_node_message_limit + the 10-slot unestablished
            # forwarding queue to exercise forward_command() returning false
            # (503 "Unable to establish channel to forward to primary."). Then
            # wait for its election timer to clear primary_id and exercise the
            # unknown-primary forwarding error path.
            cur_primary, cur_backups = network.find_nodes()
            isolated = cur_backups[0]
            to_suspend = [cur_primary, *cur_backups[1:]]
            isolated_url = f"https://{isolated.get_public_rpc_address()}"
            isolated_fwd_url = (
                f"https://{isolated.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"
            )
            for node in to_suspend:
                node.suspend()
            try:

                def send_one(_):
                    with httpx.Client(
                        verify=network.cert_path, http2=False, timeout=5.0
                    ) as c:
                        return c.put(
                            f"{isolated_fwd_url}/records/chan", content=b"value"
                        )

                burst_count = N2N_MESSAGE_LIMIT + 15
                with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
                    responses = list(pool.map(send_one, range(burst_count)))
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
                    httpx.Client(verify=network.cert_path, http2=False)
                )
                wait_for_unknown_primary(
                    isolated_client,
                    isolated_url,
                    timeout_s=network.election_duration * 4,
                )
                r = isolated_client.put(
                    f"{isolated_fwd_url}/records/no_primary", content=b"value"
                )
                assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE, r.text
                assert r.json()["error"]["code"] == "InternalError", r.text
                assert "unknown primary" in r.json()["error"]["message"], r.text
            finally:
                for node in to_suspend:
                    if node.suspended:
                        node.resume()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "js_generic"
    args.js_app_bundle = "../samples/apps/basic_tv/js/"
    args.nodes = infra.e2e_args.nodes(args, 5)
    # Long signature interval to maximise the chance of an InvalidStatus transaction
    args.sig_ms_interval = 1000
    run(args)
