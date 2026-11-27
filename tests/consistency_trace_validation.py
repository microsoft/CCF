# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

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
    for host in args.nodes:
        host.rpc_interfaces[FORWARDING_RPC_INTERFACE] = infra.interfaces.RPCInterface(
            app_protocol="HTTP1",
            redirections=None,
        )

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

            # Establish persistent forwarding sessions on both backups in the
            # initial view so whichever remains a backup after election sees a
            # view change on its existing forwarding session.
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
                # Suspend the primary long enough to cause an election
                primary.suspend()
                try:
                    time.sleep(network.election_duration * 2)

                    # While the old primary is suspended, one of the original
                    # backups is the new primary and the other remains a backup
                    # in a newer view. Reusing its pre-election forwarding
                    # session must detect the view change before forwarding.
                    new_primary, new_view = network.wait_for_new_primary(
                        primary, nodes=backups
                    )
                    assert new_view > initial_view, (new_view, initial_view)
                    remaining_backup = next(b for b in backups if b != new_primary)
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
                finally:
                    primary.resume()

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

            # Suspend a majority so the remaining node loses its primary and
            # exercises the unknown-primary forwarding error path.
            cur_primary, cur_backups = network.find_nodes()
            isolated = cur_backups[0]
            to_suspend = [cur_primary, cur_backups[1]]
            for node in to_suspend:
                node.suspend()
            try:
                isolated_url = f"https://{isolated.get_public_rpc_address()}"
                isolated_fwd_url = f"https://{isolated.get_public_rpc_address(FORWARDING_RPC_INTERFACE)}"
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
                    node.resume()


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "js_generic"
    args.js_app_bundle = "../samples/apps/basic_tv/js/"
    args.nodes = infra.e2e_args.nodes(args, 3)
    # Long signature interval to maximise the chance of an InvalidStatus transaction
    args.sig_ms_interval = 1000
    run(args)
