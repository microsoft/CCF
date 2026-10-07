# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Controlled scheduling regressions, run before e2e_logging's network tests."""

import http
import threading
import unittest
from builtins import ExceptionGroup
from collections import deque
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import e2e_logging
import infra.clients
from ccf.tx_id import TxID


class CommitPollerTests(unittest.TestCase):
    def make_poller(self, *actions, shutdown_timeout=2):
        client = MagicMock()
        client.__enter__.return_value = client
        node = Mock()
        node.client.return_value = client
        poller = e2e_logging.CommitPoller(node, shutdown_timeout=shutdown_timeout)
        remaining = deque(actions)
        last_txid = "2.2163"

        def get(path, log_capture):
            nonlocal last_txid
            self.assertEqual(path, "/node/commit")
            self.assertEqual(log_capture, [])
            if remaining:
                action = remaining.popleft()
                if callable(action):
                    action = action()
                if isinstance(action, BaseException):
                    raise action
                last_txid = action
            else:
                if not poller._stop_event.wait(2):
                    raise TimeoutError("Mock observer was not stopped")
            response = Mock(status_code=http.HTTPStatus.OK)
            response.body.json.return_value = {"transaction_id": last_txid}
            return response

        client.get.side_effect = get
        return poller, client

    def wait_for_samples(self, poller, count):
        with poller._condition:
            self.assertTrue(
                poller._condition.wait_for(
                    lambda: len(poller.known_commit_times) >= count or poller._finished,
                    timeout=2,
                )
            )
            self.assertEqual(len(poller.known_commit_times), count)

    def test_delayed_observer_is_drained_before_stop(self):
        poller, _ = self.make_poller("2.2163", "2.2164")
        between_samples = threading.Event()
        release_observer = threading.Event()
        waiter_blocked = threading.Event()
        waiter_done = threading.Event()
        waiter_errors = []
        original_is_stopped = poller.is_stopped
        original_wait = poller._condition.wait
        checks = 0

        def is_stopped():
            nonlocal checks
            checks += 1
            if checks == 2:
                between_samples.set()
                if not release_observer.wait(2):
                    raise TimeoutError("Delayed observer was not released")
            return original_is_stopped()

        def wait(timeout):
            waiter_blocked.set()
            return original_wait(timeout)

        def observe():
            try:
                poller.wait_for_observation([TxID(2, 2164)], timeout=2)
            except BaseException as error:
                waiter_errors.append(error)
            finally:
                waiter_done.set()

        waiter = threading.Thread(target=observe)
        with patch.object(poller, "is_stopped", is_stopped), patch.object(
            poller._condition, "wait", wait
        ), poller:
            try:
                self.assertTrue(between_samples.wait(2))
                waiter.start()
                self.assertTrue(waiter_blocked.wait(2))
                self.assertFalse(waiter_done.is_set())
                self.assertFalse(original_is_stopped())
                release_observer.set()
                waiter.join(timeout=2)
                self.assertFalse(waiter.is_alive())
                self.assertTrue(waiter_done.is_set())
                self.assertEqual(waiter_errors, [])
            finally:
                release_observer.set()
                if waiter.ident is not None:
                    waiter.join(timeout=2)
        self.assertFalse(poller.is_alive())
        self.assertTrue(original_is_stopped())
        self.assertEqual(
            [txid for _, txid in poller.known_commit_times],
            [TxID(2, 2163), TxID(2, 2164)],
        )
        self.assertTrue(
            all(
                timestamp.tzinfo == timezone.utc
                for timestamp, _ in poller.known_commit_times
            )
        )

    def test_already_recorded_sample_and_same_view_later_commit(self):
        for observed in ("2.2164", "2.2200"):
            with self.subTest(observed=observed):
                poller, _ = self.make_poller(observed)
                with poller:
                    self.wait_for_samples(poller, 1)
                    poller.wait_for_observation([TxID(2, 2164)], timeout=0)

    def test_older_view_does_not_cover_target(self):
        poller, _ = self.make_poller("1.9999")
        with self.assertRaisesRegex(TimeoutError, "did not observe 2.2164"), poller:
            self.wait_for_samples(poller, 1)
            poller.wait_for_observation([TxID(2, 2164)], timeout=0)

    def test_older_view_sample_before_covering_sample(self):
        poller, _ = self.make_poller("1.9999", "2.2200")
        with poller:
            self.wait_for_samples(poller, 2)
            poller.wait_for_observation([TxID(2, 2164)], timeout=0)

    def test_newer_view_is_not_commitment_proof(self):
        poller, _ = self.make_poller("2.2163", "3.9999")
        with self.assertRaisesRegex(AssertionError, "single view"), poller:
            self.wait_for_samples(poller, 2)
            poller.wait_for_observation([TxID(2, 2164)], timeout=0)

    def test_covering_sample_survives_later_view_change(self):
        poller, _ = self.make_poller("2.2200", "3.9999")
        with poller:
            self.wait_for_samples(poller, 2)
            poller.wait_for_observation([TxID(2, 2164)], timeout=0)

    def test_final_response_must_cover_prior_responses(self):
        for txids, diagnostic in (
            ([TxID(1, 2163), TxID(2, 2164)], "single response view"),
            ([TxID(2, 2165), TxID(2, 2164)], "does not cover all responses"),
            ([], "No response transactions"),
        ):
            with self.subTest(txids=txids):
                poller, _ = self.make_poller("2.2200")
                with self.assertRaisesRegex(AssertionError, diagnostic), poller:
                    poller.wait_for_observation(txids, timeout=0)

    def test_worker_http_error_is_not_observation_timeout(self):
        error = RuntimeError("Observer HTTP failure")
        poller, _ = self.make_poller(error)
        with self.assertRaises(RuntimeError) as caught, poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)
        self.assertIs(caught.exception, error)
        self.assertFalse(poller.is_alive())

    def test_bad_http_status_and_malformed_commit_ids(self):
        poller, client = self.make_poller()
        client.get.return_value = Mock(status_code=http.HTTPStatus.SERVICE_UNAVAILABLE)
        client.get.side_effect = None
        with self.assertRaises(AssertionError), poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)

        poller, _ = self.make_poller("not-a-txid")
        with self.assertRaisesRegex(AssertionError, "Invalid commit ID"), poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)

    def test_client_creation_and_entry_failures_are_propagated(self):
        for at_entry in (False, True):
            with self.subTest(at_entry=at_entry):
                error = RuntimeError("Observer client failure")
                poller, client = self.make_poller()
                if at_entry:
                    client.__enter__.side_effect = error
                else:
                    poller.node.client.side_effect = error
                with self.assertRaises(RuntimeError) as caught, poller:
                    poller.wait_for_observation([TxID(2, 2164)], timeout=2)
                self.assertIs(caught.exception, error)

    def test_early_worker_exit_is_not_success(self):
        poller, _ = self.make_poller()
        poller.stop()
        with self.assertRaisesRegex(RuntimeError, "stopped before observing"), poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)

    def test_observation_timeout_is_bounded_and_diagnostic(self):
        poller, _ = self.make_poller()
        with self.assertRaisesRegex(
            TimeoutError,
            "2.2164 within 0s: last sample=None, samples=0, finished=False",
        ), poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=0)
        self.assertFalse(poller.is_alive())

    def test_foreground_failure_stops_and_joins(self):
        error = RuntimeError("Foreground failure")
        poller, _ = self.make_poller("2.2163")
        with self.assertRaises(RuntimeError) as caught, poller:
            self.wait_for_samples(poller, 1)
            raise error
        self.assertIs(caught.exception, error)
        self.assertTrue(poller.is_stopped())
        self.assertFalse(poller.is_alive())

    def test_worker_failure_after_successful_drain_is_propagated(self):
        error = RuntimeError("Observer client exit failure")
        poller, client = self.make_poller("2.2164")
        client.__exit__.side_effect = error
        with self.assertRaises(RuntimeError) as caught, poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)
        self.assertIs(caught.exception, error)

    def test_foreground_and_worker_failures_are_both_propagated(self):
        foreground = RuntimeError("Foreground failure")
        worker = RuntimeError("Observer client exit failure")
        poller, client = self.make_poller("2.2164")
        client.__exit__.side_effect = worker
        with self.assertRaises(ExceptionGroup) as caught, poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)
            raise foreground
        self.assertEqual(caught.exception.exceptions, (foreground, worker))

    def test_foreground_worker_and_cleanup_failures_are_all_propagated(self):
        foreground = RuntimeError("Foreground failure")
        worker = RuntimeError("Observer client exit failure")
        cleanup = RuntimeError("Join failure")
        poller, client = self.make_poller("2.2164")
        client.__exit__.side_effect = worker
        original_join = poller.join

        def join(timeout):
            original_join(timeout=timeout)
            raise cleanup

        with patch.object(poller, "join", join), self.assertRaises(
            ExceptionGroup
        ) as caught, poller:
            poller.wait_for_observation([TxID(2, 2164)], timeout=2)
            raise foreground
        self.assertEqual(caught.exception.exceptions, (foreground, cleanup, worker))
        self.assertFalse(poller.is_alive())

    def test_still_live_observer_fails_bounded_cleanup(self):
        release = threading.Event()
        in_http = threading.Event()

        def blocked_request():
            in_http.set()
            if not release.wait(2):
                raise TimeoutError("Blocked request was not released")
            return "2.2164"

        poller, _ = self.make_poller(blocked_request, shutdown_timeout=0)
        try:
            with self.assertRaisesRegex(
                TimeoutError, "still alive after 0s shutdown"
            ), poller:
                self.assertTrue(in_http.wait(2))
            self.assertTrue(poller.is_alive())
            self.assertTrue(poller.is_stopped())
        finally:
            release.set()
            poller.join(timeout=2)
        self.assertFalse(poller.is_alive())

    def run_measurement(self, deltas):
        paths = [
            "/log/private",
            "/log/blocking/private",
            "/log/blocking/private/receipt",
            "/log/private/optional_commit",
            "/log/private/optional_commit?wait_for_commit=true",
        ]
        request_order = paths * 5
        start = datetime(2026, 10, 7, tzinfo=timezone.utc)
        timestamps = [
            start + timedelta(seconds=i * 10) for i in range(len(request_order))
        ]
        txids = [TxID(2, i + 1) for i in range(len(request_order))]
        commits = [
            (timestamp + timedelta(seconds=deltas[path]), txid)
            for timestamp, path, txid in zip(timestamps, request_order, txids)
        ]
        commits.insert(0, (start - timedelta(seconds=1), TxID(1, 9999)))
        commits.append((start + timedelta(seconds=999), TxID(3, 9999)))
        responses = []
        for txid in txids:
            response = Mock(
                status_code=http.HTTPStatus.OK,
                headers={
                    infra.clients.CCF_TX_ID_HEADER: str(txid),
                    "content-type": "application/cose",
                },
            )
            response.body.data.return_value = b"test receipt"
            responses.append(response)
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.side_effect = responses
        primary = Mock()
        primary.client.return_value = client
        network = Mock()
        network.find_nodes.return_value = (primary, [])
        with patch.object(e2e_logging, "CommitPoller") as factory, patch.object(
            e2e_logging, "datetime"
        ) as clock, patch.object(e2e_logging.random, "shuffle"), patch.object(
            e2e_logging.ccf.receipt, "verify_cose"
        ) as verify_receipt, patch.object(
            e2e_logging.LOG, "info"
        ) as log:
            poller = factory.return_value
            poller.__enter__.return_value = poller
            poller.known_commit_times = commits
            clock.now.side_effect = timestamps
            result = e2e_logging.test_blocking_calls(network, None)
            self.assertIs(result, network)
            self.assertEqual(
                [call.args for call in client.post.call_args_list],
                [(path, {"id": 42, "msg": "Hello world"}) for path in request_order],
            )
            client.wait_for_commit.assert_called_once_with(responses[-1])
            poller.wait_for_observation.assert_called_once_with(txids)
            self.assertEqual(verify_receipt.call_count, 5)
            for call in verify_receipt.call_args_list:
                self.assertEqual(
                    call.args,
                    (b"test receipt", network.cert.public_key(), b"\0" * 32),
                )
            self.assertEqual(clock.now.call_count, 25)
            self.assertTrue(
                all(call.args == (timezone.utc,) for call in clock.now.call_args_list)
            )
            means = {path: deltas[path] for path in paths}
            log.assert_called_once_with(f"Mean commit deltas: {means}")

    def test_first_covering_sample_times_and_path_means_are_preserved(self):
        self.run_measurement(
            {
                "/log/private": 1.0,
                "/log/blocking/private": 0.0,
                "/log/blocking/private/receipt": -0.02,
                "/log/private/optional_commit": 0.8,
                "/log/private/optional_commit?wait_for_commit=true": -0.01,
            }
        )

    def test_all_latency_inequalities_remain_enforced(self):
        for path in (
            "/log/blocking/private",
            "/log/blocking/private/receipt",
            "/log/private/optional_commit?wait_for_commit=true",
        ):
            with self.subTest(path=path):
                deltas = {
                    "/log/private": 1.0,
                    "/log/blocking/private": 0.0,
                    "/log/blocking/private/receipt": -0.02,
                    "/log/private/optional_commit": 0.8,
                    "/log/private/optional_commit?wait_for_commit=true": -0.01,
                }
                deltas[path] = 2.0
                with self.assertRaises(AssertionError):
                    self.run_measurement(deltas)


def run(args):
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CommitPollerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    assert result.wasSuccessful(), "Commit poller scheduling regressions failed"


if __name__ == "__main__":
    unittest.main()
