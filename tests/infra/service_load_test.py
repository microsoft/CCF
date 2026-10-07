# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import subprocess
import sys
import threading
import unittest
from unittest import mock

import infra.service_load


class ServiceLoadTest(unittest.TestCase):
    def test_context_cleanup(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                service_load = mock.Mock()
                with mock.patch(
                    "infra.service_load.ServiceLoad", return_value=service_load
                ):
                    if fail:
                        error = RuntimeError("Test failure")
                        with (
                            self.assertRaises(RuntimeError) as raised,
                            infra.service_load.load() as load,
                        ):
                            self.assertIs(load, service_load)
                            raise error
                        self.assertIs(raised.exception, error)
                    else:
                        with infra.service_load.load() as load:
                            self.assertIs(load, service_load)
                service_load.end.assert_called_once_with()

    def test_cleanup_before_begin(self):
        with infra.service_load.load() as load:
            self.assertIsNone(load.client)
        self.assertTrue(load.is_stopped())

    def test_exception_stops_process(self):
        client = infra.service_load.LoadClient(mock.Mock())
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stderr=subprocess.PIPE,
        )
        client.proc = process
        error = RuntimeError("Test failure")
        try:
            with (
                mock.patch.object(client, "_aggregate_results"),
                mock.patch.object(client, "_render_results"),
                self.assertRaises(RuntimeError) as raised,
                infra.service_load.load() as load,
            ):
                load.client = client
                raise error
            self.assertIs(raised.exception, error)
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stderr.close()

    def test_cleanup_waits_for_restart(self):
        load = infra.service_load.ServiceLoad()
        load.client = mock.Mock()
        primary = mock.Mock()
        backup = mock.Mock()
        new_primary = mock.Mock()
        polling = threading.Event()
        calls = 0

        def find_nodes(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return primary, [backup]
            polling.set()
            if not load._stop_event.wait(timeout=5):
                raise TimeoutError("Service load was not stopped")
            return new_primary, [backup]

        load.network = mock.Mock()
        load.network.find_nodes.side_effect = find_nodes
        client_calls = mock.Mock()
        client_calls.attach_mock(load.client.restart, "restart")
        client_calls.attach_mock(load.client.stop, "stop")

        with mock.patch("infra.service_load.NETWORK_POLL_INTERVAL_S", 0):
            load.start()
            try:
                self.assertTrue(polling.wait(timeout=5))
            finally:
                load.end()

        self.assertFalse(load.is_alive())
        self.assertEqual(
            client_calls.mock_calls,
            [
                mock.call.restart(new_primary, [backup], event=mock.ANY),
                mock.call.stop(),
            ],
        )


if __name__ == "__main__":
    unittest.main()
