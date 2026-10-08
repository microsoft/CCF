# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import contextlib
import io
import unittest
from unittest.mock import patch

import httpx
import tvc


class RedirectTests(unittest.TestCase):
    def test_backup_only_targets_follow_redirects(self):
        requests = []

        def handle(request):
            requests.append((request.url.host, request.method, request.url.path))
            if request.url.path == "/tx":
                return httpx.Response(200, json={"status": "Committed"})
            if request.url.host == "backup.test":
                return httpx.Response(
                    307, headers={"location": "https://primary.test/records/0"}
                )
            return httpx.Response(
                200,
                text=tvc.VALUE,
                headers={"x-ms-ccf-transaction-id": "2.10"},
            )

        client_type = httpx.Client

        def make_client(**kwargs):
            kwargs["verify"] = False
            return client_type(transport=httpx.MockTransport(handle), **kwargs)

        reads = 0

        def choose(values):
            nonlocal reads
            if values == ["Ro", "Rw"]:
                reads += 1
                if reads > 1:
                    raise KeyboardInterrupt
                return "Ro"
            return values[0]

        with (
            patch.object(tvc.httpx, "Client", side_effect=make_client),
            patch.object(tvc.random, "choice", side_effect=choose),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(KeyboardInterrupt),
        ):
            tvc.run(["https://backup.test"], None)

        self.assertIn(("primary.test", "PUT", "/records/0"), requests)
        self.assertIn(("primary.test", "GET", "/records/0"), requests)


if __name__ == "__main__":
    unittest.main()
