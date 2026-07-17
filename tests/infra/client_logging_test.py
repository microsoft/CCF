# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import io
import unittest

from loguru import logger as LOG

from infra.clients import Request, Response
from infra.log_capture import flush_info


class ClientLoggingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        LOG.remove()

    def test_client_logs_are_plain_text(self):
        messages = [
            str(Request("/<invalid>", "<invalid>", "GET", {"x": "<invalid>"})),
            str(
                Response(
                    status_code=500,
                    body="<invalid>",
                    seqno=None,
                    view=None,
                    headers={},
                )
            ),
            str(
                Response(
                    status_code=200,
                    body="trailing\\",
                    seqno=3,
                    view=2,
                    headers={},
                )
            ),
            "<invalid>",
        ]
        expected = [
            "GET /<invalid> {'x': '<invalid>'} <invalid>",
            "500 <invalid>",
            "200 @2.3 trailing\\",
            "<invalid>",
        ]
        self.assertEqual(messages, expected)

        output = io.StringIO()
        handler_id = LOG.add(output, format="{message}")
        try:
            flush_info(messages)
        finally:
            LOG.remove(handler_id)
        self.assertEqual(output.getvalue().splitlines(), expected)


if __name__ == "__main__":
    unittest.main()
