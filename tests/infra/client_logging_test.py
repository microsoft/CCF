# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import io
import unittest

import httpx
from loguru import logger as LOG

from infra.clients import (
    CCFClient,
    Request,
    RequestsResponseBody,
    Response,
    escape_loguru_tags,
)
from infra.log_capture import flush_info


class StubClient:
    def __init__(self, response):
        self.response = response

    def request(self, request, timeout, cose_header_parameters_override):
        return self.response


class ClientLoggingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        LOG.remove()

    def capture(self, callback):
        output = io.StringIO()
        handler_id = LOG.add(output, format="{message}", colorize=False)
        try:
            callback()
        finally:
            LOG.remove(handler_id)
        return output.getvalue().rstrip("\n")

    def render(self, message):
        return self.capture(lambda: flush_info([message]))

    @staticmethod
    def response(status_code=200, body="body", headers=None):
        headers = headers or {}
        httpx_response = httpx.Response(status_code, headers=headers, text=body)
        return Response(
            status_code=status_code,
            body=RequestsResponseBody(httpx_response),
            seqno=None,
            view=None,
            headers=headers,
        )

    def test_escapes_loguru_tags_after_backslashes(self):
        for backslash_count in range(5):
            with self.subTest(backslash_count=backslash_count):
                message = ("\\" * backslash_count) + "<invalid>"
                self.assertEqual(self.render(escape_loguru_tags(message)), message)

    def test_escapes_dynamic_request_text(self):
        headers = {"x": r"\<invalid>"}
        cases = (
            (Request(r"/\<invalid>", None, "GET", {}), r"GET /\<invalid>"),
            (
                Request("/endpoint", None, "GET", headers),
                f"GET /endpoint {headers}",
            ),
            (
                Request("/endpoint", r"\<invalid>", "POST", {}),
                r"POST /endpoint \<invalid>",
            ),
        )

        for request, expected in cases:
            with self.subTest(request=request):
                self.assertEqual(self.render(str(request)), expected)

        for backslash_count in range(5):
            with self.subTest(backslash_count=backslash_count):
                path = "/trailing" + ("\\" * backslash_count)
                self.assertEqual(
                    self.render(str(Request(path, None, "GET", {}))),
                    f"GET {path}",
                )

    def test_escapes_dynamic_response_text(self):
        self.assertEqual(
            self.render(str(self.response(body=r"\<invalid>"))),
            r"200 \<invalid>",
        )

        for backslash_count in range(5):
            body = "trailing" + ("\\" * backslash_count)
            with self.subTest(body=body):
                self.assertEqual(
                    self.render(str(self.response(body=body))), f"200 {body}"
                )

        location = r"/\<invalid>"
        response = self.response(
            status_code=307,
            headers={"location": location},
        )
        self.assertEqual(
            self.render(str(response)),
            f"307 [Redirect to -> {location}] body",
        )

    def test_escapes_client_description(self):
        response = self.response()
        client = CCFClient.__new__(CCFClient)
        client.description = r"client \<invalid>"
        client.client_impl = StubClient(response)

        rendered = self.capture(lambda: client._call("/endpoint", http_verb="GET"))

        self.assertEqual(
            rendered,
            "client \\<invalid> GET /endpoint\n200 body",
        )


if __name__ == "__main__":
    unittest.main()
