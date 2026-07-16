# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import io
import unittest

import httpx
from loguru import logger as LOG

from infra.clients import (
    CONTENT_TYPE_BINARY,
    CONTENT_TYPE_CBOR,
    CONTENT_TYPE_COSE,
    CONTENT_TYPE_TEXT,
    Request,
    RequestsResponseBody,
    Response,
    escape_loguru_tags,
)
from infra.log_capture import flush_info


class ClientLoggingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        LOG.remove()

    def render(self, message):
        output = io.StringIO()
        handler_id = LOG.add(output, format="{message}", colorize=False)
        try:
            flush_info([message])
        finally:
            LOG.remove(handler_id)
        return output.getvalue().rstrip("\n")

    def test_escapes_loguru_tags_after_backslashes(self):
        for backslash_count in range(5):
            with self.subTest(backslash_count=backslash_count):
                message = ("\\" * backslash_count) + "<invalid>"
                self.assertEqual(self.render(escape_loguru_tags(message)), message)

    def test_hides_binary_response_bodies(self):
        body = b"\\<invalid>"
        content_types = (
            CONTENT_TYPE_BINARY,
            CONTENT_TYPE_COSE,
            f"{CONTENT_TYPE_CBOR}; profile=test",
            "Application/COSE",
        )

        for content_type in content_types:
            with self.subTest(content_type=content_type):
                headers = {"Content-Type": content_type}
                httpx_response = httpx.Response(
                    200,
                    headers=headers,
                    content=body,
                )
                response = Response(
                    status_code=200,
                    body=RequestsResponseBody(httpx_response),
                    seqno=None,
                    view=None,
                    headers=headers,
                )
                self.assertEqual(
                    self.render(str(response)),
                    f"200 <binary: {len(body)} bytes>",
                )

    def test_hides_byte_request_bodies(self):
        body = b"\\<invalid>"
        request = Request("/endpoint", body, "POST", {})
        self.assertEqual(
            self.render(str(request)),
            f"POST /endpoint <binary: {len(body)} bytes>",
        )

    def test_hides_requests_with_binary_content_type(self):
        body = "binary body"
        request = Request(
            "/endpoint",
            body,
            "POST",
            {"Content-Type": "Application/COSE; profile=test"},
        )
        rendered = self.render(str(request))
        self.assertNotIn(body, rendered)
        self.assertIn(f"<binary: {len(body)} bytes>", rendered)

    def test_escapes_dynamic_request_text(self):
        for path in (r"/\<invalid>", "/trailing\\"):
            with self.subTest(path=path):
                request = Request(path, None, "GET", {})
                self.assertEqual(self.render(str(request)), f"GET {path}")

    def test_escapes_text_response_bodies(self):
        for body in (r"\<invalid>", "trailing\\"):
            with self.subTest(body=body):
                headers = {"content-type": CONTENT_TYPE_TEXT}
                httpx_response = httpx.Response(
                    200,
                    headers=headers,
                    text=body,
                )
                response = Response(
                    status_code=200,
                    body=RequestsResponseBody(httpx_response),
                    seqno=None,
                    view=None,
                    headers=headers,
                )
                self.assertEqual(self.render(str(response)), f"200 {body}")


if __name__ == "__main__":
    unittest.main()
