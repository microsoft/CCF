# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from openapi_core import OpenAPI

from infra.openapi import OpenAPIValidator

SCHEMA = {
    "openapi": "3.0.0",
    "info": {"title": "Test", "version": "1"},
    "paths": {
        "/node/items/{item_id}": {
            "get": {
                "parameters": [
                    {
                        "name": "item_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Item",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["value"],
                                    "properties": {"value": {"type": "integer"}},
                                }
                            }
                        },
                    }
                },
            }
        }
    },
}

SWAGGER_SCHEMA = {
    "swagger": "2.0",
    "info": {"title": "Test", "version": "1"},
    "produces": ["application/json"],
    "paths": {
        "/gov/items/{item_id}": {
            "get": {
                "parameters": [
                    {
                        "name": "item_id",
                        "in": "path",
                        "required": True,
                        "type": "integer",
                    },
                    {
                        "name": "api-version",
                        "in": "query",
                        "required": True,
                        "type": "string",
                        "enum": ["2024-07-01"],
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Item",
                        "schema": {"$ref": "#/definitions/Item"},
                    }
                },
            }
        }
    },
    "definitions": {
        "Item": {
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "integer"}},
        }
    },
}


class Body:
    def __init__(self, value):
        self.value = value

    def data(self):
        return json.dumps(self.value).encode()


@dataclass
class Request:
    path: str
    body: dict | None
    http_verb: str
    headers: dict


@dataclass
class Response:
    status_code: int
    body: Body
    headers: dict


def response(body):
    return Response(
        status_code=200,
        body=Body(body),
        headers={"content-type": "application/json"},
    )


def validator(schema=SCHEMA, prefix="/node"):
    result = OpenAPIValidator()
    result._schemas[prefix] = schema
    result._apis[prefix] = (
        None if schema.get("swagger") == "2.0" else OpenAPI.from_dict(schema)
    )
    result._operations[prefix] = {
        (path, method)
        for path, path_item in schema["paths"].items()
        for method in path_item
    }
    return result


class OpenAPIValidatorTests(unittest.TestCase):
    def test_validates_and_reports_covered_operation(self):
        openapi = validator()
        request = Request("/node/items/42", None, "GET", {})

        openapi.validate(request, response({"value": 42}))
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "coverage.json"
            openapi.report(str(report_path))
            report = json.loads(report_path.read_text())

        self.assertEqual(report["node"]["covered"], 1)
        self.assertEqual(report["node"]["percent"], 100.0)
        self.assertEqual(
            report["node"]["operations"], ["GET /node/items/{item_id}"]
        )

    def test_rejects_invalid_response(self):
        openapi = validator()

        with self.assertRaisesRegex(
            AssertionError, "OpenAPI validation failed"
        ):
            openapi.validate(
                Request("/node/items/42", None, "GET", {}),
                response({"value": "not an integer"}),
            )

    def test_rejects_invalid_request(self):
        openapi = validator()

        with self.assertRaisesRegex(
            AssertionError, "OpenAPI validation failed"
        ):
            openapi.validate(
                Request("/node/items/not-an-integer", None, "GET", {}),
                response({"value": 42}),
            )

    def test_reports_undocumented_operation(self):
        openapi = validator()
        openapi.validate(
            Request("/node/unknown", None, "GET", {}), response({})
        )

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "coverage.json"
            openapi.report(str(report_path))
            report = json.loads(report_path.read_text())

        self.assertEqual(
            report["node"]["undocumented"], ["GET /node/unknown"]
        )

    def test_validates_swagger_request_and_response(self):
        openapi = validator(SWAGGER_SCHEMA, "/gov")
        request = Request(
            "/gov/items/42?api-version=2024-07-01", None, "GET", {}
        )

        openapi.validate(request, response({"value": 42}))

        with self.assertRaisesRegex(
            AssertionError, "OpenAPI validation failed"
        ):
            validator(SWAGGER_SCHEMA, "/gov").validate(
                request, response({"value": "not an integer"})
            )


if __name__ == "__main__":
    unittest.main()
