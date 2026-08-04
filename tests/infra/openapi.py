# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import re
import threading
import urllib.parse
from dataclasses import dataclass

import jsonschema
from loguru import logger as LOG
from openapi_core import OpenAPI
from openapi_core.datatypes import RequestParameters
from werkzeug.datastructures import Headers, ImmutableMultiDict


@dataclass
class _Request:
    host_url: str
    path: str
    method: str
    parameters: RequestParameters
    body: bytes | None
    content_type: str


@dataclass
class _Response:
    status_code: int
    headers: Headers
    data: bytes
    content_type: str


class OpenAPIValidator:
    def __init__(self):
        self._apis = {}
        self._schemas = {}
        self._operations = {}
        self._visited = set()
        self._undocumented = set()
        self._validated_requests = set()
        self._validated_responses = set()
        self._lock = threading.Lock()

    @property
    def loaded(self):
        return bool(self._apis)

    def load(self, client, gov_api_version):
        if self.loaded:
            return

        schemas = {}
        for prefix, path in (
            ("/node", "/node/api"),
            ("/gov", f"/gov/api?api-version={gov_api_version}"),
        ):
            response = client.get(path)
            assert response.status_code == 200, response
            schemas[prefix] = response.body.json()

        with self._lock:
            if self.loaded:
                return
            for prefix, schema in schemas.items():
                self._schemas[prefix] = schema
                self._apis[prefix] = (
                    None
                    if schema.get("swagger") == "2.0"
                    else OpenAPI.from_dict(schema)
                )
                self._operations[prefix] = {
                    (path, method)
                    for path, path_item in schema["paths"].items()
                    for method in path_item
                    if method.lower()
                    in {"delete", "get", "head", "options", "patch", "post", "put"}
                }

    @staticmethod
    def _header(headers, name):
        for key, value in headers.items():
            if key.lower() == name:
                return value
        return None

    @staticmethod
    def _body_bytes(body):
        if body is None:
            return None
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            if body.startswith("@"):
                with open(body[1:], "rb") as body_file:
                    return body_file.read()
            return body.encode()
        return json.dumps(body).encode()

    @staticmethod
    def _path_matches(template, path):
        pattern = re.sub(r"\\{[^}]+\\}", "[^/]+", re.escape(template))
        return re.fullmatch(pattern, path) is not None

    def _operation(self, prefix, method, path):
        method = method.lower()
        for template, operation_method in self._operations[prefix]:
            if operation_method.lower() == method and self._path_matches(
                template, path
            ):
                return (prefix, template, method)
        return None

    def _v2_operation(self, prefix, operation):
        _, template, method = operation
        path_item = self._schemas[prefix]["paths"][template]
        return path_item, path_item[method]

    def _resolve_v2(self, prefix, value):
        if "$ref" not in value:
            return value
        reference = value["$ref"]
        assert reference.startswith("#/")
        resolved = self._schemas[prefix]
        for part in reference[2:].split("/"):
            resolved = resolved[part.replace("~1", "/").replace("~0", "~")]
        return resolved

    def _validate_v2_schema(self, prefix, value, schema):
        root_schema = self._schemas[prefix]
        validation_schema = {
            "definitions": root_schema.get("definitions", {}),
            "allOf": [schema],
        }
        jsonschema.Draft4Validator(validation_schema).validate(value)

    @staticmethod
    def _coerce_parameter(value, schema):
        parameter_type = schema.get("type")
        if parameter_type == "integer":
            return int(value)
        if parameter_type == "number":
            return float(value)
        if parameter_type == "boolean":
            if value.lower() not in {"true", "false"}:
                return value
            return value.lower() == "true"
        if parameter_type == "array":
            separator = {
                "csv": ",",
                "pipes": "|",
                "ssv": " ",
                "tsv": "\t",
            }.get(schema.get("collectionFormat", "csv"))
            values = value if separator is None else value.split(separator)
            return [
                OpenAPIValidator._coerce_parameter(item, schema.get("items", {}))
                for item in values
            ]
        return value

    def _validate_v2_request(self, prefix, operation, request, parsed, cose):
        path_item, operation_value = self._v2_operation(prefix, operation)
        parameters = path_item.get("parameters", []) + operation_value.get(
            "parameters", []
        )
        query = urllib.parse.parse_qs(parsed.query)
        path_values = re.fullmatch(
            re.sub(
                r"\\{([^}]+)\\}",
                lambda match: f"(?P<{match.group(1)}>[^/]+)",
                re.escape(operation[1]),
            ),
            parsed.path,
        ).groupdict()
        headers = {key.lower(): value for key, value in request.headers.items()}

        for unresolved_parameter in parameters:
            parameter = self._resolve_v2(prefix, unresolved_parameter)
            location = parameter["in"]
            name = parameter["name"]
            if location == "body":
                if request.body is not None and not cose:
                    self._validate_v2_schema(prefix, request.body, parameter["schema"])
                elif parameter.get("required") and request.body is None:
                    raise jsonschema.ValidationError(f"{name} is required")
                continue

            values = (
                path_values.get(name)
                if location == "path"
                else (
                    query.get(name)
                    if location == "query"
                    else headers.get(name.lower()) if location == "header" else None
                )
            )
            if values is None:
                if parameter.get("required"):
                    raise jsonschema.ValidationError(f"{name} is required")
                continue
            value = values[0] if isinstance(values, list) else values
            parameter_schema = {
                key: value
                for key, value in parameter.items()
                if key
                not in {
                    "allowEmptyValue",
                    "collectionFormat",
                    "description",
                    "in",
                    "name",
                    "required",
                    "x-ms-client-name",
                }
            }
            jsonschema.Draft4Validator(parameter_schema).validate(
                self._coerce_parameter(value, parameter),
            )

    def _validate_v2_response(self, prefix, operation, response):
        _, operation_value = self._v2_operation(prefix, operation)
        response_schema = operation_value["responses"].get(
            str(response.status_code), operation_value["responses"].get("default")
        )
        if response_schema is None:
            raise jsonschema.ValidationError(
                f"Response status {response.status_code} is not documented"
            )
        response_schema = self._resolve_v2(prefix, response_schema)
        response_headers = {
            key.lower(): value for key, value in response.headers.items()
        }
        for name, header_schema in response_schema.get("headers", {}).items():
            value = response_headers.get(name.lower())
            if value is not None:
                jsonschema.Draft4Validator(header_schema).validate(
                    self._coerce_parameter(value, header_schema)
                )
        if "schema" not in response_schema:
            return
        data = response.body.data()
        value = json.loads(data) if data else None
        self._validate_v2_schema(prefix, value, response_schema["schema"])

    def validate(self, request, response, cose=False):
        if not self.loaded:
            return

        parsed = urllib.parse.urlsplit(request.path)
        prefix = next(
            (
                candidate
                for candidate in self._apis
                if parsed.path == candidate or parsed.path.startswith(f"{candidate}/")
            ),
            None,
        )
        if prefix is None:
            return

        operation = self._operation(prefix, request.http_verb, parsed.path)
        if operation is None:
            with self._lock:
                self._undocumented.add((prefix, parsed.path, request.http_verb.lower()))
            return

        query = ImmutableMultiDict(urllib.parse.parse_qsl(parsed.query))
        request_headers = Headers(request.headers)
        content_type = self._header(request.headers, "content-type")
        if content_type is None:
            if cose and request.http_verb != "GET":
                content_type = "application/cose"
            elif isinstance(request.body, dict):
                content_type = "application/json"
            elif isinstance(request.body, str):
                content_type = (
                    "application/json"
                    if request.body.startswith("@")
                    and request.body.lower().endswith(".json")
                    else "text/plain"
                )
            elif isinstance(request.body, bytes):
                content_type = "application/octet-stream"
            else:
                content_type = ""

        openapi_request = _Request(
            host_url="https://ccf.test",
            path=parsed.path,
            method=request.http_verb.lower(),
            parameters=RequestParameters(query=query, header=request_headers),
            body=self._body_bytes(request.body),
            content_type=content_type,
        )
        response_headers = Headers(response.headers)
        openapi_response = _Response(
            status_code=response.status_code,
            headers=response_headers,
            data=response.body.data(),
            content_type=self._header(response.headers, "content-type") or "",
        )

        with self._lock:
            self._visited.add(operation)
            validate_request = (
                200 <= response.status_code < 300
                and operation not in self._validated_requests
            )
            response_sample = (*operation, response.status_code)
            validate_response = response_sample not in self._validated_responses

        try:
            if self._apis[prefix] is None:
                if validate_request:
                    self._validate_v2_request(prefix, operation, request, parsed, cose)
                if validate_response:
                    self._validate_v2_response(prefix, operation, response)
            else:
                if validate_request:
                    self._apis[prefix].validate_request(openapi_request)
                if validate_response:
                    self._apis[prefix].validate_response(
                        openapi_request, openapi_response
                    )
        except Exception as exc:
            raise AssertionError(
                f"OpenAPI validation failed for {request.http_verb} {request.path} "
                f"with response {response.status_code}: {exc}"
            ) from exc

        with self._lock:
            if validate_request:
                self._validated_requests.add(operation)
            if validate_response:
                self._validated_responses.add(response_sample)

    def report(self, output_path):
        if not self.loaded:
            return

        report = {}
        with self._lock:
            for prefix, operations in self._operations.items():
                visited = {
                    (path, method)
                    for visited_prefix, path, method in self._visited
                    if visited_prefix == prefix
                }
                total = len(operations)
                report[prefix.removeprefix("/")] = {
                    "covered": len(visited),
                    "total": total,
                    "percent": round(100 * len(visited) / total, 1) if total else 100.0,
                    "operations": [
                        f"{method.upper()} {path}" for path, method in sorted(visited)
                    ],
                    "undocumented": [
                        f"{method.upper()} {path}"
                        for undocumented_prefix, path, method in sorted(
                            self._undocumented
                        )
                        if undocumented_prefix == prefix
                    ],
                }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2)
            report_file.write("\n")
        LOG.info(f"Wrote OpenAPI coverage report to {output_path}: {report}")
