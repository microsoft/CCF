# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import grpc
import json
import urllib

from loguru import logger as LOG

# pylint: disable=import-error
import kv_pb2 as KV

# pylint: disable=import-error
import http_pb2 as HTTP

# pylint: disable=import-error
import kv_pb2_grpc as Service

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty


class LoggingExecutor:
    def __init__(self, ccf_node, credentials):
        self.ccf_node = ccf_node
        self.credentials = credentials

    def _execute_get_description(self, kv_stub, request, response):
        prefix = "/article_description/"
        title = request.uri[len(prefix) :]
        result = kv_stub.Get(
            KV.KVKey(table=self.CACHE_TABLE, key=title.encode("utf-8"))
        )

        if not result.HasField("optional"):
            response.status_code = HTTP.HttpStatusCode.NOT_FOUND
            response.body = f"No description for '{title}' in cache"

        response.status_code = HTTP.HttpStatusCode.OK
        response.body = result.optional.value

    def do_post(self, kv_stub, table, request, response):
        body = json.loads(request.body)
        kv_stub.Put(
            KV.KVKeyValue(
                table=table,
                key=str(body["id"]).encode("utf-8"),  # TODO: Write as buffer, not UTF-8
                value=body["msg"].encode("utf-8"),
            )
        )
        response.status_code = HTTP.HttpStatusCode.OK
        header = response.headers.add()
        header.field = "content-type"
        header.value = "application/json"
        response.body = json.dumps(True).encode("utf-8")

    def do_get(self, kv_stub, table, request, response):
        query_args = urllib.parse.parse_qs(request.query)
        id = query_args["id"][0]
        result = kv_stub.Get(
            KV.KVKey(
                table=table,
                key=str(id).encode("utf-8"),  # TODO: Write as buffer, not UTF-8
            )
        )

        if not result.HasField("optional"):
            response.status_code = HTTP.HttpStatusCode.BAD_REQUEST
            response.body = f"No such record: {id}"
            return

        response.status_code = HTTP.HttpStatusCode.OK
        response.body = json.dumps(
            {"msg": result.optional.value.decode("utf-8")}
        ).encode("utf-8")

    def run_loop(self, terminate_event):
        target_uri = f"{self.ccf_node.get_public_rpc_host()}:{self.ccf_node.get_public_rpc_port()}"
        with grpc.secure_channel(
            target=target_uri,
            credentials=self.credentials,
        ) as channel:
            stub = Service.KVStub(channel)

            while not (terminate_event.is_set()):
                request_description_opt = stub.StartTx(Empty())
                if not request_description_opt.HasField("optional"):
                    continue

                request = request_description_opt.optional
                response = KV.ResponseDescription(
                    status_code=HTTP.HttpStatusCode.NOT_FOUND
                )

                if "log/private" in request.uri:
                    table = "private:records"
                elif "log/public" in request.uri:
                    table = "records"
                else:
                    LOG.error(f"Unhandled request: {request.method} {request.uri}")
                    stub.EndTx(response)
                    continue

                if request.method == "POST":
                    self.do_post(stub, table, request, response)
                elif request.method == "GET":
                    self.do_get(stub, table, request, response)
                else:
                    LOG.error(f"Unhandled request: {request.method} {request.uri}")
                    stub.EndTx(response)
                    continue

                stub.EndTx(response)

        LOG.info("Ended executor loop")
