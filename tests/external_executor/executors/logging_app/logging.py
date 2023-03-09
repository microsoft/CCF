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

# pylint: disable=import-error
import historical_pb2 as Historical

# pylint: disable=import-error
import historical_pb2_grpc as HistoricalService

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty


class LoggingExecutor:
    base_endpoints = [
        ("POST", "/log/public"),
        ("GET", "/log/public"),
        ("POST", "/log/private"),
        ("GET", "/log/private"),
        ("GET", "/log/private/historical"),
    ]

    @staticmethod
    def get_supported_endpoints(topic=None):
        def make_uri(uri, topic=None):
            return uri if topic is None else f"{uri}/{topic}"

        endpoints = []
        endpoints.append(("POST", make_uri("/log/public", topic)))
        endpoints.append(("GET", make_uri("/log/public", topic)))
        endpoints.append(("POST", make_uri("/log/private", topic)))
        endpoints.append(("GET", make_uri("/log/public", topic)))
        endpoints.append(("GET", make_uri("/log/private/historical", topic)))
        return endpoints

    def __init__(self, node_public_rpc_address, credentials):
        self.node_public_rpc_address = node_public_rpc_address
        self.credentials = credentials
        self.handled_requests_count = 0

    def add_supported_endpoints(self, endpoints):
        self.supported_endpoints.add(endpoints)
        print(self.supported_endpoints)

    def do_post(self, kv_stub, table, request, response):
        body = json.loads(request.body)
        kv_stub.Put(
            KV.KVKeyValue(
                table=table,
                key=body["id"].to_bytes(8, "big"),
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
        msg_id = int(query_args["id"][0])
        result = kv_stub.Get(
            KV.KVKey(
                table=table,
                key=msg_id.to_bytes(8, "big"),
            )
        )

        if not result.HasField("optional"):
            response.status_code = HTTP.HttpStatusCode.NOT_FOUND
            response.body = f"No such record: {msg_id}".encode()
            return

        response.status_code = HTTP.HttpStatusCode.OK
        response.body = json.dumps(
            {"msg": result.optional.value.decode("utf-8")}
        ).encode("utf-8")

    def do_historical(self, table, request, response):
        query_args = urllib.parse.parse_qs(request.query)
        msg_id = int(query_args["id"][0])
        tx_id = []
        for header in request.headers:
            if "x-ms-ccf-transaction-id" in header.field:
                val = header.value
                tx_id = val.split(".")
        view_no = int(tx_id[0])
        seq_no = int(tx_id[1])

        with grpc.secure_channel(
            target=self.node_public_rpc_address,
            credentials=self.credentials,
        ) as channel:
            try:
                stub = HistoricalService.HistoricalStub(channel)
                tx_id = Historical.TxID()
                tx_id.view = view_no
                tx_id.seqno = seq_no
                result = stub.GetHistoricalData(
                    Historical.HistoricalData(
                        map_name=table,
                        key=msg_id.to_bytes(8, "big"),
                        tx_id=tx_id,
                    )
                )
            except grpc.RpcError as e:
                # pylint: disable=no-member
                assert e.code() == grpc.StatusCode.NOT_FOUND
                response.status_code = HTTP.HttpStatusCode.NOT_FOUND
                response.body = e.details().encode()
                return

            if result.retry == True:
                response.status_code = HTTP.HttpStatusCode.ACCEPTED
                response.body = "Historical transaction is not currently available. Please retry.".encode()
                return

            if not result.HasField("data"):
                response.status_code = HTTP.HttpStatusCode.NOT_FOUND
                response.body = "No such Key was found in the transaction".encode()
                return

            response.status_code = HTTP.HttpStatusCode.OK
            response.body = json.dumps(
                {"msg": result.data.value.decode("utf-8")}
            ).encode("utf-8")

    def run_loop(self, activated_event=None):
        with grpc.secure_channel(
            target=self.node_public_rpc_address,
            credentials=self.credentials,
        ) as channel:
            stub = Service.KVStub(channel)

            for work in stub.Activate(Empty()):
                if work.HasField("activated"):
                    if activated_event is not None:
                        activated_event.set()
                    continue

                elif work.HasField("work_done"):
                    break

                assert work.HasField("request_description")
                self.handled_requests_count += 1
                request = work.request_description

                response = KV.ResponseDescription(
                    status_code=HTTP.HttpStatusCode.NOT_FOUND
                )

                if "log/private" in request.uri:
                    table = "records"
                elif "log/public" in request.uri:
                    table = "public:records"
                else:
                    LOG.error(f"Unhandled request: {request.method} {request.uri}")
                    stub.EndTx(response)
                    continue

                try:
                    if request.method == "GET" and "historical" in request.uri:
                        self.do_historical(table, request, response)
                    elif request.method == "POST":
                        self.do_post(stub, table, request, response)
                    elif request.method == "GET":
                        self.do_get(stub, table, request, response)
                    else:
                        LOG.error(f"Unhandled request: {request.method} {request.uri}")
                except Exception as e:
                    LOG.error(
                        f"Error while processing request: {request.method} {request.uri}: {e}"
                    )
                    response.status_code = HTTP.HttpStatusCode.INTERNAL_SERVER_ERROR
                    response.body = str(e).encode("utf-8")

                stub.EndTx(response)

        LOG.info("Ended executor loop")

    def terminate(self, *args):
        with grpc.secure_channel(
            target=self.node_public_rpc_address,
            credentials=self.credentials,
        ) as channel:
            stub = Service.KVStub(channel)
            stub.Deactivate(Empty())
