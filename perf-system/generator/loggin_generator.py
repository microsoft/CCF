# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from generator import create_parquet, create_verb

HOST = "127.0.0.1:8000"
REQUEST_CONTENT_TYPE = "content-type: application/json"

create_verb(
    "GET", HOST, "/app/log/private/count", "HTTP/1.1", headers=[REQUEST_CONTENT_TYPE]
)

for i in range(14):
    req_type = "HTTP/1.1"
    req_path = "/app/log/private"
    req_data = '{"id": ' + str(i) + ', "msg": "Logged ' + str(i) + ' to private table"}'

    create_verb(
        "post",
        HOST,
        req_path,
        req_type,
        req_message=req_data,
        headers=[REQUEST_CONTENT_TYPE],
    )

create_verb(
    "GET", HOST, "/app/log/private/count", "HTTP/1.1", headers=[REQUEST_CONTENT_TYPE]
)

for i in range(14):

    req_type = "HTTP/1.1"
    req_path = "/app/log/private?id=" + str(i)

    create_verb("GET", HOST, req_path, req_type, headers=[REQUEST_CONTENT_TYPE])

create_verb(
    "GET", HOST, "/app/log/private/count", "HTTP/1.1", headers=[REQUEST_CONTENT_TYPE]
)

for i in range(14):

    req_type = "HTTP/1.1"
    req_path = "/app/log/private?id=" + str(i)

    create_verb("delete", HOST, req_path, req_type, headers=[REQUEST_CONTENT_TYPE])

create_verb(
    "GET", HOST, "/app/log/private/count", "HTTP/1.1", headers=[REQUEST_CONTENT_TYPE]
)

create_parquet("new_raw.parquet")
