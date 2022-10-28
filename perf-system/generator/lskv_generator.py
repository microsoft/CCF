# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from generator import create_parquet, create_verb

MYHOST = "127.0.0.1:8000"
REQUEST_CONTENT_TYPE = "content-type: application/json"


for i in range(10):
    req_path = "/v3/kv/range"
    req_type = "HTTP/2"
    req_data = '{"key":"aGVsbG8="}'

    create_verb(
        "post",
        MYHOST,
        req_path,
        req_type,
        req_message=req_data,
        headers=[REQUEST_CONTENT_TYPE],
    )
for i in range(10):
    req_path = "/v3/kv/put"
    req_type = "HTTP/2"
    req_data = '{"key":"aGVsbG8=","value":"d29ybGQ="}'

    create_verb(
        "post",
        MYHOST,
        req_path,
        req_type,
        req_message=req_data,
        headers=[REQUEST_CONTENT_TYPE],
    )

for i in range(50):
    req_path = "/v3/kv/range"
    req_type = "HTTP/2"
    req_data = '{"key":"aGVsbG8="}'

    create_verb(
        "post",
        MYHOST,
        req_path,
        req_type,
        req_message=req_data,
        headers=[REQUEST_CONTENT_TYPE],
    )

for i in range(10):
    req_path = "/v3/kv/delete_range"
    req_type = "HTTP/2"
    req_data = '{"key":"aGVsbG8="}'

    create_verb(
        "post",
        MYHOST,
        req_path,
        req_type,
        req_message=req_data,
        headers=[REQUEST_CONTENT_TYPE],
    )

create_parquet("lskv.parquet")
