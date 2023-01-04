# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from generator import Messages


common_headers = {"host": "127.0.0.1:8000"}
msgs = Messages()

msgs.append("/app/log/private/count", "GET")

for i in range(14):
    msgs.append(
        "/app/log/private",
        "POST",
        additional_headers=common_headers,
        body='{"id": ' + str(i) + ', "msg": "Logged ' + str(i) + ' to private table"}',
    )
msgs.append("/app/log/private/count", "GET", additional_headers=common_headers)

for i in range(14):
    msgs.append(
        "/app/log/private?id=" + str(i), "GET", additional_headers=common_headers
    )
msgs.append("/app/log/private/count", "GET", additional_headers=common_headers)

for i in range(14):
    msgs.append(
        "/app/log/private?id=" + str(i), "DELETE", additional_headers=common_headers
    )
msgs.append("/app/log/private/count", "GET", additional_headers=common_headers)


msgs.to_parquet_file("new_raw.parquet")
