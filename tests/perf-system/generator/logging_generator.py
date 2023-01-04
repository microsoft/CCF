# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from generator import Messages

HOST = "127.0.0.1:8000"
REQUEST_CONTENT_TYPE = "content-type: application/json"


msgs = Messages()

msgs.append(HOST, "/app/log/private/count", "GET")

for i in range(14):
    msgs.append(
        HOST,
        "/app/log/private",
        "POST",
        body='{"id": ' + str(i) + ', "msg": "Logged ' + str(i) + ' to private table"}',
    )
msgs.append(HOST, "/app/log/private/count", "GET")

for i in range(14):
    msgs.append(HOST, "/app/log/private?id=" + str(i), "GET")
msgs.append(HOST, "/app/log/private/count", "GET")

for i in range(14):
    msgs.append(HOST, "/app/log/private?id=" + str(i), "DELETE")
msgs.append(HOST, "/app/log/private/count", "GET")


msgs.to_parquet_file("new_raw.parquet")
