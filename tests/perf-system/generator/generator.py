# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""
Generate requests
"""

import pandas as pd  # type: ignore

# pylint: disable=import-error
import fastparquet as fp  # type: ignore


class Messages:
    def __init__(self):
        self.requests = []

    def append(
        self,
        path,
        verb,
        http_version="HTTP/1.1",
        content_type="application/json",
        additional_headers=None,
        body=bytes(),
    ):
        """
        Serialise HTTP request specified by the arguments, and
        append it to self.requests
        """

        headers = {}
        if additional_headers is not None:
            headers.update({k.lower(): v for k, v in additional_headers.items()})

        # Insert content-length, and content-type headers, if they're not already present
        if "content-length" not in headers:
            headers["content-length"] = str(len(body))
        if "content-type" not in headers and content_type is not None:
            headers["content-type"] = content_type

        # Convert body to bytes if we were given a string
        if type(body) == str:
            body = body.encode("utf-8")

        request_line = f"{verb.upper()} {path} {http_version}"
        headers_string = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        serialised_request = (
            f"{request_line}\r\n{headers_string}\r\n\r\n".encode("ascii") + body
        )

        self.requests.append(
            {"messageID": str(len(self.requests)), "request": serialised_request}
        )

    def to_parquet_file(self, path):
        df = pd.DataFrame(self.requests)
        fp.write(path, df, write_index=True)
