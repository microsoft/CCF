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
        self.df = pd.DataFrame(columns=["messageID", "request"])

    def append(
        self,
        host,
        path,
        verb,
        request_type="HTTP/1.1",
        content_type="application/json",
        data="",
        iterations=1,
    ):
        for _ in range(iterations):
            data_headers = "\r\n"
            if len(data) > 0:
                data_headers = "content-length: " + str(len(data)) + "\r\n\r\n" + data

            ind = len(self.df.index)
            self.df.loc[ind] = [
                str(ind),
                verb.upper()
                + " "
                + path
                + " "
                + request_type
                + "\r\n"
                + "host: "
                + host
                + "\r\n"
                + "content-type: "
                + content_type.lower()
                + "\r\n"
                + data_headers,
            ]

        return self.df

    def to_parquet_file(self, path):
        fp.write(path, self.df)
