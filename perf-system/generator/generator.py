# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""
Generate requests
"""

import pandas as pd  # type: ignore

# pylint: disable=import-error
import fastparquet as fp  # type: ignore

REQUEST_CONTENT_TYPE = "content-type: application/json"
REQUEST_LENGTH_TEXT = "content-length: "

df = pd.DataFrame(columns=["messageID", "request"])


def fill_df(host, req_path, req_type, req_verb, req_iters, data):
    """
    Creates a dataframe with the data
    required for the requests
    """
    # entering the private file paths as metadata in the start of parquet

    print("Starting generation of requests")
    for _ in range(req_iters):
        create_verb(
            req_verb,
            host,
            req_path,
            req_type,
            req_message=data,
            headers=[REQUEST_CONTENT_TYPE],
        )

    print("Finished generation of requests")


def create_verb(
    verb: str, host: str, req_path: str, req_type: str, req_message="", headers=None
) -> None:
    """
    Generate queries
    """
    headers_string = "\r\n".join(headers) + "\r\n"
    data_headers = ""
    if len(req_message) > 0:
        data_headers = (
            REQUEST_LENGTH_TEXT + str(len(req_message)) + "\r\n\r\n" + req_message
        )
    else:
        data_headers = "\r\n"

    ind = len(df.index)
    df.loc[ind] = [
        str(ind),
        verb.upper()
        + " "
        + req_path
        + " "
        + req_type
        + "\r\n"
        + "host: "
        + host
        + "\r\n"
        + headers_string
        + data_headers,
    ]


def create_parquet(parquet_filename):
    """
    Takes the dataframe data and stores them
    in a parquet file in the current directory
    """
    print("Start writing requests to " + parquet_filename)
    fp.write(parquet_filename, df)
    print("Finished writing requests to " + parquet_filename)
