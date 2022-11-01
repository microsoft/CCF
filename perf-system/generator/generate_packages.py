# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
from generator import Messages


def main():
    """
    The function to receive the arguments
    from the command line
    """
    arg_host = "https://127.0.0.1:8000"
    arg_path = "/app/log/private"  # default path to request
    arg_request_type = "HTTP/1.1"  # default type
    arg_verb = "POST"  # default verb
    arg_content_type = "application/json"
    arg_iterations = 16
    arg_path_to_parquet = "requests.parquet"
    arg_data = '{"id": 1, "msg": "Send message with id 1"}'

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-hs",
        "--host",
        help="The host to submit the request. Default `https://127.0.0.1:8000`",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--path",
        help="The relative path to submit the request. Default `app/log/private`",
        type=str,
    )
    parser.add_argument(
        "-vr",
        "--verb",
        help="The request action. Default `POST`",
    )
    parser.add_argument(
        "-r", "--rows", help="The number of requests to send. Default `16` ", type=int
    )
    parser.add_argument(
        "-rt",
        "--request_type",
        help="The transfer protocol for the request.\
            Default type `HTTP/1.1`",
        type=str,
    )
    parser.add_argument(
        "-pf",
        "--path_to_parquet",
        help="Path to the parquet file to store the\
            generated requests. Default path `./requests.parquet`",
        type=str,
    )
    parser.add_argument(
        "-ct",
        "--content_type",
        help="he Content-Type representation header is used\
            to indicate the original media type of the resource.\
            Default `application-json`",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--data",
        help="A string with the data to be sent with a request",
        type=str,
    )

    args = parser.parse_args()

    msg = Messages()
    msg.append(
        args.host or arg_host,
        args.path or arg_path,
        args.verb or arg_verb,
        args.request_type or arg_request_type,
        args.content_type or arg_content_type,
        args.data or arg_data,
        args.rows or arg_iterations,
    )

    msg.to_parquet_file(args.path_to_parquet or arg_path_to_parquet)


if __name__ == "__main__":
    main()
