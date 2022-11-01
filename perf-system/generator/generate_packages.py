# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
from generator import Messages


def main():
    """
    The function to receive the arguments
    from the command line
    """

    parser = argparse.ArgumentParser(
        description="Generator for perf workloads",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-hs",
        "--host",
        help="The host to submit the request.",
        default="127.0.0.1:8000",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--path",
        help="The relative path to submit the request.",
        default="app/log/private",
        type=str,
    )
    parser.add_argument(
        "-vr", "--verb", help="The request action.", default="POST", type=str
    )
    parser.add_argument(
        "-r",
        "--rows",
        default=16,
        help="The number of requests to send.",
        type=int,
    )
    parser.add_argument(
        "-rt",
        "--request_type",
        help="The transfer protocol for the request.",
        default="HTTP/1.1",
        type=str,
    )
    parser.add_argument(
        "-pf",
        "--path_to_parquet",
        help="Path to the parquet file to store the\
            generated requests",
        default="./requests.parquet",
        type=str,
    )
    parser.add_argument(
        "-ct",
        "--content_type",
        help="he Content-Type representation header is used\
            to indicate the original media type of the resource.\
            Default `application-json`",
        default="application-json",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--data",
        help="A string with the data to be sent with a request",
        default='{"id": 1, "msg": "Send message with id 1"}',
        type=str,
    )

    args = parser.parse_args()

    msg = Messages()
    msg.append(
        args.host,
        args.path,
        args.verb,
        args.request_type,
        args.content_type,
        args.data,
        args.rows,
    )

    msg.to_parquet_file(args.path_to_parquet)


if __name__ == "__main__":
    main()
