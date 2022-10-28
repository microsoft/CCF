# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import generator


def main():
    """
    The function to receive the arguments
    from the command line
    """
    arg_host = "https://127.0.0.1:8000"
    arg_path = "/app/log/private"  # default path to request
    arg_type = "HTTP/1.1"  # default type
    arg_verb = "POST"  # default verb
    arg_iterations = 16
    arg_parquet_filename = "requests.parquet"
    arg_data = '{"id": 1, "msg": "Send message with id 1"}'

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-hs",
        "--host",
        help="The main host to submit the request. Default `http://localhost:8000`",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--path",
        help="The realtive path to submit the request. Default `app/log/private`",
        type=str,
    )
    parser.add_argument(
        "-t",
        "--type",
        help="The type of the HTTP request (Only HTTP/1.1 which is the\
        default is supported for now)",
        type=str,
    )
    parser.add_argument(
        "-vr",
        "--verb",
        help="The request action. Default `POST` (Only `POST` and `GET` are supported for now)",
    )
    parser.add_argument(
        "-r", "--rows", help="The number of requests to send. Default `16` ", type=int
    )
    parser.add_argument(
        "-pf",
        "--parquet_filename",
        help="Name of the parquet file to store the\
            generated requests. Default file `./requests.parquet`",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--data",
        help="A string with the data to be sent in the POST request",
        type=str,
    )

    args = parser.parse_args()

    generator.fill_df(
        args.host or arg_host,
        args.path or arg_path,
        args.type or arg_type,
        args.verb or arg_verb,
        args.rows or arg_iterations,
        args.data or arg_data,
    )
    # create_post("https://127.0.0.1:8000", "/app/log/private", "HTTP/1.1", 30)
    # create_get("https://127.0.0.1:8000", "/app/log/private?id=1", "HTTP/1.1", 20)

    generator.create_parquet(args.parquet_filename or arg_parquet_filename)


if __name__ == "__main__":
    main()
