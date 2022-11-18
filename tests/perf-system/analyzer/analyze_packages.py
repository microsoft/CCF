# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import analyzer


def main():
    """
    The function to receive the arguments
    from the command line
    """

    parser = argparse.ArgumentParser(
        description="Analysis for perf workloads",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-sf",
        "--send_file_path",
        help="Path to the parquet file that contains the submitted requests",
        default="../submitter/cpp_send.parquet",
        type=str,
    )
    parser.add_argument(
        "-rf",
        "--response_file_path",
        help="Path to the parquet file that contains the responses\
            from the submitted requests",
        default="../submitter/cpp_respond.parquet",
        type=str,
    )

    args = parser.parse_args()
    analyzer.default_analysis(args.send_file_path, args.response_file_path)


if __name__ == "__main__":
    main()
