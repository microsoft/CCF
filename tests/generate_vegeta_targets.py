# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import json
import base64
import sys
import urllib.parse
from collections import abc


def build_vegeta_target(hostname, path, body=None, method="POST"):
    target = {}
    target["method"] = method
    target["url"] = urllib.parse.urljoin(f"https://{hostname}", path)
    target["header"] = {"Content-Type": ["application/json"]}
    if body is not None:
        # Bodies must be base64 encoded strings
        target["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    return target


def write_vegeta_target_line(f, *args, **kwargs):
    target = build_vegeta_target(*args, **kwargs)
    f.write(json.dumps(target))
    f.write("\n")


# Quick and dirty solution for building request bodies that vary
def recursive_format(obj, i):
    if isinstance(obj, str):
        return obj.format(i=i)
    elif isinstance(obj, abc.Sequence):
        return [recursive_format(e, i) for e in obj]
    elif isinstance(obj, abc.Mapping):
        return {recursive_format(k, i): recursive_format(v, i) for k, v in obj.items()}
    else:
        return obj


def nan_replacer(i):
    def fun(s):
        if s == "NaN":
            return i
        return float(s)

    return fun


def append_targets(file, args):
    for i in range(args.range_start, args.range_end):
        format_args = {"i": i}
        path = args.uri_path.format(**format_args)
        if args.body is not None:
            body = recursive_format(
                json.loads(args.body, parse_constant=nan_replacer(i)), **format_args
            )
        else:
            body = None
        write_vegeta_target_line(
            file,
            hostname=args.hostname,
            path=path,
            method=args.method,
            body=body,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    subparsers = parser.add_subparsers(
        title="targets",
        description="Instructions to generate a list of targets. Can be repeated multiple times",
    )
    targets_s = "targets"
    targets_parser = subparsers.add_parser(
        targets_s, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    targets_parser.add_argument("--uri-path", type=str, help="Path to desired endpoint")
    targets_parser.add_argument(
        "--range-start", type=int, default=0, help="First index for range of targets"
    )
    targets_parser.add_argument(
        "--range-end", type=int, default=1, help="End index for range of targets"
    )
    targets_parser.add_argument(
        "--method", type=str, default="POST", help="HTTP method to be called"
    )
    targets_parser.add_argument(
        "--hostname",
        type=str,
        default="127.0.0.1:8000",
        help="Base hostname to submit target to",
    )
    targets_parser.add_argument("--body", default=None, help="JSON body of request")

    remaining_args = sys.argv[1:]
    steps = []
    while remaining_args:
        try:
            start_index = remaining_args.index(targets_s)
        except ValueError:
            start_index = None
        if start_index != 0:
            raise RuntimeError(
                f"Unable to parse args - next section doesn't begin with '{targets_s}'"
            )

        try:
            end_index = remaining_args.index(targets_s, start_index + 1)
        except ValueError:
            end_index = len(remaining_args)

        parse_slice = remaining_args[start_index:end_index]
        args, rest = targets_parser.parse_known_args(parse_slice)
        steps += [args]
        remaining_args = remaining_args[end_index:]

    for step in steps:
        append_targets(sys.stdout, step)
