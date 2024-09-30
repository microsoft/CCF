#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
#
# Python TLC wrapper script for the CCF project
# Goals:
# - No dependencies, no venv, no pip install
# - Set sensible defaults with an eye on performance
# - Capture useful switches for CI, debugging
# - Expose specification configuration through CLI
# - Provide a useful --help, and basic sanity checks

import os
import argparse
import pprint
import pathlib

DEFAULT_JVM_ARGS = [
    "-XX:+UseParallelGC",  # Use parallel garbage collection, for performance
]


DEFAULT_CLASSPATH_ARGS = ["-cp", "tla2tools.jar:CommunityModules-deps.jar"]


def cli():
    parser = argparse.ArgumentParser(
        description="TLC model checker wrapper for the CCF project"
    )
    parser.add_argument(
        "--disable-cdot", action="store_true", help="Disable \\cdot support"
    )
    parser.add_argument(
        "--jmx",
        action="store_true",
        help="Enable JMX to allow monitoring, use echo 'get -b tlc2.tool:type=ModelChecker CurrentState' | jmxterm -l localhost:55449 -i to query",
    )
    parser.add_argument(
        "-v",
        action="store_true",
        help="Print out command and environment before running",
    )
    parser.add_argument(
        "--workers",
        type=str,
        default="auto",
        help="Number of workers to use, default is 'auto'",
    )
    parser.add_argument(
        "--checkpoint", type=int, default=0, help="Checkpoint interval, default is 0"
    )
    parser.add_argument(
        "--lncheck",
        type=str,
        choices=["final", "default"],
        default="final",
        help="Liveness check, set to 'default' to run periodically or 'final' to run once at the end, default is final",
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=None,
        help="Path to the TLA+ configuration",
    )
    parser.add_argument(
        "spec", type=pathlib.Path, help="Path to the TLA+ specification"
    )
    return parser


if __name__ == "__main__":
    env = os.environ.copy()
    args = cli().parse_args()
    jvm_args = DEFAULT_JVM_ARGS
    cp_args = DEFAULT_CLASSPATH_ARGS
    tlc_args = [
        "-workers",
        args.workers,
        "-checkpoint",
        str(args.checkpoint),
        "-lncheck",
        args.lncheck,
    ]
    trace_name = os.path.basename(args.spec).replace(".tla", "")

    if "CI" in env:
        # When run in CI, format output for GitHub, and participate in statistics collection
        jvm_args.append("-Dtlc2.TLC.ide=Github")
        jvm_args.append(
            "-Dutil.ExecutionStatisticsCollector.id=be29f6283abeed2fb1fd0be898bc6601"
        )
        # When run in CI, always dump a JSON trace
        tlc_args.extend(["-dumpTrace", "json", f"{trace_name}.json"])
    if args.jmx:
        jvm_args.append("-Dcom.sun.management.jmxremote")
        jvm_args.append("-Dcom.sun.management.jmxremote.port=55449")
        jvm_args.append("-Dcom.sun.management.jmxremote.ssl=false")
        jvm_args.append("-Dcom.sun.management.jmxremote.authenticate=false")
    if not args.disable_cdot:
        jvm_args.append("-Dtlc2.tool.impl.Tool.cdot=true")
    if args.config:
        tlc_args.extend(["-config", args.config])

    cmd = ["java"] + jvm_args + cp_args + ["tlc2.TLC"] + tlc_args + [args.spec]
    if args.v:
        pprint.pprint(env)
        pprint.pprint(cmd)
    os.execvpe("java", cmd, env)
