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
        "--dot", action="store_true", help="Generate a dot file for the state graph"
    )
    parser.add_argument(
        "--lncheck",
        type=str,
        choices=["final", "default"],
        default="final",
        help="Liveness check, set to 'default' to run periodically or 'final' to run once at the end, default is final",
    )
    # It would be ideal if this could be derived from the current task name in GitHub Actions, rather than
    # have to set it manually when we invoke the same spec or config with different parameters
    parser.add_argument(
        "--trace-name",
        type=str,
        default=None,
        help="Name to give to the trace files, defaults to base name of the spec, or config if provided",
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

    # Trace, simulation and model checking would be best as sub-commands, rather than a flat
    # option space
    trace_validation = parser.add_argument_group(title="trace validation arguments")
    trace_validation.add_argument(
        "--dfs",
        action="store_true",
        help="Set TLC to use depth-first search",
    )
    trace_validation.add_argument(
        "--driver-trace",
        type=pathlib.Path,
        default=None,
        help="Path to a CCF Raft driver trace .ndjson file, produced by make_traces.sh",
    )

    simulation = parser.add_argument_group(title="simulation arguments")
    simulation.add_argument(
        "--simulate",
        type=str,
        help="Set TLC to simulate rather than model-check",
    )
    simulation.add_argument(
        "--depth",
        type=int,
        default=500,
        help="Set the depth of the simulation, defaults to 500",
    )
    simulation.add_argument(
        "--max-seconds",
        type=int,
        default=1200,
        help="Set the timeout of the simulation, defaults to 1200 seconds",
    )

    mc_ccfraft = parser.add_argument_group(title="MCccfraft arguments")
    mc_ccfraft.add_argument(
        "--max-term-count",
        type=int,
        default=0,
        help="Maximum number of terms the nodes are allowed to advance through, defaults to 0",
    )
    mc_ccfraft.add_argument(
        "--max-request-count",
        type=int,
        default=3,
        help="Maximum number of requests the nodes are allowed to advance through, defaults to 3",
    )
    mc_ccfraft.add_argument(
        "--raft-configs",
        type=str,
        default="1C2N",
        help="Raft configuration sequence, defaults to 1C2N",
    )
    mc_ccfraft.add_argument(
        "--disable-check-quorum", action="store_true", help="Disable CheckQuorum action"
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
    trace_name = args.trace_name or os.path.basename(args.config or args.spec).replace(
        ".tla", ""
    )

    if "CI" in env:
        # When run in CI, format output for GitHub, and participate in statistics collection
        jvm_args.append("-Dtlc2.TLC.ide=Github")
        jvm_args.append(
            "-Dutil.ExecutionStatisticsCollector.id=be29f6283abeed2fb1fd0be898bc6601"
        )

    if args.trace_name or "CI" in env:
        # When run in CI, or told explicitly, dump a trace
        tlc_args.extend(["-dumpTrace", "json", f"{trace_name}.trace.json"])
    if args.jmx:
        jvm_args.append("-Dcom.sun.management.jmxremote")
        jvm_args.append("-Dcom.sun.management.jmxremote.port=55449")
        jvm_args.append("-Dcom.sun.management.jmxremote.ssl=false")
        jvm_args.append("-Dcom.sun.management.jmxremote.authenticate=false")
    if not args.disable_cdot:
        jvm_args.append("-Dtlc2.tool.impl.Tool.cdot=true")
    if args.dfs:
        jvm_args.append("-Dtlc2.tool.queue.IStateQueue=StateDeque")
    if args.config:
        tlc_args.extend(["-config", args.config])
    if args.dot:
        tlc_args.extend(
            ["-dump", "dot,constrained,colorize,actionlabels", f"{trace_name}.dot"]
        )

    if args.driver_trace:
        env["DRIVER_TRACE"] = args.driver_trace

    if args.simulate:
        tlc_args.extend(["-simulate", args.simulate])
        env["SIM_TIMEOUT"] = str(args.max_seconds)
    if args.depth:
        tlc_args.extend(["-depth", str(args.depth)])

    if args.max_term_count:
        env["MAX_TERM_COUNT"] = str(args.max_term_count)
    if args.max_request_count:
        env["MAX_REQUEST_COUNT"] = str(args.max_request_count)
    if args.raft_configs:
        env["RAFT_CONFIGS"] = args.raft_configs
    if args.disable_check_quorum:
        env["DISABLE_CHECK_QUORUM"] = "true"

    cmd = ["java"] + jvm_args + cp_args + ["tlc2.TLC"] + tlc_args + [args.spec]
    if args.v:
        pprint.pprint(env)
        pprint.pprint(cmd)
    os.execvpe("java", cmd, env)
