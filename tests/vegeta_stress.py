# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import subprocess
import threading
import time
import generate_vegeta_targets as TargetGenerator
from loguru import logger as LOG

VEGETA_BIN = "/opt/vegeta/vegeta"


def print_memory_stats(node, shutdown_event):
    with node.client() as c:
        while not shutdown_event.is_set():
            r = c.get("/node/memory")
            LOG.warning(r.body.json())
            time.sleep(10)


def run(args, additional_attack_args):
    # Test that vegeta is available
    subprocess.run([VEGETA_BIN, "-version"], capture_output=True, check=True)

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()
        primary_hostname = (
            f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}"
        )

        vegeta_targets = "vegeta_targets"
        with open(vegeta_targets, "w", encoding="utf-8") as f:
            for i in range(10):
                TargetGenerator.write_vegeta_target_line(
                    f,
                    primary_hostname,
                    "/app/log/private",
                    body={"id": i, "msg": f"Private message: {i}"},
                )

            for i in range(10):
                TargetGenerator.write_vegeta_target_line(
                    f, primary_hostname, f"/app/log/private?id={i}", method="GET"
                )

            for i in range(10):
                TargetGenerator.write_vegeta_target_line(
                    f,
                    primary_hostname,
                    "/app/log/public",
                    body={"id": i, "msg": f"Public message: {i}"},
                )

            for i in range(10):
                TargetGenerator.write_vegeta_target_line(
                    f, primary_hostname, f"/app/log/public?id={i}", method="GET"
                )

        attack_cmd = [VEGETA_BIN, "attack"]
        attack_cmd += ["--targets", vegeta_targets]
        attack_cmd += ["--format", "json"]
        attack_cmd += ["--duration", "10s"]
        sa = primary.session_auth("user0")
        attack_cmd += ["--cert", sa["session_auth"].cert]
        attack_cmd += ["--key", sa["session_auth"].key]
        attack_cmd += ["--root-certs", primary.session_ca(False)["ca"]]
        attack_cmd += additional_attack_args

        attack_cmd_s = " ".join(attack_cmd)
        LOG.warning(f"Starting: {attack_cmd_s}")
        vegeta_run = subprocess.Popen(attack_cmd, stdout=subprocess.PIPE)

        tee_split = subprocess.Popen(
            ["tee", "vegeta_results.bin"],
            stdin=vegeta_run.stdout,
            stdout=subprocess.PIPE,
        )

        report_cmd = [VEGETA_BIN, "report", "--every", "5s"]
        vegeta_report = subprocess.Popen(report_cmd, stdin=tee_split.stdout)

        # Start a second thread which will print the primary's memory stats at regular intervals
        shutdown_event = threading.Event()
        memory_thread = threading.Thread(
            target=print_memory_stats, args=(primary, shutdown_event)
        )
        memory_thread.start()

        LOG.info("Waiting for completion...")
        vegeta_report.communicate()

        LOG.info("Shutting down...")
        shutdown_event.set()
        memory_thread.join()

        LOG.success("Done!")


if __name__ == "__main__":

    def add(parser):
        pass

    args, unknown_args = infra.e2e_args.cli_args(add=add, accept_unknown=True)
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args, unknown_args)