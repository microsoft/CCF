# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import subprocess
import json
import base64
import threading
import time
from loguru import logger as LOG

VEGETA_BIN = "/opt/vegeta/vegeta"


def build_vegeta_target(node, path, body=None, method="POST"):
    target = {}
    target["method"] = method
    target["url"] = f"https://{node.pubhost}:{node.rpc_port}{path}"
    target["header"] = {"Content-Type": ["application/json"]}
    if body is not None:
        # Bodies must be base64 encoded strings
        target["body"] = base64.b64encode(json.dumps(body, indent=2).encode()).decode()
    return target


def write_vegeta_target_line(f, *args, **kwargs):
    target = build_vegeta_target(*args, **kwargs)
    f.write(json.dumps(target))
    f.write("\n")


def print_memory_stats(node, shutdown_event):
    with node.client() as c:
        while not shutdown_event.is_set():
            r = c.get("/node/memory")
            LOG.warning(r.body.json())
            time.sleep(10)


def run(args, additional_attack_args):
    hosts = ["localhost", "localhost", "localhost"]

    # Test that vegeta is available
    subprocess.run([VEGETA_BIN, "-version"], capture_output=True, check=True)

    with infra.network.network(
        hosts,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_join(args)

        primary, _ = network.find_primary()

        vegeta_targets = "vegeta_targets"
        with open(vegeta_targets, "w") as f:
            for i in range(10):
                write_vegeta_target_line(
                    f,
                    primary,
                    "/app/log/private",
                    body={"id": i, "msg": f"Private message: {i}"},
                )

            for i in range(10):
                write_vegeta_target_line(
                    f, primary, f"/app/log/private?id={i}", method="GET"
                )

            for i in range(10):
                write_vegeta_target_line(
                    f,
                    primary,
                    "/app/log/public",
                    body={"id": i, "msg": f"Public message: {i}"},
                )

            for i in range(10):
                write_vegeta_target_line(
                    f, primary, f"/app/log/public?id={i}", method="GET"
                )

        attack_cmd = [VEGETA_BIN, "attack"]
        attack_cmd += ["--targets", vegeta_targets]
        attack_cmd += ["--format", "json"]
        attack_cmd += ["--duration", "10s"]
        certs = primary.client_certs("user0")
        attack_cmd += ["--cert", certs["cert"]]
        attack_cmd += ["--key", certs["key"]]
        attack_cmd += ["--root-certs", certs["ca"]]
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
    args.package = "liblogging"
    run(args, unknown_args)
