# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import subprocess
import json
import base64
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


def run(args, additional_attack_args):
    hosts = ["localhost", "localhost", "localhost"]

    # Test that vegeta is available
    subprocess.run([VEGETA_BIN, "-version"], capture_output=True)

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

        report_cmd = [VEGETA_BIN, "report"]
        report_cmd_s = " ".join(report_cmd)
        vegeta_report = subprocess.Popen(
            report_cmd,
            stdin=tee_split.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        LOG.info("Waiting for completion...")
        report_out, report_err = vegeta_report.communicate()

        LOG.info(f"Report output:\n{report_out.decode()}")
        if report_err:
            LOG.error(f"Error running '{' '.join(attack_cmd)}':\n{report_err.decode()}")


if __name__ == "__main__":

    args, unknown_args = infra.e2e_args.cli_args(accept_unknown=True)
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args, unknown_args)
