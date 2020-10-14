# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import subprocess
import json
import base64
from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    # Test that vegeta is available
    subprocess.run(["vegeta", "-version"], capture_output=True)

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
            for i in range(5):
                target = {}
                target["method"] = "POST"
                target[
                    "url"
                ] = f"https://{primary.pubhost}:{primary.rpc_port}/app/log/public"
                target["header"] = {"Content-Type": ["application/json"]}
                body = {}
                body["id"] = i
                body["msg"] = "Some logged message body"
                # Bodies must be base64 encoded strings
                target["body"] = base64.b64encode(
                    json.dumps(body, indent=2).encode()
                ).decode()

                json.dump(target, f)
                f.write("\n")

        attack_cmd = ["vegeta", "attack"]
        attack_cmd += ["--targets", vegeta_targets]
        attack_cmd += ["--format", "json"]
        attack_cmd += ["--duration", "10s"]
        certs = primary.client_certs("user0")
        attack_cmd += ["--cert", certs["cert"]]
        attack_cmd += ["--key", certs["key"]]
        attack_cmd += ["--root-certs", certs["ca"]]

        attack_cmd_s = ' '.join(attack_cmd)
        LOG.warning(f"Starting: {attack_cmd_s}")
        vegeta_run = subprocess.Popen(attack_cmd, stdout=subprocess.PIPE)

        report_cmd = ["vegeta", "report"]
        report_cmd_s = ' '.join(report_cmd)
        vegeta_report = subprocess.Popen(
            report_cmd,
            stdin=vegeta_run.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        LOG.info("Waiting for completion...")
        report_out, report_err = vegeta_report.communicate()

        LOG.info(f"Report output:\n{report_out.decode()}")
        if report_err:
            LOG.error(f"Error running '{' '.join(attack_cmd)}':\n{report_err.decode()}")
        LOG.info(f"Err was:\n{report_err}")


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
