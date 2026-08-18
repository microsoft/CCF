# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import infra.e2e_args


class E2EArgsTest(unittest.TestCase):
    def parse_args(self, *args, use_host_config_defaults=False):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        with patch.object(sys, "argv", ["e2e_args_test.py", *args]):
            parsed_args = infra.e2e_args.cli_args(
                parser=parser,
                use_host_config_defaults=use_host_config_defaults,
            )
        return parsed_args, parser

    def test_e2e_defaults_are_unchanged(self):
        with patch.dict(os.environ, {"ELECTION_TIMEOUT_MS": ""}):
            args, _ = self.parse_args()

        self.assertEqual(args.sig_ms_interval, 100)
        self.assertEqual(args.election_timeout_ms, 4000)
        self.assertEqual(args.ledger_chunk_bytes, "20KB")
        self.assertEqual(args.snapshot_tx_interval, 10)
        self.assertEqual(args.tick_ms, 1)

    def test_host_config_defaults_and_descriptions(self):
        args, parser = self.parse_args(use_host_config_defaults=True)

        self.assertEqual(args.sig_ms_interval, 1000)
        self.assertEqual(args.election_timeout_ms, 5000)
        self.assertEqual(args.ledger_chunk_bytes, "5MB")
        self.assertEqual(args.snapshot_tx_interval, 10000)
        self.assertEqual(args.tick_ms, 10)
        self.assertEqual(args.initial_node_cert_validity_days, 1)
        self.assertEqual(args.initial_service_cert_validity_days, 1)

        signature_delay = next(
            action for action in parser._actions if action.dest == "sig_ms_interval"
        )
        schema = infra.e2e_args._load_host_config_schema()
        schema_signature_delay = schema["properties"]["ledger_signatures"][
            "properties"
        ]["delay"]
        self.assertEqual(signature_delay.help, schema_signature_delay["description"])
        self.assertIn("(default: 1000)", parser.format_help())

    def test_explicit_argument_overrides_host_config_default(self):
        args, _ = self.parse_args(
            "--sig-ms-interval",
            "250",
            use_host_config_defaults=True,
        )

        self.assertEqual(args.sig_ms_interval, 250)

    def test_start_network_uses_host_config_defaults(self):
        result = subprocess.run(
            [
                sys.executable,
                Path(__file__).with_name("start_network.py"),
                "--use-defaults-from-host-config",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        normalised_help = " ".join(result.stdout.split())
        schema = infra.e2e_args._load_host_config_schema()
        signature_description = schema["properties"]["ledger_signatures"][
            "properties"
        ]["delay"]["description"]
        self.assertIn(signature_description, normalised_help)
        self.assertIn("(default: 1000)", normalised_help)


if __name__ == "__main__":
    unittest.main()
