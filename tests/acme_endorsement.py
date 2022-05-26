# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import subprocess
import os
from time import sleep
import urllib.request
import json
import base64
import infra.network
import infra.path
import infra.proc
import infra.interfaces
import infra.net
import infra.e2e_args
import infra.crypto
import suite.test_requirements as reqs
import os

from loguru import logger as LOG


def test_with_pebble(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        return


def run(args):
    binary_url = (
        "https://github.com/letsencrypt/pebble/releases/latest/download/pebble_linux-amd64",
    )
    binary_filename = "pebble_linux-amd64"
    config_filename = "pebble.config.json"
    ca_key_filename = "pebble-key.pem"
    ca_cert_filename = "pebble-ca-cert.pem"
    output_filename = "pebble.out"
    error_filename = "pebble.err"
    listen_address = "127.0.0.1:14000"

    if not os.path.isfile(binary_filename):
        urllib.request.urlretrieve(
            binary_url,
            binary_filename,
        )
        os.chmod(binary_filename, 0o744)

    config = {
        "pebble": {
            "listenAddress": listen_address,
            "managementListenAddress": "127.0.0.1:15000",
            "certificate": ca_cert_filename,
            "privateKey": ca_key_filename,
            "httpPort": 5002,
            "tlsPort": 5001,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": False,
        }
    }
    with open(config_filename, "w", encoding="ascii") as f:
        json.dump(config, f)

    ca_key, _ = infra.crypto.generate_ec_keypair("secp384r1")
    with open(ca_key_filename, "w", encoding="ascii") as f:
        f.write(ca_key)

    ca_cert = infra.crypto.generate_cert(ca_key)
    with open(ca_cert_filename, "w", encoding="ascii") as f:
        f.write(ca_cert)

    args.acme_configurations = {
        "pebble": {
            "ca_certs": [ca_cert],
            "directory_url": f"https://{listen_address}/dir",
            "service_dns_name": "localhost",
            "contact": ["mailto:nobody@example.com"],
            "terms_of_service_agreed": True,
            "challenge_type": "http-01",
        }
    }
    args.acme_challenge_interface = "0.0.0.0:5002"

    for node in args.nodes:
        host = infra.net.expand_localhost()
        endorsed_interface = infra.interfaces.RPCInterface(
            host=host,
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.ACME
            ),
        )
        # endorsed_interface.public_host = "my-ccf.adns.ccf.dev"
        endorsed_interface.acme_configuration = "pebble"
        node.rpc_interfaces["acme_endorsed_interface"] = endorsed_interface

    try:
        with open(output_filename, "w", encoding="ascii") as out:
            with open(error_filename, "w", encoding="ascii") as err:
                with subprocess.Popen(
                    ["./" + binary_filename, "--config", config_filename],
                    stdout=out,
                    stderr=err,
                ) as proc:
                    test_with_pebble(args)
                    proc.kill()
    except Exception as ex:
        LOG.error(f"Exception: {ex}")
        LOG.info("Pebble standard output:")
        print(open(output_filename, "r", encoding="ascii").read())
        LOG.info("Pebble error output:")
        print(open(error_filename, "r", encoding="ascii").read())


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
