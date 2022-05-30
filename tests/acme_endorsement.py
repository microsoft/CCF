# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import subprocess
import os
import time
import urllib.request
import json

import infra.network
import infra.path
import infra.proc
import infra.interfaces
import infra.net
import infra.e2e_args
import infra.crypto
import suite.test_requirements as reqs
from socket import socket
import ssl
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from loguru import logger as LOG


def get_network_public_key(network):
    cert_data = open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    network_cert = load_pem_x509_certificate(cert_data, default_backend())
    return network_cert.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )


@reqs.description("Start network and check for ACME certificates")
def test_with_pebble(args, network_name, ca_certs, timeout=60):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        # NB: Pebble non-deterministically injects delays and failures,
        # so the following checks may take a signficant amount of time.

        network_public_key = get_network_public_key(network)

        start_time = time.time()
        end_time = start_time + timeout
        num_ok = 0
        while num_ok != len(args.nodes):
            if time.time() > end_time:
                raise TimeoutError(
                    f"Not all nodes had the correct ACME-endorsed TLS certificate installed after {timeout} seconds"
                )

            num_ok = 0
            for node in network.nodes:
                iface = node.host.rpc_interfaces["acme_endorsed_interface"]
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.check_hostname = True
                    for crt in ca_certs:
                        context.load_verify_locations(cadata=crt)

                    s = socket()
                    c = context.wrap_socket(s, server_hostname=network_name)
                    c.connect((iface.host, iface.port))
                    cert_der = c.getpeercert(binary_form=True)
                    cert = load_der_x509_certificate(cert_der, default_backend())
                    if cert.subject.rfc4514_string() != "CN=" + network_name:
                        raise Exception("Common name mismatch")
                    cert_public_key = cert.public_key().public_bytes(
                        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
                    )
                    if network_public_key != cert_public_key:
                        raise Exception("Public key mismatch")
                    num_ok += 1
                except Exception as ex:
                    LOG.trace(f"Likely expected exception: {ex}")

            if num_ok != len(args.nodes):
                time.sleep(1)

        LOG.info(
            f"Success: all nodes had correct certificates installed after {int(time.time() - start_time)} seconds"
        )


def get_binary(url, filename):
    if not os.path.isfile(filename):
        urllib.request.urlretrieve(
            url,
            filename,
        )
        os.chmod(filename, 0o744)


def start_mock_dns(filename, listen_address, mgmt_address, out, err):
    p = subprocess.Popen(
        [
            "./" + filename,
            "-http01",
            "",
            "-https01",
            "",
            "-dns01",
            listen_address,
            "-tlsalpn01",
            "",
            "-management",
            mgmt_address,
        ],
        stdout=out,
        stderr=err,
    )
    time.sleep(1)
    return p


def register_endorsed_hosts(args, network_name, dns_mgmt_address):
    endorsed_hosts = [
        node.rpc_interfaces["acme_endorsed_interface"].host for node in args.nodes
    ]
    data = str(
        json.dumps(
            {
                "host": network_name,
                "addresses": endorsed_hosts,
            }
        )
    ).encode("utf-8")
    urllib.request.urlopen("http://" + dns_mgmt_address + "/add-a", data=data)

    # Disable the default IPv6 entry
    data = str(json.dumps({"ip": ""})).encode("utf-8")
    urllib.request.urlopen(
        "http://" + dns_mgmt_address + "/set-default-ipv6", data=data
    )


def start_pebble(filename, config_filename, dns_address, out, err):
    p = subprocess.Popen(
        [
            "./" + filename,
            "--config",
            config_filename,
            "-dnsserver",
            dns_address,
        ],
        stdout=out,
        stderr=err,
    )
    time.sleep(1)
    return p


def get_without_cert_check(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx).read().decode("utf-8")


def get_pebble_ca_certs(mgmt_address):
    ca = get_without_cert_check("https://" + mgmt_address + "/roots/0")
    intermediate = get_without_cert_check(
        "https://" + mgmt_address + "/intermediates/0"
    )
    return ca, intermediate


def run(args):
    binary_url = "https://github.com/letsencrypt/pebble/releases/latest/download/pebble_linux-amd64"
    binary_filename = "pebble_linux-amd64"
    config_filename = "pebble.config.json"
    ca_key_filename = "pebble-key.pem"
    ca_cert_filename = "pebble-ca-cert.pem"
    output_filename = "pebble.out"
    error_filename = "pebble.err"
    listen_address = "127.0.0.1:1024"
    mgmt_address = "127.0.0.1:1025"
    tls_port = 1026
    http_port = 1027

    mock_dns_url = "https://github.com/letsencrypt/pebble/releases/latest/download/pebble-challtestsrv_linux-amd64"
    mock_dns_filename = "pebble-challtestsrv_linux-amd64"
    mock_dns_listen_address = "127.0.0.1:1028"
    mock_dns_mgmt_address = "127.0.0.1:1029"

    network_name = "my-network.ccf.dev"

    get_binary(binary_url, binary_filename)
    get_binary(mock_dns_url, mock_dns_filename)

    config = {
        "pebble": {
            "listenAddress": listen_address,
            "managementListenAddress": mgmt_address,
            "certificate": ca_cert_filename,
            "privateKey": ca_key_filename,
            "httpPort": http_port,
            "tlsPort": tls_port,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": False,
        }
    }
    with open(config_filename, "w", encoding="ascii") as f:
        json.dump(config, f)

    ca_key, _ = infra.crypto.generate_ec_keypair("secp384r1")
    with open(ca_key_filename, "w", encoding="ascii") as f:
        f.write(ca_key)

    ca_cert = infra.crypto.generate_cert(ca_key, ca=True, cn="Pebble Test CA")
    with open(ca_cert_filename, "w", encoding="ascii") as f:
        f.write(ca_cert)

    args.acme = {
        "configurations": {
            "pebble": {
                "ca_certs": [ca_cert],
                "directory_url": f"https://{listen_address}/dir",
                "service_dns_name": network_name,
                "contact": ["mailto:nobody@example.com"],
                "terms_of_service_agreed": True,
                "challenge_type": "http-01",
            }
        }
    }

    for node in args.nodes:
        endorsed_interface = infra.interfaces.RPCInterface(
            host=infra.net.expand_localhost(),
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.ACME
            ),
        )
        endorsed_interface.public_host = network_name
        endorsed_interface.acme_configuration = "pebble"
        node.rpc_interfaces["acme_endorsed_interface"] = endorsed_interface
        node.acme_challenge_server_interface = (
            endorsed_interface.host + ":" + str(http_port)
        )

    try:
        with open(output_filename, "w", encoding="ascii") as out:
            with open(error_filename, "w", encoding="ascii") as err:
                with start_mock_dns(
                    mock_dns_filename,
                    mock_dns_listen_address,
                    mock_dns_mgmt_address,
                    out,
                    err,
                ) as mock_dns_proc:

                    register_endorsed_hosts(args, network_name, mock_dns_mgmt_address)

                    with start_pebble(
                        binary_filename,
                        config_filename,
                        mock_dns_listen_address,
                        out,
                        err,
                    ) as pebble_proc:

                        ca_certs = get_pebble_ca_certs(mgmt_address)
                        test_with_pebble(args, network_name, ca_certs)
                        pebble_proc.kill()

                mock_dns_proc.kill()

    except Exception as ex:
        LOG.error(f"Exception: {ex}")

    LOG.info("Pebble stdout:")
    LOG.info(open(output_filename, "r", encoding="ascii").read())
    LOG.info("Pebble err:")
    LOG.info(open(error_filename, "r", encoding="ascii").read())


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=1)
    run(args)
