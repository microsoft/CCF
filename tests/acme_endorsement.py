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


@reqs.description("Start network and wait for ACME certificates")
def wait_for_certificates(args, network_name, ca_certs, timeout=60):
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
                    s.settimeout(1)
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
                    LOG.debug(f"Likely expected exception: {ex}")

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


@reqs.description("Test against a local pebble CA")
def run_pebble(args):
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
                        wait_for_certificates(args, network_name, ca_certs)
                        pebble_proc.kill()

                mock_dns_proc.kill()

    except Exception as ex:
        LOG.error(f"Exception: {ex}")

    LOG.info("Pebble stdout:")
    LOG.info(open(output_filename, "r", encoding="ascii").read())
    LOG.info("Pebble err:")
    LOG.info(open(error_filename, "r", encoding="ascii").read())


@reqs.description("Test against Let's Encrypt's staging environment")
def run_lets_encrypt(args):

    #  This requires a DNS name by which the network is reachable (which we don't have in the CI).
    service_dns_name = "acc-cwinter.uksouth.cloudapp.azure.com"

    ca_certs = [
        "-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIDCzCCApGgAwIBAgIRALRY4992FVxZJKOJ3bpffWIwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowVTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSQwIgYDVQQD\nExsoU1RBR0lORykgRXJzYXR6IEVkYW1hbWUgRTEwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAAT9v/PJUtHOTk28nXCXrpP665vI4Z094h8o7R+5E6yNajZa0UubqjpZFoGq\nu785/vGXj6mdfIzc9boITGusZCSWeMj5ySMZGZkS+VSvf8VQqj+3YdEu4PLZEjBA\nivRFpEejggEQMIIBDDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\nAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOv5JcKA\nKGbibQiSMvPC4a3D/zVFMB8GA1UdIwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5Vm\nMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxl\nbmNyLm9yZy8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNy\nLm9yZy8wIgYDVR0gBBswGTAIBgZngQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZI\nzj0EAwMDaAAwZQIwXcZbdgxcGH9rTErfSTkXfBKKygU0yO7OpbuNeY1id0FZ/hRY\nN5fdLOGuc+aHfCsMAjEA0P/xwKr6NQ9MN7vrfGAzO397PApdqfM7VdFK18aEu1xm\n3HMFKzIR8eEPsMx4smMl\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo\nFQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT\nVqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI\nKoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo\nuc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9\nvbtH7QiVzeKCOTQPINyRql6P\n-----END CERTIFICATE-----\n",
    ]

    args.acme = {
        "configurations": {
            "letsencrypt": {
                "ca_certs": ca_certs,
                "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "service_dns_name": service_dns_name,
                "contact": ["mailto:admin@ccf.dev"],
                "terms_of_service_agreed": True,
                "challenge_type": "http-01",
            }
        },
        "challenge_server_interface": "0.0.0.0:80",
    }

    for node in args.nodes:
        endorsed_interface = infra.interfaces.RPCInterface(
            host="0.0.0.0",
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.ACME
            ),
        )
        endorsed_interface.public_host = service_dns_name
        endorsed_interface.acme_configuration = "letsencrypt"
        node.rpc_interfaces["acme_endorsed_interface"] = endorsed_interface

    wait_for_certificates(args, service_dns_name, ca_certs)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=1)
    run_pebble(args)
    # run_lets_encrypt(args)
