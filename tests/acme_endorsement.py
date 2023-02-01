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
import socket
import ssl
import http
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec


from loguru import logger as LOG


def get_network_public_key(network):
    cert_data = open(os.path.join(network.common_dir, "service_cert.pem"), "rb").read()
    network_cert = load_pem_x509_certificate(cert_data, default_backend())
    return network_cert.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )


def wait_for_port_to_listen(host, port, timeout=10):
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            socket.create_connection((host, int(port)), timeout=0.1)
            return
        except Exception as ex:
            LOG.trace(f"Likely expected exception: {ex}")
            time.sleep(0.5)
    raise TimeoutError(f"port did not start listening within {timeout} seconds")


@reqs.description("Start network and wait for ACME certificates")
def wait_for_certificates(
    args, network_name, ca_certs, interface_name, challenge_interface, timeout=5 * 60
):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        # NB: Pebble non-deterministically injects delays and failures,
        # so the following checks may take a significant amount of time.

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
                iface = node.host.rpc_interfaces[interface_name]
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.check_hostname = True
                    for crt in ca_certs:
                        context.load_verify_locations(cadata=crt)

                    s = socket.socket()
                    s.settimeout(1)
                    c = context.wrap_socket(s, server_hostname=network_name)
                    c.connect((iface.host, iface.port))
                    cert_der = c.getpeercert(binary_form=True)
                    cert = load_der_x509_certificate(cert_der, default_backend())
                    if cert.subject.rfc4514_string() != "CN=" + network_name:
                        # pylint: disable=broad-exception-raised
                        raise Exception("Common name mismatch")
                    cert_public_key = cert.public_key().public_bytes(
                        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
                    )
                    if network_public_key != cert_public_key:
                        # pylint: disable=broad-exception-raised
                        raise Exception("Public key mismatch")
                    num_ok += 1
                except Exception as ex:
                    LOG.trace(f"Likely expected exception: {ex}")

            if num_ok != len(args.nodes):
                time.sleep(1)

        # We can't run test_unsecured_interfaces against the ACME-endorsed interface
        # here, because network_name may not be an address that the name server can
        # resolve, e.g. those that are added to the pebble mock dns server.
        # Conversely, if we were to use the IP address instead of the name, then
        # the ACME-certificate subject/SAN won't match.
        # I have not yet found a way to add a name server in such a way that
        # httpx.Client picks it up.

        test_unsecured_interfaces(
            network, infra.interfaces.PRIMARY_RPC_INTERFACE, challenge_interface
        )

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


def start_mock_dns(filename, listen_address, mgmt_address, out, err, env=None):
    p = subprocess.Popen(
        [
            filename,
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
        close_fds=True,
        env=env,
    )
    host, port = listen_address.split(":")
    wait_for_port_to_listen(host, port, 5)
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
    urllib.request.urlopen(f"http://{dns_mgmt_address}/add-a", data=data)

    # Disable the default IPv6 entry
    data = str(json.dumps({"ip": ""})).encode("utf-8")
    urllib.request.urlopen(
        "http://" + dns_mgmt_address + "/set-default-ipv6", data=data
    )


def start_pebble(filename, config_filename, dns_address, listen_address, out, err, env):
    p = subprocess.Popen(
        [
            filename,
            "--config",
            config_filename,
            "-dnsserver",
            dns_address,
        ],
        stdout=out,
        stderr=err,
        close_fds=True,
        env=env,
    )
    host, port = listen_address.split(":")
    wait_for_port_to_listen(host, port, 5)
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


@reqs.description("Test that secure content is not available on an unsecured interface")
def test_unsecured_interfaces(network, secured_interface, unsecured_interface):
    for node in network.nodes:
        with node.client(interface_name=secured_interface) as c:
            r = c.get("/node/network/nodes")
            assert r.status_code == http.HTTPStatus.OK
        with node.client(interface_name=unsecured_interface, protocol="http") as c:
            r = c.get("/node/network/nodes")
            assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE
        with node.client(interface_name=unsecured_interface, protocol="http") as c:
            r = c.get("/.well-known/acme-challenge/A1B2C3D4")
            assert r.status_code == http.HTTPStatus.NOT_FOUND


@reqs.description("Test against a local pebble CA")
def run_pebble(args):
    binary_filename = "/opt/pebble/pebble_linux-amd64"
    config_filename = "pebble.config.json"
    ca_key_filename = "pebble-key.pem"
    ca_cert_filename = "pebble-ca-cert.pem"
    output_filename = "pebble.out"
    error_filename = "pebble.err"
    listen_address = "127.0.0.1:1024"
    mgmt_address = "127.0.0.1:1025"
    tls_port = 1026
    http_port = 1027

    mock_dns_filename = "/opt/pebble/pebble-challtestsrv_linux-amd64"
    mock_dns_listen_address = "127.0.0.1:1028"
    mock_dns_mgmt_address = "127.0.0.1:1029"

    network_name = "my-network.ccf.dev"

    if not os.path.exists(binary_filename) or not os.path.exists(mock_dns_filename):
        # pylint: disable=broad-exception-raised
        raise Exception("pebble not found; run playbooks to install it")

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

    ca_key, _ = infra.crypto.generate_ec_keypair(ec.SECP384R1)
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
                "challenge_server_interface": "acme_challenge_server_if",
            }
        }
    }

    for node in args.nodes:
        endorsed_interface = infra.interfaces.RPCInterface(
            host=infra.net.expand_localhost(),
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.ACME,
                acme_configuration="pebble",
            ),
        )
        challenge_server_interface = infra.interfaces.RPCInterface(
            host=endorsed_interface.host,
            port=http_port,
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.Unsecured
            ),
            accepted_endpoints=["/.well-known/acme-challenge/.*"],
        )
        endorsed_interface.public_host = network_name
        node.rpc_interfaces["acme_endorsed_interface"] = endorsed_interface
        node.rpc_interfaces["acme_challenge_server_if"] = challenge_server_interface

    exception_seen = None

    with open(output_filename, "w", encoding="ascii") as out:
        with open(error_filename, "w", encoding="ascii") as err:
            mock_dns_proc = start_mock_dns(
                mock_dns_filename,
                mock_dns_listen_address,
                mock_dns_mgmt_address,
                out,
                err,
            )

            register_endorsed_hosts(args, network_name, mock_dns_mgmt_address)

            pebble_proc = start_pebble(
                binary_filename,
                config_filename,
                mock_dns_listen_address,
                listen_address,
                out,
                err,
                env={"PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_VA_NOSLEEP": "1"},
            )

            try:
                ca_certs = get_pebble_ca_certs(mgmt_address)
                wait_for_certificates(
                    args,
                    network_name,
                    ca_certs,
                    "acme_endorsed_interface",
                    "acme_challenge_server_if",
                )
            except Exception as ex:
                exception_seen = ex
            finally:
                if pebble_proc:
                    pebble_proc.kill()
                if mock_dns_proc:
                    mock_dns_proc.kill()

    if exception_seen:
        LOG.info("Pebble out:")
        LOG.info(open(output_filename, "r", encoding="ascii").read())
        LOG.info("Pebble err:")
        LOG.info(open(error_filename, "r", encoding="ascii").read())
        raise exception_seen


@reqs.description("Test against Let's Encrypt's staging environment")
def run_lets_encrypt(args):
    # This requires a DNS name by which the network is reachable (which we don't have in the CI), e.g. your dev VM name.
    # On the interface of that name, we also need port 80 to be reachable from the internet for the challenge responses (see Network on the Azure portal panel of your VM).
    # The Let's Encrypt staging environment is described here: https://letsencrypt.org/docs/staging-environment/ (we need the CA certs for the staging environment, which are not globally endorsed).
    # Further, to connect to Let's Encrypt, we also need their public root cert, which can be found at https://letsencrypt.org/certificates/
    # (Clients won't need this as they usually have ISRG Root X1 installed, but our enclaves don't.)

    service_dns_name = "..."  # Set to the DNS name of your machine

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
                "challenge_server_interface": "0.0.0.0:80",
            }
        },
    }

    for node in args.nodes:
        endorsed_interface = infra.interfaces.RPCInterface(
            host="0.0.0.0",
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.ACME
            ),
        )
        endorsed_interface.public_host = service_dns_name
        endorsed_interface.endorsement.acme_configuration = "letsencrypt"
        node.rpc_interfaces["acme_endorsed_interface"] = endorsed_interface

        if node == args.nodes[0]:
            # Only the first node offers the challenge server interface,
            # as only one can serve port 80.
            challenge_server_interface = infra.interfaces.RPCInterface(
                host=endorsed_interface.host,
                port=80,
                endorsement=infra.interfaces.Endorsement(
                    authority=infra.interfaces.EndorsementAuthority.Unsecured
                ),
                accepted_endpoints=["/.well-known/acme-challenge/.*"],
            )
            node.rpc_interfaces["acme_challenge_server_if"] = challenge_server_interface

    wait_for_certificates(
        args,
        service_dns_name,
        ca_certs,
        "acme_endorsed_interface",
        "acme_challenge_server_if",
    )


def run_unsecured(args):
    for node in args.nodes:
        endorsed_interface = infra.interfaces.RPCInterface(
            host=infra.net.expand_localhost(),
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.Node,
            ),
        )
        challenge_server_interface = infra.interfaces.RPCInterface(
            host=endorsed_interface.host,
            port=1024,
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.Unsecured
            ),
            accepted_endpoints=["/.well-known/acme-challenge/.*"],
        )
        node.rpc_interfaces["secured_interface"] = endorsed_interface
        node.rpc_interfaces["unsecured_interface"] = challenge_server_interface

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_unsecured_interfaces(network, "secured_interface", "unsecured_interface")


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run_pebble(args)
    run_unsecured(args)
    # run_lets_encrypt(args)
