# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import subprocess
import sys
import tempfile
import os


def run(cert_test):
    def test(args, *substrs):
        with tempfile.NamedTemporaryFile() as ntf:
            subprocess.run([cert_test] + args, stdout=ntf, check=True)
            ntf.flush()
            rv = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    os.path.join(tempfile.gettempdir(), ntf.name),
                    "-text",
                ],
                capture_output=True,
                check=True,
            )
            try:
                for substr in substrs:
                    assert substr in rv.stdout.decode()
            except AssertionError:
                print(rv.stdout.decode(), file=sys.stderr)
                raise

    test(
        ["--sn=CN=subject", "--san=iPAddress:1.2.3.4"],
        "Subject: CN = subject\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "IP Address:1.2.3.4",
    )

    test(
        [
            "--sn=CN=subject",
            "--san=iPAddress:1.2.3.4",
            "--san=iPAddress:192.168.200.123",
        ],
        "Subject: CN = subject\n",
        "X509v3 Subject Alternative Name: \n"
        + 16 * " ",
        "IP Address:192.168.200.123",
        "IP Address:1.2.3.4"
    )

    test(
        ["--sn=CN=subject", "--san=dNSName:sub.domain.tld"],
        "Subject: CN = subject\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "DNS:sub.domain.tld"
    )

    test(
        [
            "--sn=CN=subject",
            "--san=iPAddress:1.2.3.4",
            "--san=dNSName:sub.domain.tld",
            "--san=iPAddress:192.168.200.123",
        ],
        "Subject: CN = subject\n",
        "X509v3 Subject Alternative Name: \n"
        + 16 * " ",
        "IP Address:192.168.200.123",
        "DNS:sub.domain.tld",
        "IP Address:1.2.3.4",
    )


if __name__ == "__main__":
    run(sys.argv[1])
