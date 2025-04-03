# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import subprocess
import sys
import tempfile
import os
import shlex


def run(cert_test):
    def test(args, *substrs):
        with tempfile.NamedTemporaryFile() as ntf:
            print(f"Running: {shlex.join([cert_test] + args)}")
            subprocess.run([cert_test] + args, stdout=ntf, check=True)
            ntf.flush()
            rv = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-nameopt",
                    "space_eq",
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
                print("All asserts passed")
            except AssertionError:
                print(rv.stdout.decode(), file=sys.stderr)
                raise

    test(
        ["--sn=CN=subject1", "--san=iPAddress:1.2.3.4"],
        "Subject: CN = subject1\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "IP Address:1.2.3.4",
    )

    test(
        [
            "--sn=CN=subject2",
            "--san=iPAddress:1.2.3.4",
            "--san=iPAddress:192.168.200.123",
        ],
        "Subject: CN = subject2\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "IP Address:192.168.200.123",
        "IP Address:1.2.3.4",
    )

    test(
        ["--sn=CN=subject3", "--san=dNSName:sub.domain.tld"],
        "Subject: CN = subject3\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "DNS:sub.domain.tld",
    )

    test(
        [
            "--sn=CN=subject4",
            "--san=iPAddress:1.2.3.4",
            "--san=dNSName:sub.domain.tld",
            "--san=iPAddress:192.168.200.123",
        ],
        "Subject: CN = subject4\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "IP Address:192.168.200.123",
        "DNS:sub.domain.tld",
        "IP Address:1.2.3.4",
    )

    MAX_SUBJECT_LENGTH = 64
    PREFIX = "CN="
    long_subject = PREFIX + "a" * (MAX_SUBJECT_LENGTH - len(PREFIX))
    test(
        [f"--sn=CN={long_subject}", "--san=iPAddress:1.2.3.4"],
        f"Subject: CN = {long_subject}\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        "IP Address:1.2.3.4",
    )

    MAX_DNSNAME_SAN_LENGTH = 4096
    long_dnsname = "a" * MAX_DNSNAME_SAN_LENGTH
    test(
        ["--sn=CN=subject3", f"--san=dNSName:{long_dnsname}"],
        "Subject: CN = subject3\n",
        "X509v3 Subject Alternative Name: \n" + 16 * " ",
        f"DNS:{long_dnsname}",
    )


if __name__ == "__main__":
    run(sys.argv[1])
