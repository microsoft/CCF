# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    load_pem_x509_certificate,
)
from pyasn1.type.useful import UTCTime


def get_validity_period_from_pem_cert(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.not_valid_before, cert.not_valid_after


def datetime_as_UTCtime(datetime: datetime):
    return UTCTime.fromDateTime(datetime)


def verify_certificate_validity_period(
    pem: str, expected_validity_period_days: int, expected_valid_from=None
):
    valid_from, valid_to = get_validity_period_from_pem_cert(pem)

    # By default, assume that certificate has been issued within this test run
    expected_valid_from = expected_valid_from or (
        datetime.utcnow() - timedelta(hours=1)
    )
    if valid_from < expected_valid_from:
        raise ValueError(
            f'Certificate is too old: valid from "{valid_from}", expected "{expected_valid_from}"'
        )

    # Note: CCF substracts one second from validity period since x509
    # specifies that validity dates are inclusive.
    expected_valid_to = valid_from + timedelta(
        days=expected_validity_period_days, seconds=-1
    )
    if valid_to != expected_valid_to:
        raise ValueError(
            f'Validity period for certiticate is not as expected: valid to "{valid_to}, expected to "{expected_valid_to}"'
        )
