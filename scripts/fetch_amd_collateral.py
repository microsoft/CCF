# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
from enum import Enum
import logging
import sys
import httpx
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class AMDCPUFamily(Enum):
    MILAN = "Milan"
    GENOA = "Genoa"
    TURIN = "Turin"


def make_host_amd_blob(tcbm, leaf, chain):
    return (
        "{"
        + f'tcbm={tcbm}, leaf="{leaf.encode("unicode_escape").decode("utf-8")}", chain="{chain.encode("unicode_escape").decode("utf-8")}"'
        + "}"
    )


def make_leaf_url(base_url, product_family, chip_id, tcbm):
    if len(tcbm) != 16:
        raise ValueError("TCBM must be 16 hex characters (64 bits)")

    if product_family in [AMDCPUFamily.MILAN.value, AMDCPUFamily.GENOA.value]:
        assert len(chip_id) == 32 * 2, "Chip ID must be 32 bytes long"
        hwid = chip_id[0 : 32 * 2]
        params = {
            "ucodeSPL": int(tcbm[0:2], base=16),
            "snpSPL": int(tcbm[2:4], base=16),
            # 4 reserved bytes
            "teeSPL": int(tcbm[12:14], base=16),
            "blSPL": int(tcbm[14:16], base=16),
        }
    elif product_family == AMDCPUFamily.TURIN.value:
        # Note hwid is explicitly shortened for turin (the full chip_id in the attestation will not work)
        # See Table 11 (section 3.1) of the VCEK spec for details
        assert (
            len(chip_id) >= 8 * 2
        ), "Chip ID should be at least 8 bytes long for Turin"
        hwid = chip_id[0 : 8 * 2]
        assert chip_id[8 * 2 :] == "0" * (
            len(chip_id) - len(hwid)
        ), "Chip ID bytes 8-32 should be zero for Turin"
        params = {
            "ucodeSPL": int(tcbm[0:2], base=16),
            # 3 reserved bytes
            "snpSPL": int(tcbm[8:10], base=16),
            "teeSPL": int(tcbm[10:12], base=16),
            "blSPL": int(tcbm[12:14], base=16),
            "fmcSPL": int(tcbm[14:16], base=16),
        }
    else:
        raise ValueError(f"Unknown product family {product_family}")

    return f"{base_url}/vcek/v1/{product_family}/{hwid}?" + "&".join(
        [f"{k}={v}" for k, v in params.items()]
    )


def make_chain_url(base_url, product_family):
    return f"{base_url}/vcek/v1/{product_family}/cert_chain"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch AMD collateral data.")
    parser.add_argument(
        "-u",
        "--base-url",
        type=str,
        default="https://kdsintf.amd.com:443",
        help="URL to fetch the AMD collateral data from.",
    )
    parser.add_argument(
        "--chip-id",
        type=str,
        help="Chip ID (hex 64 byte, from attestation) for the the AMD leaf cert.",
    )
    parser.add_argument(
        "--tcb",
        type=str,
        help="TCB (hex 64 bits eg DB18000000000004 from attestation).",
    )
    parser.add_argument(
        "--product-family",
        type=str,
        default="Milan",
        choices=[pf.value for pf in AMDCPUFamily],
        help="AMD product family",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file to write the AMD host certs to.",
    )
    parser.add_argument(
        "--output-format",
        type=str,
        choices=["json", "b64"],
        default="b64",
        help="Output format for the AMD host certs.",
    )

    args = parser.parse_args()

    # log to stderr
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    leaf_url = make_leaf_url(
        args.base_url,
        args.product_family,
        args.chip_id,
        args.tcb,
    )

    logging.info(f"Fetching AMD leaf cert from {leaf_url}")
    with httpx.Client() as client:
        leaf_response = client.get(
            leaf_url,
        )
        leaf_response.raise_for_status()
        der = leaf_response.content
        leaf = (
            x509.load_der_x509_certificate(der, default_backend())
            .public_bytes(serialization.Encoding.PEM)
            .decode("utf-8")
        )
        logging.info(f"AMD leaf cert response: {leaf}")

    chain_url = make_chain_url(args.base_url, args.product_family)

    logging.info(f"Fetching AMD chain cert from {chain_url}")
    with httpx.Client() as client:
        chain_response = client.get(chain_url)
        chain_response.raise_for_status()
        chain = chain_response.text
        logging.info(f"AMD chain cert response: {chain_response.text}")

    blob = make_host_amd_blob(
        tcbm=args.tcb,
        leaf=leaf,
        chain=chain,
    )

    output_stream = sys.stdout if not args.output else open(args.output, "w")

    if args.output_format == "json":
        output_stream.write(blob)
    elif args.output_format == "b64":
        output_stream.write(base64.b64encode(blob.encode("utf-8")).decode("utf-8"))
    else:
        logging.error(f"Unknown output format {args.output_format}")
        sys.exit(1)
