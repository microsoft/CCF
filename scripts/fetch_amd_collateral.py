# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import logging
import sys
import httpx
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json


def make_host_amd_blob(tcbm, leaf, chain):
    return json.dumps(
        {
            "cacheControl": "0",
            "tcbm": tcbm.upper(),
            "vcekCert": leaf,
            "certificateChain": chain,
        }
    )


def make_leaf_url(base_url, product_family, chip_id, tcbm):
    microcode = int(tcbm[0:2], base=16)
    snp = int(tcbm[2:4], base=16)
    # 4 reserved bytes
    tee = int(tcbm[12:14], base=16)
    bootloader = int(tcbm[14:16], base=16)

    return (
        f"{base_url}/vcek/v1/{product_family}/{chip_id}"
        + f"?blSPL={bootloader}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={microcode}"
    )


def make_chain_url(base_url, product_family):
    return f"{base_url}/vcek/v1/{product_family}/cert_chain"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch AMD collateral data.")
    parser.add_argument(
        "-u",
        "--base-url",
        type=str,
        default="https://kdsintf.amd.com",
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
        help="AMD product family (e.g., Milan, Genoa).",
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
