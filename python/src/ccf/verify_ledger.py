# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from ccf.merkletree import MerkleTree
from ccf.read_ledger import counted_string
from ccf.tx_id import TxID
from cryptography.hazmat.primitives import hashes
from loguru import logger as LOG
import argparse
import base64
import ccf.ledger
import json
import sys


SIG_TABLE_NAME = ccf.ledger.SIGNATURE_TX_TABLE_NAME


class SparseValidator(ccf.ledger.BaseValidator):
    merkle: MerkleTree
    signature_count: int = 0
    last_verified_seqno: int = 0
    last_verified_view: int = 0

    def __init__(self):
        self.merkle = MerkleTree()
        empty_bytes_array = bytearray(hashes.SHA256.digest_size)
        self.merkle.add_leaf(empty_bytes_array, do_hash=False)

    def add_transaction(self, transaction, verify=False):
        if verify:
            transaction_public_domain = transaction.get_public_domain()
            tables = transaction_public_domain.get_tables()

            if SIG_TABLE_NAME in tables:
                sig_table = tables[SIG_TABLE_NAME]

                assert len(sig_table) == 1

                for _, signature in sig_table.items():
                    signature = json.loads(signature)

                    cert = signature["cert"].encode("utf-8")
                    root = bytes.fromhex(signature["root"])
                    sig = base64.b64decode(signature["sig"])

                    self._verify_root_signature(cert, root, sig)

                    self.signature_count += 1
                    self.last_verified_seqno = signature["seqno"]
                    self.last_verified_view = signature["view"]

        self.merkle.add_leaf(transaction.get_tx_digest(), False)

    def last_verified_txid(self) -> TxID:
        return TxID(self.last_verified_view, self.last_verified_seqno)


def run(
    paths,
):
    validator = SparseValidator()
    ledger_paths = paths
    ledger = ccf.ledger.Ledger(ledger_paths)

    LOG.info(f"Reading ledger from {ledger_paths}")
    LOG.info(f"Contains {counted_string(ledger, 'chunk')}")

    try:
        for chunk in ledger:
            LOG.info(
                f"chunk {chunk.filename()} ({'' if chunk.is_committed() else 'un'}committed)"
            )
            n = len(chunk)
            for i, transaction in enumerate(chunk):
                validator.add_transaction(
                    transaction,
                    verify=(i == 0 or i == n - 1),
                )

    except Exception as e:
        LOG.exception(f"Error parsing ledger: {e}")
        has_error = True
    else:
        LOG.success("Ledger verification complete")
        has_error = False
    finally:
        LOG.info(
            f"Checked {validator.signature_count} signatures, and verified until {validator.last_verified_txid()}"
        )

    return not has_error


def main():
    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    parser = argparse.ArgumentParser(
        description="Quickly verify CCF ledger",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "paths",
        help="Path to ledger directories, or ledger chunks.",
        nargs="+",
    )

    args = parser.parse_args()

    if not run(args.paths):
        sys.exit(1)


if __name__ == "__main__":
    main()
