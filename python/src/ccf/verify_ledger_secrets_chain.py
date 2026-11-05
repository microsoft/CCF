# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import sys
from collections.abc import Sized
from typing import Any, TypedDict

import ccf.ledger


class HistoricalLedgerEntry(TypedDict):
    """Historical secret contents and the transaction that recorded them."""

    txid: tuple[int | None, int | None]
    entry: dict[str, Any]


def counted_string(string: Sized, name: str) -> str:
    """Format an object's length with a pluralised label."""
    return f"{len(string)} {name}{'s' * bool(len(string) != 1)}"


def historical_secrets_invariant(
    current: HistoricalLedgerEntry, prev: HistoricalLedgerEntry | None
) -> None:
    """Check that successive historical secrets link to the expected version."""
    if not prev:
        return

    # During startup or DR will have a next_version field
    if "next_version" in prev["entry"]:
        expected_next_version = prev["entry"]["next_version"]
        reported_version = current["entry"]["previous_ledger_secret"]["version"]
        assert expected_next_version == reported_version
    # During rekey adds one to the previous versions txid
    else:
        previous_seqno = prev["txid"][1]
        assert previous_seqno is not None
        expected_next_version = previous_seqno + 1
        reported_next_version = current["entry"]["previous_ledger_secret"]["version"]
        assert expected_next_version == reported_next_version


def run(paths: list[str], uncommitted: bool = False) -> bool:
    """Check the historical secret chain in ledger chunks, reporting failures."""
    historical_secrets_table = "public:ccf.internal.historical_encrypted_ledger_secret"

    ledger_paths = paths
    ledger = ccf.ledger.Ledger(
        ledger_paths,
        committed_only=not uncommitted,
        read_recovery_files=True,
    )

    print(f"Reading ledger from {ledger_paths}")
    print(f"Contains {counted_string(ledger, 'chunk')}")
    try:
        previous_historical_ledger_entry: HistoricalLedgerEntry | None = None
        for chunk in ledger:
            print(
                f"chunk {chunk.filename()} ({'' if chunk.is_committed() else 'un'}committed)"
            )
            for transaction in chunk:
                public_transaction = transaction.get_public_domain()
                public_tables = public_transaction.get_tables()
                for table_name, records in public_tables.items():
                    if table_name != historical_secrets_table:
                        continue

                    for value in records.values():
                        if value is not None:
                            transaction_id = transaction.get_txid()
                            txid = (transaction_id.view, transaction_id.seqno)
                            entry: HistoricalLedgerEntry = {
                                "txid": txid,
                                "entry": json.loads(value.decode("utf-8")),
                            }
                            print(json.dumps(entry))
                            historical_secrets_invariant(
                                entry, previous_historical_ledger_entry
                            )
                            previous_historical_ledger_entry = entry

    except Exception as e:
        print(f"Error parsing ledger: {e}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Verify that the ledger's secrets are valid",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "paths",
        help="Path to ledger directories, ledger chunks, or snapshot file. "
        "Note that parsing individual ledger chunks requires the additional --insecure-skip-verification option",
        nargs="+",
    )
    parser.add_argument(
        "--uncommitted", help="Also parse uncommitted ledger files", action="store_true"
    )

    args = parser.parse_args()

    if not run(
        args.paths,
        uncommitted=args.uncommitted,
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
