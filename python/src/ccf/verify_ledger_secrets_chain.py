# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import sys
import json
import argparse

from loguru import logger as LOG


def counted_string(string, name):
    return f"{len(string)} {name}{'s' * bool(len(string) != 1)}"


def historical_secrets_invariant(current, prev):
    if not prev:
        return

    # During startup or DR will have a next_version field
    if "next_version" in prev["entry"]:
        expected_next_version = prev["entry"]["next_version"]
        reported_version = current["entry"]["previous_ledger_secret"]["version"]
        assert expected_next_version == reported_version
    # During rekey adds one to the previous versions txid
    else:
        expected_next_version = prev["txid"][1] + 1
        reported_next_version = current["entry"]["previous_ledger_secret"]["version"]
        assert expected_next_version == reported_next_version


def run(paths, uncommitted=False):
    historical_secrets_table = "public:ccf.internal.historical_encrypted_ledger_secret"

    ledger_paths = paths
    ledger = ccf.ledger.Ledger(
        ledger_paths,
        committed_only=not uncommitted,
        read_recovery_files=True,
    )

    LOG.info(f"Reading ledger from {ledger_paths}")
    LOG.info(f"Contains {counted_string(ledger, 'chunk')}")
    try:
        previous_historical_ledger_entry = None
        for chunk in ledger:
            LOG.info(
                f"chunk {chunk.filename()} ({'' if chunk.is_committed() else 'un'}committed)"
            )
            for transaction in chunk:
                public_transaction = transaction.get_public_domain()
                public_tables = public_transaction.get_tables()
                for table_name, records in public_tables.items():
                    if table_name != historical_secrets_table:
                        continue

                    for _, value in records.items():
                        if value is not None:
                            txid = (
                                transaction.gcm_header.view,
                                transaction.gcm_header.seqno,
                            )
                            entry = {
                                "txid": txid,
                                "entry": json.loads(value.decode("utf-8")),
                            }
                            LOG.info(json.dumps(entry))
                            historical_secrets_invariant(
                                entry, previous_historical_ledger_entry
                            )
                            previous_historical_ledger_entry = entry

    except Exception as e:
        LOG.exception(f"Error parsing ledger: {e}")
        return False
    return True


def main():
    LOG.remove()
    LOG.add(sys.stdout, format="<level>{message}</level>")

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
