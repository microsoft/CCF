# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import sys
import json

from loguru import logger as LOG


def print_key(k, is_removed=False):
    if k == bytearray(8):
        k = "0"
    else:
        k = f"{k.decode()}"

    if is_removed:
        LOG.error(f"Removed {k}")
    else:
        LOG.info(f"{k}:")


if __name__ == "__main__":

    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    if len(sys.argv) < 2:
        LOG.error("First argument should be CCF ledger directory")
        sys.exit(1)

    ledger = ccf.ledger.Ledger(sys.argv[1])

    for chunk in ledger:
        for transaction in chunk:
            public_transaction = transaction.get_public_domain()
            public_tables = public_transaction.get_tables()

            LOG.success(
                f"seqno {public_transaction.get_seqno()} ({len(public_tables)} public table{'s' if len(public_tables) > 1 else ''})"
            )

            private_table_size = transaction.get_private_domain_size()
            if private_table_size:
                LOG.error(f"-- private: {private_table_size} bytes")

            for table_name, records in public_tables.items():
                LOG.warning(f'table "{table_name}":')
                for key, value in records.items():
                    if value is not None:
                        try:
                            value = json.dumps(json.loads(value), indent=2)
                        except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                            pass
                        finally:
                            print_key(key)
                            LOG.info(value)
                    else:
                        print_key(key, is_removed=True)
