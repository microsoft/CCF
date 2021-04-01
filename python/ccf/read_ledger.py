# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import sys
import json

from loguru import logger as LOG


def print_key(key, is_removed=False):
    if key == bytearray(8):
        key = "0"
    else:
        key = f"{key.decode()}"
    logger = LOG.error if is_removed else LOG.info
    logger(f"{key}:")


if __name__ == "__main__":

    config = {"handlers": [{"sink": sys.stdout, "format": "<level>{message}</level>"}]}
    LOG.configure(**config)

    if len(sys.argv) < 2:
        LOG.error("First argument should be CCF ledger directory")
        sys.exit(1)

    ledger = ccf.ledger.Ledger(sys.argv[1])

    for chunk in ledger:
        for transaction in chunk:
            public_transaction = transaction.get_public_domain()
            public_tables = public_transaction.get_tables()

            LOG.success(
                f"seqno {public_transaction.get_seqno()} ({len(public_tables)} table{'s' if len(public_tables) > 1 else ''})"
            )

            for table_name, records in public_tables.items():
                LOG.warning(f"table: {table_name}")
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
