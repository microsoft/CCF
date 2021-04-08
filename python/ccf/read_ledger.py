# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import sys
import json

from loguru import logger as LOG


def indent(n):
    return " " * n


def stringify_bytes(bs):
    s = bs.decode()
    if s.isprintable():
        return s
    if len(bs) > 0 and len(bs) <= 8:
        n = int.from_bytes(bs, "big")
        return f"<u{8 * len(bs)}: {n}>"
    return bs


def print_key(indent_s, k, is_removed=False):
    k = stringify_bytes(k)

    if is_removed:
        LOG.error(f"{indent_s}Removed {k}")
    else:
        LOG.info(f"{indent_s}{k}:")


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
                f"seqno {public_transaction.get_seqno()} ({len(public_tables)} table{'s' * bool(len(public_tables))})"
            )

            for table_name, records in public_tables.items():
                LOG.warning(
                    f'{indent(2)}table "{table_name}" ({len(records)} write{"s" * bool(len(records))}):'
                )
                key_indent = indent(4)
                for key, value in records.items():
                    if value is not None:
                        try:
                            value = json.dumps(json.loads(value), indent=2)
                            value = value.replace(
                                "\n", f"\n{indent(6)}"
                            )  # Indent every line within stringified JSON
                        except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                            pass
                        finally:
                            print_key(key_indent, key)
                            LOG.info(f"{indent(6)}{value}")
                    else:
                        print_key(key_indent, key, is_removed=True)
