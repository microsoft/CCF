# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import sys
import json
import re
import argparse

from loguru import logger as LOG


def indent(n):
    return " " * n


def stringify_bytes(bs):
    s = bs.decode()
    if s.isprintable():
        return s
    if len(bs) > 0 and len(bs) <= 8:
        n = int.from_bytes(bs, byteorder="little")
        return f"<u{8 * len(bs)}: {n}>"
    return bs


def print_key(indent_s, k, is_removed=False):
    k = stringify_bytes(k)

    if is_removed:
        LOG.error(f"{indent_s}Removed {k}")
    else:
        LOG.info(f"{indent_s}{k}:")


def counted_string(l, name):
    return f"{len(l)} {name}{'s' * bool(len(l) != 1)}"


def dump_entry(entry, table_filter):
    public_transaction = entry.get_public_domain()
    public_tables = public_transaction.get_tables()
    LOG.success(
        f"{indent(2)}seqno {public_transaction.get_seqno()} ({counted_string(public_tables, 'public table')})"
    )

    private_table_size = entry.get_private_domain_size()
    if private_table_size:
        LOG.error(f"{indent(2)}-- private: {private_table_size} bytes")

    for table_name, records in public_tables.items():
        if not table_filter.match(table_name):
            continue

        LOG.warning(
            f'{indent(4)}table "{table_name}" ({counted_string(records, "write")}):'
        )
        key_indent = indent(6)
        value_indent = indent(8)
        for key, value in records.items():
            if value is not None:
                try:
                    value = json.dumps(json.loads(value), indent=2)
                    value = value.replace(
                        "\n", f"\n{value_indent}"
                    )  # Indent every line within stringified JSON
                except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                    pass
                finally:
                    print_key(key_indent, key)
                    LOG.info(f"{value_indent}{value}")
            else:
                print_key(key_indent, key, is_removed=True)


if __name__ == "__main__":

    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    parser = argparse.ArgumentParser(description="Read CCF ledger or snapshot")
    parser.add_argument(
        "paths", help="Path to ledger directories or snapshot file", nargs="+"
    )
    parser.add_argument(
        "-s",
        "--snapshot",
        help="Indicates that the path to read is a snapshot",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--tables",
        help="Regex filter for tables to display",
        type=str,
        default=".*",
    )
    parser.add_argument(
        "--uncommitted", help="Also parse uncommitted ledger files", action="store_true"
    )
    args = parser.parse_args()
    table_filter = re.compile(args.tables)

    if args.snapshot:
        snapshot_file = args.paths[0]
        with ccf.ledger.Snapshot(snapshot_file) as snapshot:
            LOG.info(
                f"Reading snapshot from {snapshot_file} ({'' if snapshot.commit_seqno() else 'un'}committed)"
            )
            dump_entry(snapshot, table_filter)
    else:
        ledger_dirs = args.paths
        ledger = ccf.ledger.Ledger(ledger_dirs, committed_only=not args.uncommitted)

        LOG.info(f"Reading ledger from {ledger_dirs}")
        LOG.info(f"Contains {counted_string(ledger, 'chunk')}")

        for chunk in ledger:
            LOG.info(
                f"chunk {chunk.filename()} ({'' if chunk.is_committed() else 'un'}committed)"
            )
            for transaction in chunk:
                dump_entry(transaction, table_filter)

        LOG.success(
            f"Ledger verification complete. Found {ledger.signature_count()} signatures, and verified until {ledger.last_verified_txid()}"
        )
