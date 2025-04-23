# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import sys
import json
import re
import argparse
from datetime import datetime
from enum import Enum, auto

from loguru import logger as LOG


class PrintMode(Enum):
    Quiet = auto()
    Digests = auto()
    Contents = auto()


def indent(n):
    return " " * n


def fmt_uint_le(data):
    return (
        f'<u{8 * len(data)}: {int.from_bytes(data, byteorder="little", signed=False)}>'
    )


def fmt_raw(data):
    return str(data)


def fmt_hex(data):
    return data.hex()


def fmt_str(data):
    return data.decode()


def fmt_json(data):
    return json.dumps(json.loads(data), indent=2)


def fmt_cose_recent_timestamp(data):
    s = data.decode()
    ts, _ = s.split(":")
    dt = datetime.fromtimestamp(int(ts))
    return f"[{dt.isoformat()}] {s}"


# List of table name regex to key and value format functions (first match is used)
# Callers can specify additional rules (e.g. for application-specific
# public tables) which get looked up first.
default_format_rule = {"key": fmt_raw, "value": fmt_raw}
default_tables_format_rules = [
    (
        "^public:ccf\\.gov\\.cose_recent_proposals$",
        {
            "key": fmt_cose_recent_timestamp,
            "value": fmt_json,
        },
    ),
    (
        "^public:ccf\\.internal\\..*$",
        {
            "key": fmt_uint_le,
            "value": fmt_json,
        },
    ),
    (
        "^public:ccf\\.gov\\..*(service|network|constitution).*$",
        {
            "key": fmt_uint_le,
            "value": fmt_json,
        },
    ),
    ("^public:ccf\\.gov\\..*$", {"key": fmt_str, "value": fmt_json}),
    (".*", {"key": fmt_raw, "value": fmt_raw}),
]


def find_rule(tables_format_rules, target_table_name):
    for table_name_re, format_rules in tables_format_rules:
        if table_name_re.match(target_table_name):
            return format_rules
    return default_format_rule


def print_key(key, table_name, tables_format_rules, indent_s, is_removed=False):
    k = find_rule(tables_format_rules, table_name)["key"](key)

    if is_removed:
        LOG.error(f"{indent_s}Removed {k}")
    else:
        LOG.info(f"{indent_s}{k}:")


def counted_string(string, name):
    return f"{len(string)} {name}{'s' * bool(len(string) != 1)}"


def dump_entry(entry, table_filter, tables_format_rules):
    public_transaction = entry.get_public_domain()
    public_tables = public_transaction.get_tables()
    flags = entry.get_transaction_header().flags
    flags_msg = "" if flags == 0 else f", flags={hex(flags)}"
    tx_header = f"{indent(2)}txid {entry.get_txid()} ({counted_string(public_tables, 'public table')}) [{entry.get_len()} bytes{flags_msg}]"
    printed_tx_header = False

    private_table_size = entry.get_private_domain_size()
    if private_table_size and table_filter is None:
        if not printed_tx_header:
            LOG.success(tx_header)
            printed_tx_header = True

        LOG.error(f"{indent(2)}-- private: {private_table_size} bytes")

    for table_name, records in public_tables.items():
        if table_filter is not None and not table_filter.match(table_name):
            continue

        if not printed_tx_header:
            LOG.success(tx_header)
            printed_tx_header = True

        LOG.warning(
            f'{indent(4)}table "{table_name}" ({counted_string(records, "write")}):'
        )
        key_indent = indent(6)
        value_indent = indent(8)
        for key, value in records.items():
            if value is not None:
                try:
                    value = find_rule(tables_format_rules, table_name)["value"](value)
                    value = value.replace(
                        "\n", f"\n{value_indent}"
                    )  # Indent every line within stringified JSON
                except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                    pass
                finally:
                    print_key(key, table_name, tables_format_rules, key_indent)
                    LOG.info(f"{value_indent}{value}")
            else:
                print_key(
                    key, table_name, tables_format_rules, key_indent, is_removed=True
                )


def run(
    paths,
    print_mode: PrintMode,
    is_snapshot=False,
    tables_regex=None,
    insecure_skip_verification=False,
    uncommitted=False,
    read_recovery_files=False,
    tables_format_rules=None,
):
    table_filter = re.compile(tables_regex) if tables_regex is not None else None

    # Extend and compile rules
    tables_format_rules = tables_format_rules or []
    tables_format_rules.extend(default_tables_format_rules)
    tables_format_rules = [
        (re.compile(table_name_re), _) for (table_name_re, _) in tables_format_rules
    ]

    if is_snapshot:
        snapshot_file = paths[0]
        with ccf.ledger.Snapshot(snapshot_file) as snapshot:
            LOG.info(
                f"Reading snapshot from {snapshot_file} ({'' if snapshot.is_committed() else 'un'}committed)"
            )
            dump_entry(snapshot, table_filter, tables_format_rules)
        return True
    else:
        validator = (
            ccf.ledger.LedgerValidator() if not insecure_skip_verification else None
        )
        ledger_paths = paths
        ledger = ccf.ledger.Ledger(
            ledger_paths,
            committed_only=not uncommitted,
            read_recovery_files=read_recovery_files,
        )

        LOG.info(f"Reading ledger from {ledger_paths}")
        LOG.info(f"Contains {counted_string(ledger, 'chunk')}")

        try:
            for chunk in ledger:
                LOG.info(
                    f"chunk {chunk.filename()} ({'' if chunk.is_committed() else 'un'}committed)"
                )
                for transaction in chunk:
                    if print_mode == PrintMode.Quiet:
                        pass
                    elif print_mode == PrintMode.Digests:
                        print(
                            f"{transaction.gcm_header.view}.{transaction.gcm_header.seqno} {transaction.get_write_set_digest().hex()}"
                        )
                    elif print_mode == PrintMode.Contents:
                        dump_entry(transaction, table_filter, tables_format_rules)

                    if validator:
                        validator.add_transaction(transaction)
        except Exception as e:
            LOG.exception(f"Error parsing ledger: {e}")
            has_error = True
        else:
            LOG.success("Ledger verification complete")
            has_error = False
        finally:
            if not validator:
                LOG.warning("Skipped ledger integrity verification")
            else:
                LOG.info(
                    f"Found {validator.signature_count} signatures, and verified until {validator.last_verified_txid()}"
                )
        return not has_error


def main():
    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    parser = argparse.ArgumentParser(
        description="Read CCF ledger or snapshot",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "paths",
        help="Path to ledger directories, ledger chunks, or snapshot file. "
        "Note that parsing individual ledger chunks requires the additional --insecure-skip-verification option",
        nargs="+",
    )
    parser.add_argument(
        "-s",
        "--snapshot",
        help="Indicates that the path to read is a snapshot",
        action="store_true",
    )
    parser.add_argument(
        "--uncommitted",
        help="Also parse uncommitted ledger files. Note that if these are in a live node directory, they may be being modified.",
        action="store_true",
    )
    parser.add_argument(
        "--recovery",
        help="Also parse .recovery ledger files. Note that if these are in a live node directory, they may be being modified.",
        action="store_true",
    )

    display_options = parser.add_mutually_exclusive_group()
    display_options.add_argument(
        "-q",
        "--quiet",
        help="Don't print transaction digests or contents",
        action="store_true",
    )
    display_options.add_argument(
        "-d",
        "--digests-only",
        help="Only print transaction digests",
        action="store_true",
    )
    display_options.add_argument(
        "-t",
        "--tables",
        help="Regex filter for tables to display",
        type=str,
        default=None,
    )

    parser.add_argument(
        "--insecure-skip-verification",
        help="INSECURE: skip ledger Merkle tree integrity verification",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    print_mode = PrintMode.Contents
    if args.quiet:
        print_mode = PrintMode.Quiet
    elif args.digests_only:
        print_mode = PrintMode.Digests

    if not run(
        args.paths,
        print_mode,
        is_snapshot=args.snapshot,
        tables_regex=args.tables,
        insecure_skip_verification=args.insecure_skip_verification,
        uncommitted=args.uncommitted,
        read_recovery_files=args.recovery,
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
