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


def fmt_uint_le(data):
    return (
        f'<u{8 * len(data)}: {int.from_bytes(data, byteorder="little", signed=False)}>'
    )


def fmt_hex(data):
    return data.hex()


def fmt_str(data):
    return data.decode()


def fmt_json(data):
    return json.dumps(json.loads(data), indent=2)


# List of table name regex to key and value format functions (first match is used)
# Callers can specify additional rules (e.g. for application-specific
# public tables) which get looked up first.
default_format_rule = {"key": fmt_hex, "value": fmt_hex}
default_tables_format_rules = [
    (
        "^public:ccf\\.internal\\..*$",
        {
            "key": fmt_uint_le,
            "value": fmt_json,
        },
    ),
    (
        "^public:ccf\\.gov\\.(service|network|constitution).*$",
        {
            "key": fmt_uint_le,
            "value": fmt_json,
        },
    ),
    ("^public:ccf\\.gov\\..*$", {"key": fmt_str, "value": fmt_json}),
    (".*", {"key": fmt_hex, "value": fmt_hex}),
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


def counted_string(l, name):
    return f"{len(l)} {name}{'s' * bool(len(l) != 1)}"


def dump_entry(entry, table_filter, tables_format_rules):
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


def run(args_, tables_format_rules=None):
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
    args = parser.parse_args(args_)

    table_filter = re.compile(args.tables)

    # Extend and compile rules
    tables_format_rules = tables_format_rules or []
    tables_format_rules.extend(default_tables_format_rules)
    tables_format_rules = [
        (re.compile(table_name_re), _) for (table_name_re, _) in tables_format_rules
    ]

    if args.snapshot:
        snapshot_file = args.paths[0]
        with ccf.ledger.Snapshot(snapshot_file) as snapshot:
            LOG.info(
                f"Reading snapshot from {snapshot_file} ({'' if snapshot.commit_seqno() else 'un'}committed)"
            )
            dump_entry(snapshot, table_filter, tables_format_rules)
    else:
        ledger_dirs = args.paths
        ledger = ccf.ledger.Ledger(ledger_dirs, committed_only=not args.uncommitted)

        LOG.info(f"Reading ledger from {ledger_dirs}")
        LOG.info(f"Contains {counted_string(ledger, 'chunk')}")

        try:
            for chunk in ledger:
                LOG.info(
                    f"chunk {chunk.filename()} ({'' if chunk.is_committed() else 'un'}committed)"
                )
                for transaction in chunk:
                    dump_entry(transaction, table_filter, tables_format_rules)
        except Exception as e:
            LOG.exception(f"Error parsing ledger: {e}")
            has_error = True
        else:
            LOG.success("Ledger verification complete")
            has_error = False
        finally:
            LOG.info(
                f"Found {ledger.signature_count()} signatures, and verified until {ledger.last_verified_txid()}"
            )
        return not has_error


if __name__ == "__main__":

    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    if not run(sys.argv[1:]):
        sys.exit(1)
