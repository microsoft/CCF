# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import argparse
import json
from collections import defaultdict


def code_identity(info):
    return (info["quote_info"]["format"], info["code_digest"])


def main():
    parser = argparse.ArgumentParser(
        description="List code versions present in a CCF ledger",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "paths",
        help="Path to ledger directories or ledger chunks. "
        "Note that parsing individual ledger chunks requires the additional --insecure-skip-verification option",
        nargs="+",
    )
    parser.add_argument(
        "--uncommitted", help="Also parse uncommitted ledger files", action="store_true"
    )
    parser.add_argument(
        "--insecure-skip-verification",
        help="INSECURE: skip ledger Merkle tree integrity verification",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-s",
        help="Display short versions of digests",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-v",
        help="Display all node additions and removals",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    ledger_paths = args.paths
    ledger = ccf.ledger.Ledger(
        ledger_paths,
        committed_only=not args.uncommitted,
        validator=ccf.ledger.LedgerValidator()
        if not args.insecure_skip_verification
        else None,
    )

    def fmt_digest(d):
        return d[:6] if args.s else d

    def fmt_code_identity(ci):
        fmt, cd = ci
        return (fmt, cd[:6] if args.s else cd)

    code_to_nodes = defaultdict(set)

    def print_state(view, seqno):
        if args.v:
            state = {
                fmt_code_identity(version): [
                    fmt_digest(node.decode()) for node in nodes
                ]
                for version, nodes in code_to_nodes.items()
                if nodes
            }
            print(f"{view}.{seqno}: {state}")

    def code_ids_with_trusted_nodes():
        return {code_id for code_id, nodes in code_to_nodes.items() if nodes}

    for chunk in ledger:
        for tx in chunk:
            public = tx.get_public_domain().get_tables()

            view = tx.gcm_header.view
            seqno = tx.gcm_header.seqno
            pre_code_ids = code_ids_with_trusted_nodes()

            if ccf.ledger.NODES_TABLE_NAME in public:
                nodes_info = public[ccf.ledger.NODES_TABLE_NAME]
                for key, value in nodes_info.items():
                    if value:
                        info = json.loads(value)
                        code_id = code_identity(info)
                        if info["status"] == "Trusted":
                            code_to_nodes[code_id].add(key)
                            print_state(view, seqno)
                        elif info["status"] == "Retired":
                            if key in code_to_nodes[code_id]:
                                code_to_nodes[code_id].remove(key)
                            print_state(view, seqno)

            post_code_ids = code_ids_with_trusted_nodes()

            introduced = post_code_ids - pre_code_ids
            if introduced and not args.v:
                print(
                    f"{view}.{seqno} Introduced : {[fmt_code_identity(nv) for nv in introduced]}"
                )

            removed = pre_code_ids - post_code_ids
            if removed and not args.v:
                print(
                    f"{view}.{seqno} Removed : {[fmt_code_identity(nv) for nv in removed]}"
                )


if __name__ == "__main__":
    main()
