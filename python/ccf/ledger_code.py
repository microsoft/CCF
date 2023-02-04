# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import argparse
import os
from stringcolor import cs  # type: ignore
import json
from typing import Optional
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(
        description="List code versions present in the CCF ledger",
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
    args = parser.parse_args()

    ledger_paths = args.paths
    ledger = ccf.ledger.Ledger(
        ledger_paths,
        committed_only=not args.uncommitted,
        validator=ccf.ledger.LedgerValidator()
        if not args.insecure_skip_verification
        else None,
    )

    code_to_nodes = defaultdict(set)

    for chunk in ledger:
        for tx in chunk:
            public = tx.get_public_domain().get_tables()
            has_private = tx.get_private_domain_size()

            view = tx.gcm_header.view
            seqno = tx.gcm_header.seqno
            know_code_versions = set(code_to_nodes.keys())

            if ccf.ledger.NODES_TABLE_NAME in public:
                nodes_info = public[ccf.ledger.NODES_TABLE_NAME]
                for key, value in nodes_info.items():
                    info = json.loads(value)
                    if info["status"] == "Trusted":
                        code_to_nodes[info['code_digest']].add(key)
                        state = {version[:6]: [node[:6].decode() for node in nodes] for version, nodes in code_to_nodes.items() if nodes}
                        print(f"{view}.{seqno}: {state}")
                    elif info["status"] == "Retired":
                        if key in code_to_nodes[info['code_digest']]:
                            code_to_nodes[info['code_digest']].remove(key)
            new_versions = set(code_to_nodes.keys()) - know_code_versions
            if new_versions:
                print(f"New code versions: {new_versions}")


if __name__ == "__main__":
    main()
