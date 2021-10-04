# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import ccf.ledger
import argparse
import os
from stringcolor import cs  # type: ignore


class Liner:
    _line = ""
    _len = 0
    MAX_LENGTH = os.get_terminal_size().columns

    def flush(self):
        print(self._line)
        self._line = ""
        self._len = 0

    def append(self, c: str, colour: str, background_colour: str):
        self._line += cs(c, colour, background_colour)
        self._len += 1
        if self._len >= self.MAX_LENGTH:
            self.flush()


class DefaultLiner(Liner):
    _mapping = {
        "Signature": (" ", "White", "Green"),
        "Governance": (" ", "White", "Red"),
        "Internal": (" ", "White", "Orange"),
        "User Public": (" ", "White", "Blue"),
        "User Private": (" ", "White", "DarkBlue"),
    }

    def entry(self, category):
        self.append(*self._mapping[category])

    def help(self):
        print(
            " ".join(
                [
                    f"{category}: {cs(*values)}"
                    for category, values in self._mapping.items()
                ]
            )
        )
        print()


def main():
    parser = argparse.ArgumentParser(description="Read CCF ledger or snapshot")
    parser.add_argument(
        "paths", help="Path to ledger directories or snapshot file", nargs="+"
    )
    parser.add_argument(
        "--uncommitted", help="Also parse uncommitted ledger files", action="store_true"
    )
    args = parser.parse_args()

    ledger_dirs = args.paths
    ledger = ccf.ledger.Ledger(ledger_dirs, committed_only=not args.uncommitted)

    l = DefaultLiner()
    l.help()
    for chunk in ledger:
        for tx in chunk:
            public = tx.get_public_domain().get_tables()
            has_private = tx.get_private_domain_size()
            if not has_private:
                if "public:ccf.internal.signatures" in public:
                    l.entry("Signature")
                else:
                    if all(table.startswith("public:ccf.gov.") for table in public):
                        l.entry("Governance")
                    elif all(table.startswith("public:ccf.") for table in public):
                        l.entry("Internal")
                    else:
                        l.entry("User Public")
            else:
                l.entry("User Private")

    l.flush()


if __name__ == "__main__":
    main()
