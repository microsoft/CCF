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

    def append(self, s: str, colour: str, background_colour: str = None):
        self._line += cs(s, colour, background_colour)
        self._len += len(s)
        if self._len >= self.MAX_LENGTH:
            self.flush()


class DefaultLiner(Liner):
    _bg_colour_mapping = {
        "Signature": "Green",
        "Governance": "Red",
        "Internal": "Orange",
        "User Public": "Blue",
        "User Private": "DarkBlue",
    }
    _last_view = None
    _fg_colour = "Black"

    @staticmethod
    def view_to_char(view):
        return str(view)[-1]

    def __init__(self, write_views, split_views):
        self.write_views = write_views
        self.split_views = split_views

    def entry(self, category, view):
        view_change = view != self._last_view
        self._last_view = view

        if view_change and self.split_views:
            self.flush()
            self.append(f"{view}: ", "White")

        char = " "
        if self.write_views:
            char = "‾" if not view_change else self.view_to_char(view)

        fg_colour = self._fg_colour
        bg_colour = self._bg_colour_mapping[category]
        self.append(char, fg_colour, bg_colour)

    def help(self):
        print(
            " ".join(
                [
                    f"{category}: {cs(' ', 'White', bg_colour)}"
                    for category, bg_colour in self._bg_colour_mapping.items()
                ]
            )
        )
        if self.write_views:
            print(
                " ".join(
                    [
                        f"Start of view 14: {cs(self.view_to_char(14), self._fg_colour, 'Grey')}"
                    ]
                )
            )
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Visualise content of CCF ledger",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("paths", help="Path to ledger directories", nargs="+")
    parser.add_argument(
        "--uncommitted", help="Also parse uncommitted ledger files", action="store_true"
    )
    parser.add_argument(
        "--write-views",
        help="Include characters on each tile indicating their view",
        action="store_true",
    )
    parser.add_argument(
        "--split-views",
        help="Write each view on a new line, prefixed by the view number",
        action="store_true",
    )
    args = parser.parse_args()

    ledger_dirs = args.paths
    ledger = ccf.ledger.Ledger(ledger_dirs, committed_only=not args.uncommitted)

    l = DefaultLiner(args.write_views, args.split_views)
    l.help()
    for chunk in ledger:
        for tx in chunk:
            public = tx.get_public_domain().get_tables()
            has_private = tx.get_private_domain_size()

            view = tx.gcm_header.view
            if not has_private:
                if ccf.ledger.SIGNATURE_TX_TABLE_NAME in public:
                    l.entry("Signature", view)
                else:
                    if all(table.startswith("public:ccf.gov.") for table in public):
                        l.entry("Governance", view)
                    elif all(table.startswith("public:ccf.") for table in public):
                        l.entry("Internal", view)
                    else:
                        l.entry("User Public", view)
            else:
                l.entry("User Private", view)

    l.flush()


if __name__ == "__main__":
    main()
