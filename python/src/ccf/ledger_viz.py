# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import shutil
from collections.abc import Iterable
from typing import Any, ClassVar, Protocol

import ccf.ledger
import ccf.signatures

COLORS = {
    "Black": 40,
    "Red": 41,
    "Green": 42,
    "Yellow": 43,
    "Blue": 44,
    "Magenta": 45,
    "Cyan": 46,
    "White": 47,
    "Grey": 100,
}


def cs(s: str, background_colour: str | None = None) -> str:
    """Wrap a string in an optional ANSI background colour."""
    if background_colour is not None and background_colour in COLORS:
        return f"\033[{COLORS[background_colour]}m{s}\033[0m"
    return s


class Liner:
    _line = ""
    _len = 0
    MAX_LENGTH = shutil.get_terminal_size().columns

    def flush(self):
        print(self._line)
        self._line = ""
        self._len = 0

    def append(self, s: str, background_colour: str | None = None):
        self._line += cs(s, background_colour)
        self._len += len(s)
        if self._len >= self.MAX_LENGTH:
            self.flush()


class DefaultLiner(Liner):
    _bg_colour_mapping: ClassVar[dict[str, str]] = {
        "New Service": "Black",
        "Recovering Service": "Red",
        "Service Open": "White",
        "Governance": "Yellow",
        "Signature": "Green",
        "Internal": "Magenta",
        "User Public": "Blue",
        "User Private": "Cyan",
    }
    _last_view: int | None = None

    @staticmethod
    def view_to_char(view: int) -> str:
        """Return the last decimal digit of a view."""
        return str(view)[-1]

    def __init__(
        self, write_views: bool, split_views: bool, split_services: bool
    ) -> None:
        self.write_views = write_views
        self.split_views = split_views
        self.split_services = split_services

    def entry(self, category: str, view: int, seqno: int) -> None:
        """Append a transaction tile, splitting lines at configured boundaries."""
        view_change = view != self._last_view
        self._last_view = view

        if view_change and self.split_views:
            self.flush()
            self.append(f"{view}: ", "White")

        if self.split_services:
            if category == "New Service":
                self.flush()
                self.append(f"{view}.{seqno}: ", "White")
            elif category == "Recovering Service":
                self.flush()
                self.append(f"{view}.{seqno}: ", "Grey")

        char = " "
        if self.write_views:
            char = "‾" if not view_change else self.view_to_char(view)

        bg_colour = self._bg_colour_mapping[category]
        self.append(char, bg_colour)

    def help(self):
        print(
            " | ".join(
                [
                    f"{category} {cs(' ', bg_colour)}"
                    for category, bg_colour in self._bg_colour_mapping.items()
                ]
            )
        )
        if self.write_views:
            print(" ".join([f"Start of view 3: {cs(self.view_to_char(3), 'Grey')}"]))
        print()


def try_get_service_info(
    public_tables: dict[str, dict[bytes, bytes | None]],
) -> dict[str, Any] | None:
    """Decode service info if its table is present."""
    if ccf.ledger.SERVICE_INFO_TABLE_NAME not in public_tables:
        return None
    service_info = public_tables[ccf.ledger.SERVICE_INFO_TABLE_NAME][
        ccf.signatures.WELL_KNOWN_SINGLETON_TABLE_KEY
    ]
    if service_info is None:
        raise TypeError("Service info must contain a non-null singleton value")
    return json.loads(service_info)


class EntryLiner(Protocol):
    """Output sink for categorised ledger transactions."""

    def entry(self, category: str, view: int, seqno: int) -> None: ...

    def flush(self) -> None: ...


def visualise(
    ledger: Iterable[Iterable[ccf.ledger.Transaction]],
    liner: EntryLiner,
    validator: ccf.ledger.LedgerValidator | None = None,
) -> None:
    """Iterate over the given ledger and dispatch each transaction to
    ``liner.entry(category, view, seqno)`` after categorising it. If a
    ``validator`` is provided, every transaction is also fed to it via
    ``validator.add_transaction(tx)``. Calls ``liner.flush()`` at the end.
    """
    current_service_identity = None

    for chunk in ledger:
        for tx in chunk:
            if validator:
                validator.add_transaction(tx)

            public = tx.get_public_domain().get_tables()
            has_private = tx.get_private_domain_size()

            assert tx.gcm_header is not None
            view = tx.gcm_header.view
            seqno = tx.gcm_header.seqno
            if not has_private:
                if ccf.signatures.is_signature_transaction(public):
                    liner.entry("Signature", view, seqno)
                else:
                    if all(
                        table.startswith("public:ccf.internal.") for table in public
                    ):
                        liner.entry("Internal", view, seqno)
                    elif any(table.startswith("public:ccf.gov.") for table in public):
                        service_info = try_get_service_info(public)
                        if service_info is None:
                            liner.entry("Governance", view, seqno)
                        elif service_info["status"] == "Opening":
                            liner.entry("New Service", view, seqno)
                            current_service_identity = service_info["cert"]
                        elif service_info["status"] == "Recovering":
                            liner.entry("Recovering Service", view, seqno)
                            current_service_identity = service_info["cert"]
                        elif (
                            service_info["cert"] == current_service_identity
                            and service_info["status"] == "Open"
                        ):
                            liner.entry("Service Open", view, seqno)
                    else:
                        liner.entry("User Public", view, seqno)
            else:
                liner.entry("User Private", view, seqno)

    liner.flush()


def main():
    parser = argparse.ArgumentParser(
        description="Visualise content of CCF ledger",
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
        "--write-views",
        help="Include characters on each tile indicating their view",
        action="store_true",
    )
    parser.add_argument(
        "--split-views",
        help="Write each view on a new line, prefixed by the view number",
        action="store_true",
    )
    parser.add_argument(
        "--insecure-skip-verification",
        help="INSECURE: skip ledger Merkle tree integrity verification",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--split-services",
        help="Write each new service on a new line, prefixed by the TxID",
        action="store_true",
    )
    args = parser.parse_args()

    ledger_paths = args.paths
    ledger = ccf.ledger.Ledger(
        ledger_paths,
        committed_only=not args.uncommitted,
    )

    liner = DefaultLiner(args.write_views, args.split_views, args.split_services)
    liner.help()

    validator = (
        ccf.ledger.LedgerValidator() if not args.insecure_skip_verification else None
    )

    visualise(ledger, liner, validator=validator)


if __name__ == "__main__":
    main()
