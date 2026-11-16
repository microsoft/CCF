# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import re
from dataclasses import dataclass

_TXID = re.compile(r"(?P<view>\d+)\.(?P<seqno>\d+)", re.ASCII)


@dataclass(order=True)
class TxID:
    view: int | None
    seqno: int | None

    def __str__(self):
        return f"{self.view}.{self.seqno}"

    def valid(self):
        return self.view is not None and self.seqno != 0

    @staticmethod
    def from_str(s: str) -> "TxID":
        """Parse a transaction ID, retaining None fields for invalid input."""
        return TxID(*TxID.parse(s))

    @staticmethod
    def parse(s: str | None) -> tuple[int, int] | tuple[None, None]:
        """Return the view and sequence number, or (None, None) for invalid input.

        Valid input is two ASCII decimal integers separated by a single dot.
        """
        match = _TXID.fullmatch(s) if isinstance(s, str) else None
        if match is not None:
            try:
                return int(match["view"]), int(match["seqno"])
            except ValueError:
                # Exceeds the interpreter's integer string conversion limit
                pass
        return None, None
