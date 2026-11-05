# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass


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
        """Return the view and sequence number, or (None, None) for invalid input."""
        try:
            if s is not None:
                view_s, seqno_s = s.split(".")
                return int(view_s), int(seqno_s)
        except (AttributeError, ValueError):
            pass
        return None, None
