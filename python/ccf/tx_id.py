# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from dataclasses import dataclass
from typing import Optional


@dataclass
class TxID:
    view: int
    seqno: int

    def __str__(self):
        return f"{self.view}.{self.seqno}"

    def valid(self):
        return self.view is not None and self.seqno != 0

    @staticmethod
    def from_str(s: str):
        return TxID(*TxID.parse(s))

    @staticmethod
    def parse(s: Optional[str]):
        try:
            if s is not None:
                view_s, seqno_s = s.split(".")
                return int(view_s), int(seqno_s)
        except (AttributeError, ValueError):
            pass
        return None, None
