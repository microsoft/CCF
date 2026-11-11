# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Tests for transaction ID parsing and its invalid-input sentinel."""

import pytest
from ccf.tx_id import TxID


@pytest.mark.parametrize(
    "value",
    [
        "",
        "invalid",
        "1",
        "1.2.3",
        "view.2",
        "1.seqno",
        "-1.2",
        "1.-2",
        "+1.2",
        " 1.2",
        "1.2 ",
        "1_0.2",
        "\u0661.\u0662",
        ".2",
        "1.",
        "1." + "9" * 4301,
    ],
)
def test_invalid_transaction_id(value: str):
    assert TxID.parse(value) == (None, None)
    txid = TxID.from_str(value)
    assert txid == TxID(None, None)
    assert not txid.valid()


def test_missing_transaction_id():
    assert TxID.parse(None) == (None, None)


def test_valid_transaction_id():
    assert TxID.parse("2.42") == (2, 42)
    txid = TxID.from_str("2.42")
    assert txid == TxID(2, 42)
    assert txid.valid()
    assert str(txid) == "2.42"


def test_zero_sequence_number():
    assert not TxID.from_str("2.0").valid()
