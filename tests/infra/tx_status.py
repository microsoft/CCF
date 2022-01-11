# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum


class TxStatus(Enum):
    Unknown = "Unknown"
    Pending = "Pending"
    Committed = "Committed"
    Invalid = "Invalid"
