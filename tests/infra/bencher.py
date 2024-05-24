# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import json
import dataclasses
from typing import Optional, Union

BENCHER_FILE = "bencher.json"


@dataclasses.dataclass
class Value:
    value: float
    high_value: Optional[float] = None
    low_value: Optional[float] = None


@dataclasses.dataclass
class LatencyValue:
    latency: Value

    def __init__(
        self,
        value: float,
        high_value: Optional[float] = None,
        low_value: Optional[float] = None,
    ):
        self.latency = Value(value, high_value, low_value)


@dataclasses.dataclass
class ThroughputValue:
    throughput: Value

    def __init__(
        self,
        value: float,
        high_value: Optional[float] = None,
        low_value: Optional[float] = None,
    ):
        self.throughput = Value(value, high_value, low_value)


class Bencher:
    def __init__(self):
        if not os.path.isfile(BENCHER_FILE):
            with open(BENCHER_FILE, "w+") as bf:
                json.dump({}, bf)

    def set(self, key: str, value: Union[LatencyValue, ThroughputValue]):
        with open(BENCHER_FILE, "r") as bf:
            data = json.load(bf)
        data[key] = dataclasses.asdict(value)
        with open(BENCHER_FILE, "w") as bf:
            json.dump(data, bf, indent=4)
