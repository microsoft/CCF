# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import json
import dataclasses
from typing import Optional, Union

from loguru import logger as LOG

BENCHER_FILE = "bencher.json"

# See https://bencher.dev/docs/reference/bencher-metric-format/


@dataclasses.dataclass
class Value:
    value: float
    high_value: Optional[float] = None
    low_value: Optional[float] = None


@dataclasses.dataclass
class Latency:
    latency: Value

    def __init__(
        self,
        value: float,
        high_value: Optional[float] = None,
        low_value: Optional[float] = None,
    ):
        self.latency = Value(value, high_value, low_value)


@dataclasses.dataclass
class Throughput:
    throughput: Value

    def __init__(
        self,
        value: float,
        high_value: Optional[float] = None,
        low_value: Optional[float] = None,
    ):
        self.throughput = Value(value, high_value, low_value)


@dataclasses.dataclass
class Memory:
    memory: Value

    def __init__(
        self,
        value: float,
        high_value: Optional[float] = None,
        low_value: Optional[float] = None,
    ):
        self.memory = Value(value, high_value, low_value)


@dataclasses.dataclass
class Rate:
    rate: Value

    def __init__(
        self,
        value: float,
        high_value: Optional[float] = None,
        low_value: Optional[float] = None,
    ):
        self.rate = Value(value, high_value, low_value)


class Bencher:
    def __init__(self):
        if not os.path.isfile(BENCHER_FILE):
            with open(BENCHER_FILE, "w+") as bf:
                json.dump({}, bf)

    def set_memory(self, key: str, proc_stats: dict):
        LOG.info(
            f"Memory: RSS={proc_stats['current_rss']}, "
            f"Peak RSS={proc_stats['peak_rss']}, "
            f"Virtual={proc_stats['virtual_size']}"
        )
        self.set(
            key,
            Memory(proc_stats["current_rss"], high_value=proc_stats["peak_rss"]),
        )

    def set(self, key: str, metric: Union[Latency, Throughput, Memory]):
        with open(BENCHER_FILE, "r") as bf:
            data = json.load(bf)
        metric_val = dataclasses.asdict(metric)
        if key in data:
            data[key].update(metric_val)
        else:
            data[key] = metric_val
        with open(BENCHER_FILE, "w") as bf:
            json.dump(data, bf, indent=4)
