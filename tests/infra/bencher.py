# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import dataclasses
import json
import os
import subprocess

from loguru import logger as LOG

BENCHER_FILE = "bencher.json"
METADATA_KEY = "__metadata"

# See https://bencher.dev/docs/reference/bencher-metric-format/


@dataclasses.dataclass
class Value:
    value: float
    high_value: float | None = None
    low_value: float | None = None


@dataclasses.dataclass
class Latency:
    latency: Value

    def __init__(
        self,
        value: float,
        high_value: float | None = None,
        low_value: float | None = None,
    ):
        self.latency = Value(value, high_value, low_value)


@dataclasses.dataclass
class Throughput:
    throughput: Value

    def __init__(
        self,
        value: float,
        high_value: float | None = None,
        low_value: float | None = None,
    ):
        self.throughput = Value(value, high_value, low_value)


@dataclasses.dataclass
class Memory:
    memory: Value

    def __init__(
        self,
        value: float,
        high_value: float | None = None,
        low_value: float | None = None,
    ):
        self.memory = Value(value, high_value, low_value)


@dataclasses.dataclass
class Rate:
    rate: Value

    def __init__(
        self,
        value: float,
        high_value: float | None = None,
        low_value: float | None = None,
    ):
        self.rate = Value(value, high_value, low_value)


def get_commit() -> str | None:
    commit = os.environ.get("GITHUB_SHA")
    if commit:
        return commit

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    return result.stdout.strip() or None


def get_metadata() -> dict:
    metadata = {
        "commit": get_commit(),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "server_url": os.environ.get("GITHUB_SERVER_URL"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    }
    return {key: value for key, value in metadata.items() if value}


class Bencher:
    def __init__(self):
        if not os.path.isfile(BENCHER_FILE):
            with open(BENCHER_FILE, "w+") as bf:
                json.dump({}, bf)

        metadata = get_metadata()
        if metadata:
            with open(BENCHER_FILE, "r") as bf:
                data = json.load(bf)
            # Every perf test in a CI run appends to the same file, so refresh
            # the run metadata without discarding keys an earlier test set.
            data.setdefault(METADATA_KEY, {}).update(metadata)
            with open(BENCHER_FILE, "w") as bf:
                json.dump(data, bf, indent=4)

    def set_metadata(self, key: str, value):
        """Record a property of the run itself, rather than a measurement.

        Metadata lives under a reserved key which the comparison scripts skip,
        so it travels with the results without being treated as a benchmark.
        Note that every perf test in a CI run writes to the same file, so keys
        recording a property of one test must say which test they describe.
        """
        with open(BENCHER_FILE, "r") as bf:
            data = json.load(bf)
        data.setdefault(METADATA_KEY, {})[key] = value
        with open(BENCHER_FILE, "w") as bf:
            json.dump(data, bf, indent=4)

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

    def set(self, key: str, metric: Latency | Throughput | Memory):
        with open(BENCHER_FILE, "r") as bf:
            data = json.load(bf)
        metric_val = dataclasses.asdict(metric)
        if key in data:
            data[key].update(metric_val)
        else:
            data[key] = metric_val
        with open(BENCHER_FILE, "w") as bf:
            json.dump(data, bf, indent=4)
