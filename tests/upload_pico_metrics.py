# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import cimetrics.upload
import collections
import csv
import os
from loguru import logger as LOG

benchmark_specs = {
    "kv_bench.csv": [
        {
            "_name": "KV ser (/s)^",
            "Suite": "serialise",
            "Benchmark": "serialise<SD::PUBLIC>",
            "D": "10",
        },
        {
            "_name": "KV deser (/s)^",
            "Suite": "deserialise",
            "Benchmark": "deserialise<SD::PUBLIC>",
            "D": "10",
        },
        {
            "_name": "KV snap ser (/s)^",
            "Suite": "serialise_snapshot",
            "Benchmark": "ser_snap<1000>",
            "D": "100",
        },
        {
            "_name": "KV snap deser (/s)^",
            "Suite": "deserialise_snapshot",
            "Benchmark": "des_snap<1000>",
            "D": "100",
        },
    ],
    "map_bench.csv": [
        {
            "_name": "CHAMP put (/s)^",
            "Suite": "put",
            "Benchmark": "bench_champ_map_put",
            "D": "2048",
        },
        {
            "_name": "CHAMP get (/s)^",
            "Suite": "get",
            "Benchmark": "bench_champ_map_get",
            "D": "2048",
        },
    ],
    "digest_bench.csv": [
        {
            "_name": "mbedtls sha256 (/s)^",
            "Suite": "mbedtls_digest_sha256",
            "Benchmark": "SHA-256",
            "D": "524288",
        },
    ],
}

if __name__ == "__main__":
    found_metrics = collections.defaultdict(list)

    for filename, specs in benchmark_specs.items():
        if os.path.exists(filename):
            with open(filename, newline="") as f:
                LOG.debug(f"Examining {filename}")
                reader = csv.DictReader(f)
                for i, entry in enumerate(reader):
                    for spec in specs:
                        match = True
                        for k, v in spec.items():
                            if k == "_name":
                                continue
                            entry_value = entry.get(k)
                            if entry_value != v:
                                match = False
                                break

                        if match:
                            LOG.trace(f"Found match at line {i} for {spec}")
                            dimension = int(entry["D"])
                            total_time = int(entry["Total ns"])
                            ops_per_sec = dimension * (1000000000.0 / total_time)
                            LOG.trace(f"Calculated {ops_per_sec:.2f} ops/sec")
                            name = spec.get("_name") or spec.get("Suite") or "UNNAMED"
                            found_metrics[name].append(
                                float(format(ops_per_sec, ".2f"))
                            )

    if found_metrics:
        with cimetrics.upload.metrics(complete=False) as metrics:
            for name, results in found_metrics.items():
                many_results = len(results) > 1
                for i, result in enumerate(results):
                    upload_name = f"{name}_{i}" if many_results else name
                    LOG.debug(f"Uploading metric: {upload_name} = {result}")
                    metrics.put(upload_name, result)
