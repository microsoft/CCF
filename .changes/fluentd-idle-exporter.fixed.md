The Fluentd exporter configured by [`observability.fluentd`](doc/operations/configuration.rst#observability-export) no longer wakes every millisecond while idle or while a collector is unreachable, which cost about 1% of request throughput in benchmarks.
Reconnecting to a restarted collector can take up to about 130 ms longer.
