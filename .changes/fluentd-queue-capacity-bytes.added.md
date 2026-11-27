Fluentd sinks now accept `queue_capacity_bytes`, a soft limit on the bytes queued per node thread which defaults to 4 MiB and also caps each encoded record (replacing the previous 1 MiB cap).
Records for a full queue are now dropped before they are formatted or encoded; see [node configuration](doc/operations/configuration.rst#observability-export).
