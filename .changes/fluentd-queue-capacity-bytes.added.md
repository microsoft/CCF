Fluentd sinks now accept `queue_capacity_bytes`, a soft limit on the bytes queued per node thread which defaults to 4 MiB, and no longer drop records larger than 1 MiB.
Records for a full queue are now dropped before they are formatted or encoded; see [node configuration](doc/operations/configuration.rst#observability-export).
