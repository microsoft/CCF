Records exported to Fluentd now name the process identifier `pid` instead of `process_id` in the trace envelope described in [node configuration](doc/operations/configuration.rst).
Collectors that read `process_id`, which 7.x releases since 7.0.21 emit, must read `pid` instead.
