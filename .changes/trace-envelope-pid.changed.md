Records exported to Fluentd now name the process identifier `pid` instead of `process_id` in the trace envelope described in [node configuration](doc/operations/configuration.rst).
Collectors that read `process_id` must read `pid` instead.
