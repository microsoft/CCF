Records exported to Fluentd now name the process identifier `pid` instead of `process_id`, and the per-process sequence number `m_ts` instead of `h_ts`, in the trace envelope described in [node configuration](doc/operations/configuration.rst).
Collectors that read `process_id` or the envelope's `h_ts`, which 7.x releases since 7.0.21 emit, must read `pid` and `m_ts` instead.
