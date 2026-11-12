Node logger records can now be exported to Fluentd under `ccf.log`, using the JSON console schema.
Collectors now default to `["ccf.log"]`; set `["ccf"]` explicitly to retain consensus traces, as described in [observability export](doc/operations/configuration.rst#observability-export).
