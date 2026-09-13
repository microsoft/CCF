# Disaster recovery trace validation

This package validates version 1 implementation traces from CCF's C++ recovery
decision protocol against the permanent model in `../disaster-recovery`. It is
deliberately separate from the canonical model and depends only on
`DisasterRecovery.Protocol.Model`. Both packages are pinned to Lean 4.33.1.

`DisasterRecoveryTrace.Protocol.Trace.Format` parses the strict versioned
NDJSON contract. `DisasterRecoveryTrace.Protocol.Trace.Logs` extracts records
directly from text or JSON node logs and orders them using per-node sequences
and causal send edges, not timestamps.
`DisasterRecoveryTrace.Protocol.Trace.Replay` replays each event against the
canonical transition system. The validator rejects the first incompatible event
and reports its original file/line location and shortest failing ordered prefix.

## Build and test

```sh
lake exe cache get
lake exe mk_all --check --lib DisasterRecoveryTrace
lake build --wfail
lake lint
lake exe trace-checks
```

Run the validator with:

```sh
lake exe trace-validator --logs 3 QUORUM 20000 node0/out node1/out node2/out
```

The arguments are the expected participating-node count, expected open kind
(`QUORUM` or `FAILOVER`), timeout in milliseconds, and raw log paths. Lean waits
for complete newline-terminated records and scenario terminal evidence. Missing
sequences, send causes, or terminal effects are incomplete input; if they do not
arrive before the deadline, validation fails. Malformed records, causal cycles,
duplicate identifiers, wrong outcomes, and invalid replay transitions fail
without retrying. File read errors also fail rather than silently skipping logs.
Python only supplies log paths and scenario expectations and reports the result.

The original node logs are the reproduction artifact uploaded by SNP CI. For
an offline check use a timeout of `0`. Already ordered NDJSON remains supported
with `lake exe trace-validator TRACE.ndjson`; it does not perform the additional
scenario checks.

`TraceTests.lean` contains parser, ordering, scenario, and replay tests. These tests
exercise rejection behavior; they are not implementation conformance evidence.
Conformance evidence is produced only from real C++ SNP recovery runs and is
uploaded by the Milan and Genoa jobs.

See [TRACE_FORMAT_V1.md](TRACE_FORMAT_V1.md) for the complete contract.
