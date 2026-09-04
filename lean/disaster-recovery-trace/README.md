# Disaster recovery trace validation

This package validates version 1 implementation traces from CCF's C++ recovery
decision protocol against the permanent model in `../disaster-recovery`. It is
deliberately separate from the canonical model and depends only on
`DisasterRecovery.Protocol.Model`.

`DisasterRecoveryTrace.Protocol.Trace.Format` parses the strict versioned
NDJSON contract. `DisasterRecoveryTrace.Protocol.Trace.Replay` replays each
event against the canonical transition system. The validator rejects the first
incompatible event and reports the shortest failing prefix.

## Build and test

```sh
lake exe cache get
lake build
lake exe trace-checks
lake exe axiom-checks
```

Run the validator with:

```sh
lake exe trace-validator -- TRACE.recovery.ndjson
```

`TraceTests.lean` contains small in-memory parser and replay tests. These tests
exercise rejection behavior; they are not implementation conformance evidence.
Conformance evidence is produced only from real C++ SNP recovery runs and is
uploaded by the Milan and Genoa jobs.

See [TRACE_FORMAT_V1.md](TRACE_FORMAT_V1.md) for the complete contract.
