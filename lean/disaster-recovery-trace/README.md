# Disaster recovery trace validation

This package validates implementation traces from CCF's C++ recovery
decision protocol against the permanent model in `../disaster-recovery`. It is
deliberately separate from the canonical model and depends only on
`DisasterRecovery.Protocol.Model`. Both packages are pinned to Lean 4.33.1.

`DisasterRecoveryTrace.Protocol.Trace.Format` parses the strict
NDJSON contract. `DisasterRecoveryTrace.Protocol.Trace.Logs` extracts records
directly from text or JSON node logs and orders them using per-node sequences
and causal send edges, not timestamps.
`DisasterRecoveryTrace.Protocol.Trace.Replay` buffers speculative semantic
events by `(node, attempt)`, applies globally committed attempts to the canonical
transition system, and discards rolled-back or aborted attempts. Local-commit
records prove which speculative states were visible to retry sends; sends
observed before that proof remain conditional and are rejected if every
possible attempt aborts. Starts and sends are replayed immediately. A first send
racing after lifecycle resolution may select a retained pre-resolution local
projection. Trace-only batch IDs let replay track multiple concurrent retry
invocations independently when their sends interleave. Globally committed
buffers are replayed in per-node TxID order rather than callback-log order.
Local and final TxIDs must match, and terminal validation rejects locally
committed attempts with no final status. The validator rejects the first
incompatible record and reports its original file/line location and shortest
failing ordered prefix.

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
for complete newline-terminated records and committed scenario terminal
evidence. Missing sequences, send causes, or terminal effects are incomplete
input; unresolved attempts are legal and ignored. If required evidence does not
arrive before the deadline, validation fails. Malformed records, causal cycles,
duplicate identifiers or attempt keys, invalid lifecycle references, wrong
outcomes, and invalid committed replay transitions fail without retrying. File
read errors also fail rather than silently skipping logs. The reported event
count includes raw lifecycle and discarded records. Python only supplies log
paths and scenario expectations and reports the result.

The original node logs are the reproduction artifact uploaded by SNP CI. For
an offline check use a timeout of `0`. Already ordered NDJSON remains supported
with `lake exe trace-validator TRACE.ndjson`; it does not perform the additional
scenario checks.

`TraceTests.lean` contains parser, ordering, scenario, and replay tests. These tests
exercise rejection behavior; they are not implementation conformance evidence.
Conformance evidence is produced only from real C++ SNP recovery runs and is
uploaded by the Milan and Genoa jobs.

See [TRACE_FORMAT.md](TRACE_FORMAT.md) for the complete contract.
