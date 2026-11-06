# Consistency model

An executable Lean model of CCF's externally visible consistency semantics.
It models a dummy append-and-read application, not the consensus implementation.

## Source map

| Area                                          | Lean source                                                      |
| --------------------------------------------- | ---------------------------------------------------------------- |
| Typed events, IDs, ledger entries, and state  | [`Model/Types.lean`](consistency/Model/Types.lean)               |
| Executable history queries                    | [`Model/History.lean`](consistency/Model/History.lean)           |
| Guarded actions                               | [`Model/Transitions.lean`](consistency/Model/Transitions.lean)   |
| Initialization and transition system          | [`Model.lean`](consistency/Model.lean)                           |
| History selection and transaction-ID ordering | [`Properties/History.lean`](consistency/Properties/History.lean) |
| Property statements and proof links           | [`Properties.lean`](consistency/Properties.lean)                 |
| Supporting proofs                             | [`Proofs/`](consistency/Proofs)                                  |

Shared transition systems and executions come from [`ccf_common`](../common/README.md).

## Model

The model represents a multi-node service with forwarded reads, elections, and invalidation.
`Model.transitionSystem` supplies initialization and an executable step function; `none` means an action is disabled.

The global state contains an append-only client history and one append-only ledger branch per leader view.
An election copies a prefix compatible with known commitments into a new branch, preserving older branches.
Writes and forwarded reads can still select former leaders' branches.
Write execution, initial response, and committed/invalid status reporting are separate actions.
Commitment is tracked through received status reports.
Committed writes cannot observe known invalid writes, including entries copied from earlier views, but a different-view replacement at the same sequence number can commit.

Views, branch indices, sequence numbers, and action-history indices are one-based.
Request IDs begin at zero and are allocated across both transaction kinds.
Property helpers use zero-based history positions.
The initial view is 2; view 1 is reserved and cannot process requests.

The model covers safety only, not liveness, disaster recovery, or non-forwarded reads.
There is no refinement proof connecting it to the [CCF consensus protocol model](../consensus/README.md).

## Properties

[`Properties.lean`](consistency/Properties.lean) contains 17 proved safety theorems over valid model executions, each with an adjacent non-vacuity witness.
The primary consistency guarantee is expressed by `committed_rw_ordered_serializable` and `committed_rw_ordered_real_time` together.
Committed writes serialize in transaction-ID order, and that order respects request-to-initial-response intervals rather than waiting for committed-status notifications.
Supporting proofs live under [`Proofs/`](consistency/Proofs); [`Witnesses.lean`](consistency/Proofs/Witnesses.lean) constructs the witness executions by replaying model actions and also holds the history-only proofs.
The proof modules do not import each other, so Lake checks them in parallel; lemmas needed by more than one module are duplicated as private declarations to minimise verification wall-clock time.
Proof modules follow the shared [dependency import contract](../common/README.md#dependency-imports); import additional Mathlib facilities explicitly rather than relying on incidental reexports.

## Validation

Install Lean through [elan](https://lean-lang.org/install/), then run from this package directory:

```sh
lake exe cache get
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh consistency
```

`lake check` checks proofs against the kernel and standard axiom allowlist, without allowing unfinished proofs.
`lake exe check-imports` checks module coverage and dependency direction.
The unsandboxed check executes build-time code, which must be trusted.

## Trace validation

`consistency-replay` consumes the NDJSON format from [`tests/tvc.py`](../../tests/tvc.py).
It replays requests, write executions, responses, and final statuses through `Model.step`, checking request IDs and response transaction IDs.
Missing views and non-application ledger entries are backfilled before write executions and reads.
Backfilling uses guarded model elections and appends; it cannot roll back a known committed prefix.
Elections discard known-invalid suffixes before filling gaps in the new view.
This is a deterministic reconstruction for these captures, not a complete search for all possible model executions.
The capture contains no application read values, so this does not validate the model's append-and-read application observations.
An unfinished final request is allowed, but empty traces, malformed records, and disabled transitions fail with a line-numbered diagnostic and nonzero exit code.

From the repository root, generate a capture using the existing e2e test (requires the [CCF build prerequisites](../../doc/contribute/build_setup.rst)):

```sh
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DLONG_TESTS=ON
cmake --build build --target consistency_trace_validation
(cd build && ./tests.sh -VV -R '^consistency_trace_validation$' --no-tests=error)
cd lean/consistency
lake build --wfail consistency-replay
.lake/build/bin/consistency-replay ../../build/consistency/trace.ndjson
```

The [Lean workflow](../../.github/workflows/lean.yml) captures and replays this trace in separate jobs, following the KV and CCF consensus setup, and also checks the [replay fixtures](replayer/fixtures/README.md), including election and rollback traces.
The replay fixtures check that the replayer accepts valid traces and rejects invalid ones.
