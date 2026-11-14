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

The model covers safety and deadlock freedom, but not eventual progress, disaster recovery, or non-forwarded reads.
There is no refinement proof connecting it to the [CCF consensus protocol model](../consensus/README.md).

## Properties

[`Properties.lean`](consistency/Properties.lean) contains 17 proved safety theorems over valid model executions, each with an adjacent non-vacuity witness.
It also proves `deadlock_free`, using the [shared definition](../common/README.md#transition-systems).
This is not a guarantee that requests eventually execute or receive responses.
The primary consistency guarantee is expressed by `committed_rw_ordered_serializable` and `committed_rw_ordered_real_time` together.
Committed writes serialize in transaction-ID order, and that order respects request-to-initial-response intervals rather than waiting for committed-status notifications.
Supporting proofs live under [`Proofs/`](consistency/Proofs); [`Witnesses.lean`](consistency/Proofs/Witnesses.lean) constructs the witness executions by replaying model actions and also holds the history-only proofs.
The proof modules do not import each other, so Lake checks them in parallel; lemmas needed by more than one module are duplicated as private declarations to minimise verification wall-clock time.
Proof modules follow the shared [dependency import contract](../common/README.md#dependency-imports); import additional facilities explicitly rather than relying on incidental reexports.

## Validation

Install Lean through [elan](https://lean-lang.org/install/), then run from this package directory:

```sh
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh consistency
```

`lake check` checks proofs against the kernel and standard axiom allowlist, without allowing unfinished proofs.
`lake exe check-imports` checks module coverage and dependency direction.
The unsandboxed check executes build-time code, which must be trusted.

## Trace validation

`consistency-replay` consumes the `ccf.cft` consensus trace events that nodes [export](../../doc/operations/configuration.rst), as NDJSON records with the event in a `msg` field, ordered by timestamp.
It replays them through `Model.step`, using `become_leader`, `send_request_vote`, `replicate` and `commit`, and skipping other events.
A new leader's view starts from the ledger prefix that it reported when requesting votes.
Every ledger entry is replayed as a write, which a node's `commit` reports committed.
A `tx_status` record adds what nodes do not trace: a `Committed` or `Invalid` status given to a client.
Nothing is reconstructed: a trace missing an election or a ledger entry is rejected.
Client reads are not traced, so this does not validate the model's read observations.
Empty traces, malformed records, and disabled transitions fail with a line-numbered diagnostic and nonzero exit code.

[`tests/infra/consistency_trace.py`](../../tests/infra/consistency_trace.py) records such a trace for the nodes of a test and replays it, when `CCF_LEAN_CONSISTENCY_REPLAYER` names the replayer.
The trace is written to the test workspace, named after the test, such as `basic_partitions_consistency_trace.ndjson`.
Two e2e tests use it (they require the [CCF build prerequisites](../../doc/contribute/build_setup.rst)):

- [`tests/consistency_trace_validation.py`](../../tests/consistency_trace_validation.py) suspends the primary to cause an election while [`tests/tvc.py`](../../tests/tvc.py) writes, and reports the final status of each write.
- [`tests/partitions_test.py`](../../tests/partitions_test.py) traces each of its networks, and reports the `Invalid` statuses that it checks.

From the repository root:

```sh
(cd lean/consistency && lake build --wfail consistency-replay)
export CCF_LEAN_CONSISTENCY_REPLAYER="$PWD/lean/consistency/.lake/build/bin/consistency-replay"
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DLONG_TESTS=ON
cmake --build build --target consistency_trace_validation partitions
(cd build && ./tests.sh -VV -R '^consistency_trace_validation$' --no-tests=error)
(cd build && ./tests.sh -VV -C partitions -R '^partitions$' --no-tests=error)
```

The [Lean workflow](../../.github/workflows/lean.yml) runs `consistency_trace_validation` with the replayer, and the [CI workflow](../../.github/workflows/ci.yml) does the same for the partitions tests.
The [replay fixtures](replayer/fixtures/README.md) check that the replayer accepts valid traces and rejects invalid ones.
