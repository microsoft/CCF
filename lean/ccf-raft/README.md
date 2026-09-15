# CCF Raft model

This package contains an executable CCF Raft model, user-visible safety property
definitions, and deterministic implementation-trace replay.
The input contract targets controlled `raft_driver` captures, not arbitrary
live-node logs.

```text
raft scenario -> raft_driver -> raw stdout -> Python reduction
              -> actions and observations -> Lean replay -> success or discrepancy
```

Python interprets recorded events. Lean executes the resulting actions through
the canonical model and compares observations at their specified boundaries.
Neither stage searches for a matching execution or invokes an SMT solver.

## Reviewed definitions

| File                                               | Contents                                                                                    |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `CCFRaft/Protocol/Model.lean`                      | Protocol state, messages, action guards, transitions, and initialization                    |
| `CCFRaft/Protocol/ExecutableTransitionSystem.lean` | Guarded execution and reachability definitions                                              |
| `CCFRaft/Properties.lean`                          | Committed-prefix agreement, signature commit frontiers, and election safety                 |
| `reduction.py` and [REDUCTION.md](REDUCTION.md)    | Reviewed interpretation of raw records, coalescing, coordinates, and observation boundaries |
| `CCFRaft/Replay.lean`                              | Strict instruction decoding, guarded execution, and observation comparison                  |
| `capture.py` and `trace_io.py`                     | Verbatim capture and source-line-preserving ingestion                                       |
| `run_scenarios.py`                                 | Complete scenario inventory, subprocess outcomes, and result artifacts                      |
| `CanonicalTests.lean`                              | Executable examples of selected protocol behavior                                           |

Review the reduction rules together with the C++ event locations they reference.
A successful Lean build and replay do not establish that those rules faithfully
describe every C++ execution.

The model and property definitions were imported from
`lean-tracing-demo-ccfraft` at commit `9be0b7352`. Module namespaces now follow
the package paths. Imports name the required Mathlib modules rather than the
whole library. The package uses Lean 4.33.1 and Mathlib `v4.33.1`, matching the
sibling disaster recovery package.

The type `ConsensusSafety` states properties. It is not evidence that they
hold. No system invariant, ghost history, or preservation proof has been
imported.

## Scope of execution

The transition system is parameterized by node and transaction identifier
types and a bootstrap configuration. Replay uses string identifiers and the
recorded bootstrap. Fixed-size node fixtures belong only to the executable tests.
Physical ledger indices retain the bootstrap configuration and signature.

`Enabled` and `next` define the canonical semantics. `applyAction` rejects a
disabled action rather than applying its state update.

The model retains packet multiplicity and per-source receive order. A recorded
drop removes one selected occurrence without invoking its protocol handler,
following `tla/consensus/Network.tla`. AppendEntries batches remain atomic.

A successful replay establishes that the emitted deterministic execution
satisfies its guards and selected observations. It does not establish C++
correctness in general, prove the safety properties, or check liveness.
Transient callback snapshots are not complete protocol states. Their fixed
observation scopes and exclusions are part of the reviewed reduction rules.

## Build

From this directory:

```sh
lake exe cache get Mathlib.Data.Finmap Mathlib.Data.Fintype.Basic
lake build --wfail
lake exe canonical-checks
python3 -m unittest discover -s tests -p 'test_*.py'
```

The cache command downloads only the dependencies used by this package.
The canonical examples do not replace implementation-trace replay.

## Replay every scenario

Build `raft_driver` using the repository's supported CCF development environment,
with `CCF_RAFT_TRACING=ON`. For an existing build directory:

```sh
cmake -S ../.. -B ../../build -DCCF_RAFT_TRACING=ON
cmake --build ../../build --target raft_driver
python3 run_scenarios.py ../../build/raft_driver --output ../../build/raft-replay/validation
```

The runner selects every file in `tests/raft_scenarios`, captures raw stdout,
reduces it, and invokes the Lean replayer. It retains per-scenario artifacts and
`summary.json`. A capture error, unsupported reduction, disabled action, or
observation mismatch makes the run fail. The runner continues through the
inventory so one failure does not hide the remaining scenarios.

For existing verbatim captures, use `--raw-directory` as documented in
[REDUCTION.md](REDUCTION.md). Reusing captures does not test a newly changed
implementation.
