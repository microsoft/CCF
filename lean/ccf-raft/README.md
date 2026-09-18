# CCF Raft model

An executable Lean model of CCF Raft, kernel-checked safety proofs for that
model, and a replayer that checks recorded `raft_driver` runs against it.

```text
raft scenario -(raft_driver)-> raw stdout
              -(Python reduction)-> actions and observations
              -(Lean replay)-> success or discrepancy
```

Python interprets recorded events into model actions. Lean executes those
actions and compares observations. Neither stage searches for a matching
execution or calls a solver.

## What is proven, and what is not

The public theorems in `CCFRaft/Properties.lean` establish election safety,
pairwise committed-log prefix agreement, signature commit frontiers, and
append-only committed logs for every reachable model state. They hold for
arbitrary node and transaction identifier types under the model's bootstrap
assumptions.

`ConsensusSafety.committedLogAppendOnly` states that every enabled action
retains each node's committed prefix. This is the step condition of
`CommittedLogAppendOnlyProp` in `tla/consensus/ccfraft.tla`.
`run_actions_committed_log_prefix` extends the guarantee to any finite sequence
of enabled actions from a reachable state. Uncommitted suffixes may still be
truncated or replaced.

The proofs say nothing about liveness, fairness, or the C++ implementation.
`SystemInductiveInvariant` and its ghost histories under `Proofs/` are proof
artifacts, not model fields or premises of the public statements.

A successful replay shows that the reduced execution satisfies the model's
guards and the selected observations. It does not show that the reduction
rules describe every C++ execution. Review those rules against the C++ event
locations they name.

## Files

| File                                               | Contents                                                        |
| -------------------------------------------------- | --------------------------------------------------------------- |
| `CCFRaft/Protocol/Model.lean`                      | State, messages, action guards and updates, initialization      |
| `CCFRaft/Protocol/ExecutableTransitionSystem.lean` | Guarded execution and reachability                              |
| `CCFRaft/Protocol/Safety.lean`                     | Safety predicates                                               |
| `CCFRaft/Properties.lean`                          | Public safety theorems                                          |
| `CCFRaft/Proofs/*.lean`                            | Inductive invariant and preservation lemmas                     |
| `CCFRaft/Replay.lean`                              | Instruction decoding, guarded execution, observation comparison |
| `replay/`                                          | Capture, reduction, and scenario runner. See `replay/README.md` |
| `tests/CanonicalTests.lean`                        | Executable examples of selected protocol behavior               |
| `replay/tests/test_*.py`                           | Reduction and replay regression tests                           |

## Build and check

From this directory:

```sh
lake exe cache get
lake exe mk_all --check --lib CCFRaft
lake build --wfail
lake lint
lake exe canonical-checks
python3 -m unittest discover -s replay/tests -p 'test_*.py'
```

`lake lint` audits axioms. Only `propext`, `Classical.choice`, and
`Quot.sound` are allowed, so an admitted proof fails the build.

## Replay every scenario

Build `raft_driver` with tracing, then run the suite:

```sh
cmake -S ../.. -B ../../build -DCCF_RAFT_TRACING=ON
cmake --build ../../build --target raft_driver
python3 replay/run_scenarios.py ../../build/raft_driver --output ../../build/raft-replay/validation
```

The runner captures every file under `tests/raft_scenarios`, reduces it, and
replays it. Any capture error, unsupported event, disabled action, or
observation mismatch fails the run. It continues through the inventory and
writes `summary.json`.
