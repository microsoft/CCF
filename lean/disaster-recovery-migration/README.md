# Temporary disaster recovery migration evidence

This package is the temporary PR 2 evidence layer for migrating the legacy
Rust/Stateright disaster recovery model to Lean. It depends locally on the
canonical package in `../disaster-recovery`; it does not modify or duplicate
that package. This directory and its dedicated workflow are intended to be
deleted wholesale by PR 3 once the migration evidence has served its purpose.

## Scope

There are two distinct and deliberately weaker claims:

1. The executable model in `DisasterRecoveryMigration.Legacy` is an exact
   Lean mirror of the Rust/Stateright model in `tla/disaster-recovery`.
   `compare.py` establishes exhaustive bounded equivalence for one, two, and
   three nodes.
2. `DisasterRecoveryMigration.Refinement` relates the canonical C++-aligned
   Lean model to the legacy Lean mirror only at the protocol-phase level.

The bounded comparison is not a theorem about arbitrary node counts or a
formal semantics for Rust or Stateright. The phase refinement is not a full
bisimulation, data refinement, or proof that the canonical model is identical
to the Rust model.

## Exact bounded equivalence

Both exporters emit the stable `ccf-legacy-dr-graph-v1` format. State IDs are
assigned after sorting normalized state keys, independently of traversal
order. For each requested node count, `compare.py` checks:

- the normalized initial state;
- every normalized reachable state in both directions;
- every labeled edge, including source and destination, in both directions;
- all nine registered predicate valuations for every reachable state; and
- the expected complete state and edge counts below.

| Nodes | Reachable states | Labeled edges | Predicate values per state |
| ----: | ---------------: | ------------: | -------------------------: |
|     1 |                1 |             0 |                          9 |
|     2 |               54 |            95 |                          9 |
|     3 |          105,558 |       552,282 |                          9 |

The comparator fails on a difference from either exporter and reports a
shortest path to a representative state or edge mismatch.

The mirror intentionally retains the legacy semantics, including message
multiplicity, unordered delivery, timer behavior, no-op suppression, immediate
multi-phase advancement, and the existing predicate definitions and names.
Differences in the canonical model are not backported into this oracle.

## Canonical phase refinement and limitations

`DisasterRecoveryMigration.Refinement` imports the canonical
`DisasterRecovery.Protocol.Model` through the local Lake dependency and
projects canonical phases as follows:

- Gossiping maps to legacy Vote.
- Voting maps to legacy OpenJoin.
- canonical Opening and Open collapse to legacy Open, retaining quorum versus
  failover as the legacy timeout flag.
- Joining maps to legacy Join.

`canonical_step_simulates` proves that each canonical local step projects to a
reflexive-transitive legacy phase step. The file also proves finite compatible
trace simulation, collapsed-Open preservation, quorum-kind projection, and
Opening-to-Open stuttering.

This phase-only result does not relate gossip sets, votes, timeout-lane state,
network state, transaction persistence, or all nine legacy predicates. It
does not establish a global scheduler correspondence or preserve the legacy
liveness expectations.

Two intentional model differences are explicit:

- The canonical quorum is the strict majority `n / 2 + 1`; the legacy quorum
  is `(n + 1) / 2`. They agree for odd node counts, while for even node counts
  the canonical threshold is one larger.
- With one node, the legacy full initial state opens immediately without a
  timeout. The canonical initial node remains in Gossiping, whose projected
  phase is Vote. `single_node_full_initial_models_differ` proves this mismatch.

## Files

| File                                            | Purpose                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------- |
| `DisasterRecoveryMigration/Legacy/Model.lean`   | Exact executable legacy semantics                                   |
| `DisasterRecoveryMigration/Legacy/Checker.lean` | BFS model checker and canonical graph encoder                       |
| `Main.lean`                                     | Legacy model-checker CLI                                            |
| `ExportMain.lean`                               | Separate Lean graph-exporter CLI                                    |
| `Tests.lean`                                    | Focused legacy semantic checks                                      |
| `DisasterRecoveryMigration/Refinement.lean`     | Canonical-to-legacy phase refinement                                |
| `AxiomChecks.lean`                              | `sorryAx` rejection for loaded migration and canonical declarations |
| `compare.py`                                    | Bidirectional exhaustive Rust/Lean comparison                       |

## Validation

Run from this directory:

```console
lake exe cache get
lake build
lake exe migration-semantic-checks
lake exe migration-model-checker --nodes 3
lake env lean -DwarningAsError=true AxiomChecks.lean
python3 compare.py --nodes 1 2 3
```

The canonical package's own `AxiomChecks.lean` remains authoritative for all
canonical declarations and is also run by the dedicated migration workflow.
The migration Lake package pins the same Lean toolchain, transitively resolves
the same Mathlib revision, and treats warnings as errors.
