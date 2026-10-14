# CCF Raft model

This Lake package is an executable Lean model of CCF's Raft implementation (`src/consensus/aft/raft.h`), together with the safety properties it is intended to satisfy and Lean proofs of those properties.

## Layout

| Module                             | Contents                                                       |
| ---------------------------------- | -------------------------------------------------------------- |
| `CCFRaft/Model/NodeState.lean`     | Node state, log entries and pure log queries                   |
| `CCFRaft/Model/ClusterConfig.lean` | Initial configuration, membership and retirement queries       |
| `CCFRaft/Model/Messages.lean`      | Messages exchanged between nodes                               |
| `CCFRaft/Model/Node.lean`          | `Node.step`: one node's response to an input or a message      |
| `CCFRaft/Model.lean`               | Composition of nodes into a network                            |
| `CCFRaft/Properties.lean`          | Safety property statements and their witnesses                 |
| `CCFRaft/Proof.lean`               | Exported theorem for each property and witness                 |
| `CCFRaft/Proofs/`                  | Proof implementations                                          |
| `CCFRaft/Tests/`                   | Regression theorems, behavior checks and import-boundary rules |
| `CCFRaft.lean`                     | Generated root importing every module                          |

Transition systems, traces, output-recording effects and network composition come from the `ccf_common` package in `lean/common`, under the `CCF` namespace.
It is a Git dependency pinned to a commit in `lakefile.toml`.
To move it, update `rev`, run `lake update ccf_common`, and keep `lean-toolchain` and the Mathlib tag in step with `ccf_common`.

`Properties.lean` defines `GlobalTrace` alongside the property statements.

`NodeState.lean` holds the state and simple log accessors. `ClusterConfig.lean`
holds configuration and membership queries, including `MembershipState` and
`latestMembershipIndex`, plus the configuration-majority and quorum predicates.
`MembershipState.noRetirementObserved` means no membership removal is recorded
in the local log; it does not imply that the node has joined.
`NodeState.isRetiredCommitted` queries the derived membership phase, not just
the historical commit latch.
`latestConfigurationMembers` reads the final supplied configuration's membership.
Protocol helpers such as `NodeState.recordCommit`
and `findHighestPossibleMatch` live in `Node.lean`.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake exe canonical-checks
lake check --inadvisably-no-sandbox
../../scripts/lean-format-checks.sh ccf-raft
```

The Lean CI workflow runs the same commands.

- `mk_all --check` fails if `CCFRaft.lean` does not import every module.
- `lake build --wfail` builds the library and the `canonical-checks` executable, treating warnings, including `sorry`, as errors.
- `lake exe canonical-checks` runs executable behavior checks of the model.
- `Tests/ProofCoverage.lean` fails the build unless every property has an exported theorem in `Proof.lean` and a `Witness` statement.
- `lake check` re-checks all default targets with Lean's kernel and fails on any axiom other than `propext`, `Classical.choice` and `Quot.sound`.
  It runs without sandbox isolation, so build-time code must be trusted; Lake prints a warning saying so.
- The formatting script runs the pinned [leanfmt](https://github.com/duckki/leanfmt).
  Pass `-f` before the package name to rewrite files in place.

`Properties.lean` states four properties of `Model.transitionSystem`:

- `ElectionSafety`: no two distinct nodes lead in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
- `SingleNodeCommittedLogMonotonic`: a successful network step from a state with unique node IDs preserves each node's committed prefix, without assuming reachability.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

The other three properties quantify over valid traces.
Each has a `Witness` statement exhibiting the situation it constrains, such as two distinct leaders.
The single-node witness requires unique starting node IDs and a successful step that strictly extends a nonempty committed log.
The election witness has two distinct leaders without requiring equal terms; it does not witness the safety property's entire antecedent.
Liveness is not stated.

Modules are layered in order: `ccf_common`, then the model, then the properties, then the proofs.
A module may import only from its own layer or an earlier one, and nothing may import a proof module or a package-local `CCFRaft.Shared` copy of `ccf_common`.
`Tests/Architecture.lean` enforces this ordering when the package builds.

After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.

## Proofs

`Proof.lean` proves each property and witness in `Properties.lean`.
The proofs target the current `Model.transitionSystem` directly, with no refinement to another model.
They say nothing about liveness, fairness, or the C++ implementation.

- `Proofs/Direct/` proves node-local facts: commit bounds, signature commit frontiers, and committed-log growth.
  `NodeInvariant` lifts a predicate preserved by every local step to every node of every reachable state.
  `AppendOnly.lean` proves `SingleNodeCommittedLogMonotonic` from any state with distinct node identifiers, without a reachability invariant: each step keeps the committed log as a prefix of the new log and never lowers the commit index.
- `Proofs/Safety/` proves a cross-node invariant over the execution history: terms led, entries accepted and acknowledged, and messages sent.
  `Summary.lean` and `Step.lean` summarize each node step once; the invariant clauses are proved from those summaries.
  Reconfiguration and retirement facts come from each transaction's metadata; a transaction carries at most one configuration, but one batch may append several reconfiguration transactions.
- `Proofs/Election.lean` and `Proofs/CommittedLogs.lean` derive `ElectionSafety` and `CommittedLogsPrefix` from that invariant.
- `Proofs/Witnesses.lean` proves the witnesses with concrete executions evaluated by the kernel.

[`scripts/invariant-dependencies.lean`](scripts/invariant-dependencies.lean) lists the `Proofs.Safety` declarations in the kernel dependency closure of the exported theorems, to help remove unused lemmas.
Run it with `lake env lean scripts/invariant-dependencies.lean`.
