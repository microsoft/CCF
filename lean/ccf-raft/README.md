# CCF Raft model

This Lake package is an executable Lean model of CCF's Raft implementation (`src/consensus/aft/raft.h`), together with the safety properties it is intended to satisfy.
The properties are stated but not yet proved.

## Layout

| Module                             | Contents                                                       |
| ---------------------------------- | -------------------------------------------------------------- |
| `CCFRaft/Model/NodeState.lean`     | Node state, log entries and pure log queries                   |
| `CCFRaft/Model/ClusterConfig.lean` | Initial configuration, membership and retirement queries       |
| `CCFRaft/Model/Messages.lean`      | Messages exchanged between nodes                               |
| `CCFRaft/Model/Node.lean`          | `Node.step`: one node's response to an input or a message      |
| `CCFRaft/Model.lean`               | Composition of nodes into a network                            |
| `CCFRaft/Properties.lean`          | Safety property statements and their witnesses                 |
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
- `lake check` re-checks all default targets with Lean's kernel and fails on any axiom other than `propext`, `Classical.choice` and `Quot.sound`.
  It runs without sandbox isolation, so build-time code must be trusted; Lake prints a warning saying so.
- The formatting script runs the pinned [leanfmt](https://github.com/duckki/leanfmt).
  Pass `-f` before the package name to rewrite files in place.

`Properties.lean` states three properties over every valid trace of `Model.transitionSystem`:

- `ElectionSafety`: no two distinct nodes lead in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

Each has a `Witness` statement asserting that some valid trace reaches the situation the property constrains, such as two distinct leaders, so that a later proof is not vacuous.
Liveness is not stated.

Modules are layered in order: `ccf_common`, then the model, then the properties.
A model or property module may import only from its own layer or an earlier one, and none may import a proof module or a package-local `CCFRaft.Shared` copy of `ccf_common`.
`Tests/Architecture.lean` enforces this ordering when the package builds.

After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.

## TLA+ safety properties

`PropertiesTLA.lean` is a separate experiment that measures how much Lean is needed to prove TLA+ safety properties of this model.
It states and proves:

- `LogInv` and `THEOREM Spec => []LogInv` from `tla/consensus/ccfraft.tla` (lines 1400-1407), using `Committed(i)` (line 490).
- `CommittedLogAppendOnlyProp` and its theorem from `ccfraft.tla` (lines 1639-1645).
- `AppendOnlyProp` from `tla/consensus/abs.tla` (line 101), read through ccfraft's `MappingToAbs` (line 1727), which maps `cLogs[i]` to the terms of `Committed(i)`.

`LogInv` compares committed logs of different nodes in the same state, unlike `CommittedLogsPrefix` above, which compares any two states of a trace.
`Spec` is read as a valid trace of `Model.transitionSystem`, without `Fairness`, and `Servers` as the configured nodes.
The module documentation lists the remaining correspondences.
The Lean model is not proved equivalent to the TLA+ specification, and no TLAPS proof is involved.

Each theorem body calls a helper in `ProofTLA/`, which holds the whole proof.
`ProofTLA/` imports only the model, `ccf_common` and Mathlib, and is independent of any other proof layer.
`Tests/ArchitectureTLA.lean` enforces this and fails the build if a theorem depends on an axiom other than `propext`, `Classical.choice` and `Quot.sound`.
`Tests/PropertiesTLA.lean` checks how the statements read the TLA+ definitions, such as `Committed(i)` being `SubSeq` within the log and `cLogs` keeping only terms.
The package checks under Validation cover these modules through `CCFRaft.lean`.

To compare proof sizes, count lines from this directory:

```sh
wc -l CCFRaft/PropertiesTLA.lean
find CCFRaft/ProofTLA -name '*.lean' -print0 | sort -z | xargs -0 wc -l
```
