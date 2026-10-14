# CCF Raft model

This Lake package is an executable Lean model of CCF's Raft implementation (`src/consensus/aft/raft.h`), together with the safety properties it is intended to satisfy and Lean proofs of those properties.
Its [Lean trace replayer](replay/README.md) checks recorded `raft_driver` executions against the model.

## Layout

| Module                                   | Contents                                                       |
| ---------------------------------------- | -------------------------------------------------------------- |
| `CCFRaft/Model/NodeState.lean`           | Node state, log entries and pure log queries                   |
| `CCFRaft/Model/ClusterConfig.lean`       | Initial configuration, membership and retirement queries       |
| `CCFRaft/Model/Messages.lean`            | Messages exchanged between nodes                               |
| `CCFRaft/Model/Node.lean`                | `Node.step`: one node's response to an input or a message      |
| `CCFRaft/Model.lean`                     | Composition of nodes into a network                            |
| `CCFRaft/Properties.lean`                | Safety property statements and their witnesses                 |
| `CCFRaft/Properties/Utils.lean`          | Definitions used by the statements                             |
| `CCFRaft/Proof.lean`                     | Exported theorem for each property and witness                 |
| `CCFRaft/Proofs/`                        | Proof implementations                                          |
| `CCFRaft/Tests/`                         | Regression theorems, behavior checks and import-boundary rules |
| `CCFRaft/Replay.lean`, `CCFRaft/Replay/` | Strict trace parsing, named reduction rules and direct replay  |
| `replay/`                                | Lean command-line entry point, regression suite and fixtures   |
| `CCFRaft.lean`                           | Generated root importing every module                          |

Transition systems, traces, output-recording effects and network composition come from the `ccf_common` package in `lean/common`, under the `CCF` namespace.
It is a Git dependency pinned to a commit in `lakefile.toml`.
To move it, update `rev`, run `lake update ccf_common`, and keep `lean-toolchain` and the Mathlib tag in step with `ccf_common`.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake exe canonical-checks
lake exe replay-checks
../../scripts/lean-format-checks.sh ccf-raft
```

The Lean CI workflow runs the same commands and checks every kernel root as described below.

- `mk_all --check` fails if `CCFRaft.lean` does not import every module.
- `lake build --wfail` builds the library, `canonical-checks`, `ccfraft-replay` and `replay-checks`, treating warnings, including `sorry`, as errors.
- `lake exe canonical-checks` runs executable behavior checks of the model.
- `Tests/ProofCoverage.lean` fails the build unless every property has an exported theorem in `Proof.lean` and a `Witness` statement.
- `lake exe replay-checks` checks strict parsing, reduction, model guards, observations, packet occurrences and suite failure paths without importing proofs.
- The formatting script runs the pinned [leanfmt](https://github.com/duckki/leanfmt).
  Pass `-f` before the package name to rewrite files in place.

The executable roots define distinct `main` declarations, so a single combined default-target export cannot load them together.
Run the standard sandboxed `lake check` separately for each root, temporarily selecting only its default target and restoring the original configuration afterward.
The `CCFRaft` library includes the proofs and the canonical executable root:

```sh
(
  set -euo pipefail
  config=$(mktemp)
  cp lakefile.toml "$config"
  trap 'cp "$config" lakefile.toml; rm "$config"' EXIT
  test "$(grep -c '^defaultTargets = ' "$config")" -eq 1
  for target in CCFRaft ccfraft-replay replay-checks; do
    sed "s/^defaultTargets = .*/defaultTargets = [\"$target\"]/" "$config" > lakefile.toml
    lake check
  done
)
```

Each check rejects any axiom other than `propext`, `Classical.choice` and `Quot.sound`.
Configuration evaluation, dependency resolution, builds, exports and checking all use Lake's default sandbox, which requires `bubblewrap`.
This deliberately does not use a plain `leanexport` followed by `lake check --from-export`, which checks an export file without establishing sandboxed provenance of its generation.
If local mount permissions prevent sandboxing, an explicit `--inadvisably-no-sandbox` check is qualified local evidence only; CI retains sandboxed checks.

`Properties.lean` states three properties over every valid trace of `Model.transitionSystem`:

- `ElectionSafety`: no two distinct nodes lead in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

Each has a `Witness` statement asserting that some valid trace reaches the situation the property constrains, such as two distinct leaders, so that the proofs are not vacuous.
The election witness has two distinct leaders without requiring equal terms; it does not witness the safety property's entire antecedent.
Liveness is not stated.

Modules are layered in order: `ccf_common`, then the model, then the properties, then the proofs.
Replay is a separate executable layer depending only on the model, shared helpers and earlier replay modules.
The model, properties and replay may not import proofs, and no module may import a package-local `CCFRaft.Shared` copy of `ccf_common`.
`Tests/Architecture.lean` enforces this ordering when the package builds.

After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.

## Proofs

`Proof.lean` proves each property and witness in `Properties.lean`.
The proofs target the current `Model.transitionSystem` directly, with no refinement to another model.
They say nothing about liveness, fairness, or the C++ implementation.

- `Proofs/Direct/` proves node-local facts: commit bounds, signature commit frontiers, and committed-log growth.
  `NodeInvariant` lifts a predicate preserved by every local step to every node of every reachable state.
- `Proofs/Safety/` proves a cross-node invariant over the execution history: terms led, entries accepted and acknowledged, and messages sent.
  `Summary.lean` and `Step.lean` summarize each node step once; the invariant clauses are proved from those summaries.
  Reconfiguration and retirement facts come from each transaction's ordered effects, so several configurations may share one log index.
- `Proofs/Election.lean` and `Proofs/CommittedLogs.lean` derive `ElectionSafety` and `CommittedLogsPrefix` from that invariant.
- `Proofs/Witnesses.lean` proves the witnesses with concrete executions evaluated by the kernel.

[`scripts/invariant-dependencies.lean`](scripts/invariant-dependencies.lean) lists the `Proofs.Safety` declarations in the kernel dependency closure of the exported theorems, to help remove unused lemmas.
Run it with `lake env lean scripts/invariant-dependencies.lean`.

## Trace validation

Build `raft_driver` with tracing, then run from this package:

```sh
cmake -S ../.. -B ../../build -DCCF_RAFT_TRACING=ON
cmake --build ../../build --target raft_driver
lake exe ccfraft-replay suite --driver ../../build/raft_driver --output ../../build/raft-replay
```

The Lean runner captures every file in the actual `tests/raft_scenarios` inventory, reduces it and replays it directly.
It retains raw captures and per-scenario results, attempts the entire inventory and fails on any capture, parsing, reduction or replay discrepancy.
The old Python reducer/harness and intermediate JSON replay schema are not required or included.
See the [source-event rules, observation contract and regression coverage](replay/README.md).

Successful replay checks model guards, state observations, observed message compatibility and actual delivery feasibility.
Send telemetry need not enumerate every model emission exactly once: omitted optional send observations and repeated compatible observations are allowed, but do not create another deliverable packet occurrence.
Driver FIFO scheduling and explicit drops are bookkeeping over the model's unordered multiset network, not a new model restriction.
Replay does not establish complete send logging or that the reduction describes every C++ execution.
