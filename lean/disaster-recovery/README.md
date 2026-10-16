# Lean disaster recovery model

This package contains a Lean model of CCF's recovery decision protocol (`src/node/recovery_decision_protocol.cpp`), its safety properties, machine-checked proofs of those properties, and a replayer that checks recorded C++ runs against the model.
[The Lean module guide](../AGENT.md) describes the module layout.

## Contents

| Purpose                               | Location                                                |
| ------------------------------------- | ------------------------------------------------------- |
| Property statements                   | `DisasterRecovery/Properties.lean`                      |
| Proof of each property                | `DisasterRecovery/Proof.lean`, one theorem per property |
| Single-node protocol                  | `DisasterRecovery/Model/Local.lean`                     |
| Network composition                   | `DisasterRecovery/Model.lean`, `../common/CCF/`         |
| Definitions used by the statements    | `DisasterRecovery/Properties/Utils.lean`                |
| Proof implementations                 | `DisasterRecovery/Proofs/`                              |
| Executable checks and concrete traces | `DisasterRecovery/Tests/`                               |
| Replay of recorded C++ traces         | `DisasterRecovery/TraceValidation.lean`                 |
| Parsing and ordering of those traces  | `DisasterRecovery/TraceValidation/`                     |
| Replayer executable and test traces   | `replayer/`                                             |

Human review covers the model, the property statements, the definitions they use, and the theorem links in `Proof.lean`.
The proof implementations under `Proofs/` are verified by the build and `lake check` and are marked `linguist-generated` in `.gitattributes`.

## Model

`Model/Local.lean` defines one node.
Its phases are gossiping, voting, opening, joining, and open.
It also models a timeout lane, retries, failover, and restart.
`Local.step` returns `none` for a disabled event.
For an enabled event it returns the next state and invokes the host's `send` and `notify` callbacks.
A rejected receive is an enabled step that emits a notification.
`Validation.accepted` and `Validation.rejected` represent the results of the C++ quote and certificate checks.
The model does not define that cryptography.

[`CCF.MultiNodeTransitionSystem`](../common/CCF/MultiNodeTransitionSystem.lean) in the [common package](../common/README.md) composes copies of one local protocol into a message-passing network.
Each step executes one node once, collects its outputs with `Capabilities.record`, and appends its sends to the queue.
Delivery consumes any queued envelope, not only the first.
Notifications are not stored in the global state.

`Model.lean` supplies each node's recovered TxID and adds `Config.Valid` to the initial-state predicate.
The model records no history.
The proofs reconstruct sends and notifications by re-executing local steps.

## Properties

The local properties are invariants of `Local.step`.
They hold for every node state, not only reachable ones.
Each quantifies a `LocalStep` record and assumes `ValidStep`: re-executing the step yields exactly the recorded after-state and outputs.

The global properties quantify a `GlobalTrace`, a list of states beginning with the initial state.
`trace.Valid` requires an initial first state and an enabled action between each adjacent pair.
`Trace.NotificationAt` states that a step by `node` between states `i` and `i + 1` emitted a given notification.

`QuorumOpenerUnique` states that all `opening quorum` notifications in a trace originate from one node.

`QuorumOpenPreservesCommit` and `FullGossipPreservesCommit` conclude that the opener satisfies Raft's vote freshness check against a strict majority of the recovered ledgers.
`LogUpToDate` is that check, comparing view and then sequence number, as in `recv_request_vote` in `src/consensus/aft/raft.h`.
The first property requires each voter to have received its own gossip; without this premise, `Tests/QuorumCommit.lean` exhibits a stale node opening by quorum.
The second requires a state in which every node's gossip equals `config.recovered`, and it also covers failover openings.

Each property has a `Witness` claim asserting that some valid trace or step satisfies its premises.
`Proofs/Witnesses.lean` proves all seven witnesses using concrete executions.
The full-gossip witness includes a failover opening.
`Tests/Witnesses.lean` applies each witness to its corresponding property, and `Tests/ProofCoverage.lean` requires an exported theorem for every claim.

Freshness is a necessary condition for election, not a definition of Raft commitment.
`update_commit` additionally requires a current-term signature replicated on a majority, and the Raft safety specification (`tla/consensus/ccfraft.tla`) is stated on log prefixes.
The model stores only the last signed TxID of each ledger, so this package does not prove committed-prefix preservation.
Liveness properties are out of scope.

## Trace validation

`DisasterRecovery/TraceValidation.lean` and the modules in `DisasterRecovery/TraceValidation/` check C++ runs recorded with the `CCF_RECOVERY_TRACE` environment variable set against `Model.transitionSystem`.
[`replayer/README.md`](replayer/README.md) describes the records, the reduction rules, where CI runs it, and what a successful replay does and does not show.

## Validation

The package's `lean-toolchain` is a symlink to [`../lean-toolchain`](../lean-toolchain), shared with the CCF Raft package.

Run the following commands from this directory:

```console
lake exe cache get
lake exe mk_all --check --module --lib DisasterRecovery
lake build --wfail --fail-fast
lake build CCF
lake lint
./replayer/check-fixtures.sh
lake check --inadvisably-no-sandbox
```

`--wfail` treats all build warnings, including `sorry`, as errors.
`--fail-fast` stops scheduling new build jobs after the first failure.
`lake lint` runs Lean's built-in linters.
The Lake package enables the complete `linter.extra` set (duplicated namespaces, unnecessary `<;>`, unreachable tactics, and unused decidability instances), plus `linter.missingDocs`, `linter.omit`, `linter.loopingSimpArgs`, `linter.redundantVisibility`, and `linter.unusedVariables.analyzeTactics`.
These supplement Lean's default checks, and linter findings fail validation.
The options are set in `lakefile.toml` so ordinary builds use them too; `lake lint` also runs the environment checks on the built declarations.
The opt-ins are explicit rather than `linter.all`, which would enable every optional linter registered by dependencies.
Lean's internal-module and collection-variable naming conventions, and its debugging-only `linter.tacticCheckInstances`, are not enabled.

The package also sets `autoImplicit = false`, requiring declaration headers to bind their parameters explicitly rather than silently introducing undeclared names.
This applies to ordinary Lake builds as well as CI.

The model, proofs, tests, and replayer use Lean's module system, as required by the Mathlib dependency.
Public imports preserve existing names and exports.
`@[expose] public section` keeps definitions used by cross-module proofs transparent; runtime-only helpers remain private.
`mk_all --module` generates the corresponding package-level import root.

Proofs that evaluate upstream implementations use narrowly scoped `import all` directives to retain access to those definitions.
The proof-coverage check also loads implementation metadata to distinguish checked theorems from axioms after module interface erasure.

`lake lint` also runs Mathlib's `runLinter` declaration-lint driver, including the slow checks, over every module imported by `CCF.lean`, `DisasterRecovery.lean`, and `replayer.Main`.
It lints our declarations rather than dependencies, and findings fail the command.
The package's default targets are the complete library and the replayer executable.
Canonical scenario and state-enumeration checks run with `#eval` when `Tests/CanonicalTests.lean` is built, and assertion failures fail the build.
Their runner is namespaced, leaving the replayer as the only `main` entrypoint so both targets can be checked together.

`lake check`, introduced in [Lean 4.35](https://lean-lang.org/doc/reference/4.35.0/releases/v4.35.0/), builds and exports all default targets, then rechecks the export with Lean's kernel.
It also checks axiom dependencies, rejecting any use of axioms other than `propext`, `Classical.choice`, and `Quot.sound`, so a separate axiom-audit dependency is unnecessary.
The checked targets include the complete library import root, canonical tests, and replayer, not just the exported property theorems.
These supplement the import and proof coverage checks and executable model and trace tests.
CI checks the package without sandbox isolation, using disk-backed temporary storage.
Build-time code must therefore be trusted; kernel rechecking and the axiom allowlist remain enabled.
The `--inadvisably-no-sandbox` flag also allows the check to build the shared modules directly from `../common`.
The Lean workflow runs formatting, linting, import-root, build, executable and kernel checks in one job, in that order.
Additional bundled checkers are not enabled.

`Tests/Architecture.lean` fails the build if `Properties.lean` imports a proof module or if a removed name is reintroduced.
See [Formatting](#formatting) for the [leanfmt](https://github.com/duckki/leanfmt) check.
To update a tool dependency without changing the toolchain, run `lake update --keep-toolchain <package>`.

## Formatting

Install Lean via [elan](https://lean-lang.org/install/) and run `lake exe cache get` from this directory before the first formatting check.
From the repository root, check every tracked `.lean` file:

```console
scripts/lean-format-checks.sh
```

To apply formatting fixes, run:

```console
scripts/lean-format-checks.sh -f
```

The script builds each package's imported modules and runs its pinned leanfmt dependency.
By default it checks both disaster recovery and CCF Raft; pass `disaster-recovery` to check only the recovery package and Lean files outside the Raft package.
The Lean CI workflow runs the same check before linting.
Files outside `lean/` are included; untracked files and downloaded dependencies are excluded.
Add new Lean files to Git before running the check.
