# Lean disaster recovery model

This package contains a Lean model of CCF's recovery decision protocol
(`src/node/recovery_decision_protocol.cpp`), its safety properties, and
machine-checked proofs of those properties. [The Lean module guide](../AGENT.md)
describes the module layout.

## Contents

| Purpose                               | Location                                                |
| ------------------------------------- | ------------------------------------------------------- |
| Property statements                   | `DisasterRecovery/Properties.lean`                      |
| Proof of each property                | `DisasterRecovery/Proof.lean`, one theorem per property |
| Single-node protocol                  | `DisasterRecovery/Model/Local.lean`                     |
| Network composition                   | `DisasterRecovery/Model.lean`, `Shared/`                |
| Definitions used by the statements    | `DisasterRecovery/Properties/Utils.lean`                |
| Proof implementations                 | `DisasterRecovery/Proofs/`                              |
| Executable checks and concrete traces | `DisasterRecovery/Tests/`                               |

Human review covers the model, the property statements, the definitions they
use, and the theorem links in `Proof.lean`. The proof implementations under
`Proofs/` are verified by the build and the axiom audit and are marked
`linguist-generated` in `.gitattributes`.

## Model

`Model/Local.lean` defines one node. Its phases are gossiping, voting, opening,
joining, and open. It also models a timeout lane, retries, failover, and
restart. `Local.step` returns `none` for a disabled event. For an enabled event
it returns the next state and invokes the host's `send` and `notify` callbacks.
A rejected receive is an enabled step that emits a notification.
`Validation.accepted` and `Validation.rejected` represent the results of the
C++ quote and certificate checks. The model does not define that cryptography.

`Shared/MultiNodeTransitionSystem.lean` composes copies of one local protocol
into a message-passing network. Each step executes one node once, collects its
outputs with `Capabilities.record`, and appends its sends to the queue.
Delivery consumes any queued envelope, not only the first. Notifications are
not stored in the global state.

`Model.lean` supplies each node's recovered TxID and adds `Config.Valid` to the
initial-state predicate. The model records no history. The proofs reconstruct
sends and notifications by re-executing local steps.

## Properties

The local properties are invariants of `Local.step`. They hold for every node
state, not only reachable ones. Each quantifies a `LocalStep` record and
assumes `ValidStep`: re-executing the step yields exactly the recorded
after-state and outputs.

The global properties quantify a `GlobalTrace`, a list of states beginning
with the initial state. `trace.Valid` requires an initial first state and an
enabled action between each adjacent pair. `Trace.NotificationAt` states that
a step by `node` between states `i` and `i + 1` emitted a given notification.

`QuorumOpenerUnique` states that all `opening quorum` notifications in a trace
originate from one node.

`QuorumOpenPreservesCommit` and `FullGossipPreservesCommit` conclude that the
opener satisfies Raft's vote freshness check against a strict majority of the
recovered ledgers. `LogUpToDate` is that check, comparing view and then
sequence number, as in `recv_request_vote` in `src/consensus/aft/raft.h`. The
first property requires each voter to have received its own gossip; without
this premise, `Tests/QuorumCommit.lean` exhibits a stale node opening by
quorum. The second requires a state in which every node's gossip equals
`config.recovered`, and it also covers failover openings.

Each property has a `Witness` claim asserting that some valid trace or step
satisfies its premises. `Proofs/Witnesses.lean` proves all seven witnesses using
concrete executions. The full-gossip witness includes a failover opening.
`Tests/Witnesses.lean` applies each witness to its corresponding property,
and `Tests/ProofCoverage.lean` requires an exported theorem for every claim.

Freshness is a necessary condition for election, not a definition of Raft
commitment. `update_commit` additionally requires a current-term signature
replicated on a majority, and the Raft safety specification
(`tla/consensus/ccfraft.tla`) is stated on log prefixes. The model stores only
the last signed TxID of each ledger, so this package does not prove
committed-prefix preservation. Liveness properties are out of scope.

## Validation

Run the following commands from this directory:

```console
lake exe cache get
lake exe mk_all --check --lib DisasterRecovery
lake build --wfail
lake lint
lake exe canonical-checks
```

`--wfail` treats `sorry` as an error. `lake lint` runs
[axiom-audit](https://github.com/leanprover-community/axiom-audit); only
`propext`, `Classical.choice`, and `Quot.sound` are permitted.
`Tests/Architecture.lean` fails the build if `Properties.lean` imports a proof
module or if a removed name is reintroduced. See [Formatting](#formatting) for
the [leanfmt](https://github.com/duckki/leanfmt) check.
To update a tool dependency without changing the toolchain, run
`lake update --keep-toolchain <package>`.

## Formatting

Install Lean via [elan](https://lean-lang.org/install/) and run
`lake exe cache get` from this directory before the first formatting check.
From the repository root, check every tracked `.lean` file:

```console
scripts/lean-format-checks.sh
```

To apply formatting fixes, run:

```console
scripts/lean-format-checks.sh -f
```

The script builds the model's imported modules and runs the pinned leanfmt
dependency. The Lean CI workflow runs the same check after the proof checks.
Files outside `lean/` are included; untracked files and downloaded dependencies
are excluded. Add new Lean files to Git before running the check.
