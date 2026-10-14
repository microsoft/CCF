# CCF Raft model

This package contains an executable Lean model of CCF Raft
(`src/consensus/aft/raft.h`), safety property statements and proof
implementations, and a replayer that checks recorded `raft_driver` runs
against the model.

```text
raft scenario -(raft_driver)-> raw stdout
              -(Python reduction)-> actions and observations
              -(Lean replay)-> success or discrepancy
```

## Contents

| Purpose                              | Location                                                 |
| ------------------------------------ | -------------------------------------------------------- |
| Property statements                  | `CCFRaft/Properties.lean`                                |
| Proof of each property               | `CCFRaft/Proof.lean`, one theorem per property           |
| Node state, log entries, log queries | `CCFRaft/Model/NodeState.lean`                           |
| Membership configurations            | `CCFRaft/Model/ClusterConfig.lean`                       |
| Messages between nodes               | `CCFRaft/Model/Messages.lean`                            |
| Single-node protocol                 | `CCFRaft/Model/Node.lean`                                |
| Network composition                  | `CCFRaft/Model.lean`, `ccf_common` (`CCF.*`)             |
| Definitions used by the statements   | `CCFRaft/Properties/Utils.lean`                          |
| Proof implementations                | `CCFRaft/Proofs/`                                        |
| Executable checks                    | `CCFRaft/Tests/`                                         |
| Trace replay                         | `CCFRaft/Replay.lean`, `replay/`. See `replay/README.md` |

Human review covers the model, the property statements, the definitions they
use, and the theorem links in `Proof.lean`. The build and the axiom audit
verify the proof implementations under `Proofs/`, which `.gitattributes`
marks `linguist-generated`.

The `ccf_common` dependency provides transition systems, traces,
output-recording capabilities, and network composition through the `CCF`
namespace. It is pinned to the `lean/common` Git subdirectory at commit
`cc22c58d61e628b90f1f5b49194c7e6722f1ec2c`; no package-local Shared copy is
maintained. Its `Effect` is `StateT Outputs Option`, so a disabled local step
fails without retaining outputs. The package uses Lean and Mathlib 4.35.

## Model

`Model/NodeState.lean` defines a node's state, log entries, and pure queries
over a log, such as `termAt` and `maxCommittableIndex`. An entry is either a
signature or a transaction with an identifier and an ordered list of
`TransactionEffect`s: a `reconfiguration` or a `retiredCommitted` record. An
ordinary transaction has no effects, and a signature cannot carry any.
`Model/ClusterConfig.lean` defines the `InitialConfig`, the membership
configurations recorded in a log, node-state initialization, and the
node-state queries that depend on configurations.

`configurationHistory config log` includes initial membership at index zero
and each reconfiguration effect at its transaction's one-based log position.
Several configuration effects in one transaction share that index and keep
their order; once they are committed, only the last of them remains active.
`activeConfigurations config log commitIndex` retains the last committed
configuration and every pending one. `configurationMembers` takes the union
of any supplied configuration list.

Retirement queries use the same history: `retirementIndexInLog` finds the
first change from membership to absence. `firstLogIndexAfter` finds a matching
signature or retirement record strictly after a supplied index.
`retiredCommittedNodes` unions the nodes named by retirement effects in a
log; passing `log.take commitIndex` restricts it to committed records.
`NodeState.retirementCompletedNodes` identifies removed peers whose removal
is committed but whose final retirement record is not yet committed.
`NodeState.retirement` derives the retirement index, following signature and
membership phase from the current log and commit frontier, so rollback requires
no metadata refresh. Only `retiredCommittedIndex` is stored: it remembers the
first commit frontier that covered the retirement record, not the record's
own position. `NodeState.commitThrough` sets the frontier and preserves
that historical value.

`Model/Messages.lean` defines the AppendEntries and RequestVote packets
nodes exchange, including the pre-vote and vote-proposal variants, and the
term each one carries.

`Model/Node.lean` defines how a node behaves. `Node.step` handles one event: an
`Input` or a message delivered from a source node. The inputs are
`append entries` (a leader appends a nonempty batch in one step, applying each
transaction's effects in order as `raft.h` hooks do, then attempts to advance
commit), `sendEntries destination endIndex` (the previous index comes from the
leader's `sentIndex`; an equal end is a heartbeat),
`timeout .election` or `timeout .checkQuorum`, and
`nominateSuccessor` (a leader internally selects the eligible peer with highest
replication progress, then latest active configuration membership, then highest
node ID). Commit is internal: a current-term AppendEntries acknowledgement,
promotion, or append runs the same quorum-based commit calculation in its own
step. A current-term signature can commit when a majority of every active
configuration has reached it, including the singleton case. Retirement
nominates inside the committing step using the precommit eligible peers and
configuration view, then clears leadership. A standalone nomination is enabled
only for a leader; it sends nothing if no eligible peer exists. A promotion
also sends an empty AppendEntries to every eligible peer. Each event runs in
`NodeEffect`, which records sent messages and can fail. A disabled event fails,
discarding any messages sent before the failure. An enabled event returns the
next node state and sends messages through the `send` callback in `caps`.
Timeouts are logical events, not a model
of elapsed time or acknowledgement clocks; `checkQuorum` represents a failed
quorum check. A node reads only its own state, the explicitly supplied
`InitialConfig` value, and the delivered message.

`eligiblePeers` reconstructs peers from active configurations and completed
retirements. Unlike CCF's persistent peer inventory, it does not retain peers
whose introduction was rolled back.

Except for vote proposals and AppendEntries responses delivered to
nonleaders, a newer-term message moves the receiver to that term as a follower
before handling it, in the same step. A pre-vote round starts without
incrementing the term, but newer-term pre-vote messages can still advance the
receiver's term, as in `raft.h`. A same-term AppendEntries request makes a
candidate or pre-vote candidate step down, then the node handles the request.
AppendEntries ACKs count only in the leader's current term. A log-mismatch
NACK instead carries the term of a possible matching log position, not
necessarily the sender's current election term. A lower-term NACK can
therefore rewind `sentIndex`, bounded below by `matchIndex`, without counting
as an acknowledgement.

Elections follow `raft.h`: entering a pre-vote round or a candidacy votes for
self and can synchronously advance on a self-quorum. Otherwise a pre-vote
round broadcasts pre-vote requests; candidacy broadcasts regular vote
requests even if the self-vote already promoted it. Requests go to every
other active member. A vote or pre-vote that reaches a quorum advances the
election inside the step that counted it.

Every AppendEntries request is consumed. A stale-term request or a
previous-entry mismatch gets a NACK. Once those checks pass, a request whose
previous index is below the commit index, or one that conflicts with the log
of a node that may no longer roll back, is dropped without a response.

`Model.lean` runs one copy of `Node.step` per node with
`CCF.MultiNodeTransitionSystem`. Every listed node starts in
`initialNodeState`: bootstrap members at `BOOTSTRAP_TERM`, with the initial
leader's log preloaded with the bootstrap configuration transaction (identifier
`default`) at `BOOTSTRAP_TERM` and every other log empty, all with commit
index 0. Listed nonbootstrap nodes have no role at term 0. The network is a
multiset of envelopes. A
delivery consumes any queued envelope, so the model reorders messages, and an
envelope that is never delivered is a dropped message.

Nodes share no state except the network. A leader may add any node to a
configuration, and client transaction identifiers need not be unique.

## Properties

Each claim quantifies every node and transaction identifier type, every
`InitialConfig` value, every node list, and every valid trace of
`Model.transitionSystem`.

- `ElectionSafety`: no two distinct nodes lead in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are
  prefix-comparable, whichever nodes and states they come from. Agreement
  within one state and `CommittedLogAppendOnlyProp` in
  `tla/consensus/ccfraft.tla` together imply it.
- `CommittedFrontierIsSignature`: every positive commit index points to a
  signature.

Each property has a `Witness` claim exhibiting a nontrivial valid execution.
The election witness has two distinct leaders without requiring equal terms;
it is not a witness to the safety property's entire antecedent.
`Proofs/Witnesses.lean` proves the witnesses with concrete executions checked
by the kernel. `Tests/ProofCoverage.lean` requires an exported theorem for
every claim and a witness claim for every property.

The proofs say nothing about liveness, fairness, or the C++ implementation.

## Proofs

The proofs target `Model.transitionSystem` directly. `Proofs/Direct/`
contains node-local commit bounds, signature frontiers, and committed-log
growth proofs. `NodeInvariant` lifts a predicate preserved by every local step
to every node of every reachable state.

The cross-node invariant is being replaced to cover the current four
composite inputs and multiple ordered configuration effects at one log index.
The legacy tree under `Proofs/Invariant/` was written for the earlier
fine-grained inputs and does not yet build against the current model.
The replacement and migration of the top-level election-safety and
committed-log-prefix proofs are not complete. The full package build and
axiom audit therefore remain required; successful model or direct-helper
builds alone do not establish these properties.

`Proof.lean` links the property statements to their proof implementations.
The legacy invariant modules are to be removed only after their required
guarantees and users have been migrated.

[`scripts/invariant-dependencies.lean`](scripts/invariant-dependencies.lean)
reports the invariant declarations in the exported proofs' kernel dependency
closure. It supports removal of unused proof lemmas.

## Trace validation

A successful replay shows that the reduced execution satisfies the model's
guards and the selected observations. It does not show that the reduction
rules describe every C++ execution. Review those rules against the C++ event
locations they name.

Build `raft_driver` with tracing, then run the suite:

```sh
cmake -S ../.. -B ../../build -DCCF_RAFT_TRACING=ON
cmake --build ../../build --target raft_driver
lake build ccfraft-replay
python3 replay/run_scenarios.py ../../build/raft_driver --output ../../build/raft-replay/validation
```

The runner captures every file under `tests/raft_scenarios`, reduces it, and
replays it. Any capture error, unsupported event, disabled action, or
observation mismatch fails the run. It continues through the inventory and
writes `summary.json`.

## Validation

Run the following commands from this directory:

```sh
lake exe cache get
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake check --inadvisably-no-sandbox
lake exe canonical-checks
python3 -m unittest discover -s replay/tests -p 'test_*.py'
../../scripts/lean-format-checks.sh ccf-raft
```

`--wfail` treats `sorry` as an error. `lake lint` runs Lake's built-in linter.
`lake check` rechecks declarations with Lean's kernel; only `propext`,
`Classical.choice`, and `Quot.sound` are permitted. The command above disables
build sandboxing, so it does not establish trustworthy isolation of the build
process.
`Tests/Architecture.lean` fails the build if the model, the properties, or
the replayer import a proof module. The formatting check runs
[leanfmt](https://github.com/duckki/leanfmt), pinned in `lakefile.toml`, over
every tracked Lean file in this package. Pass `-f` before the package name to
apply fixes.
