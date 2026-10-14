# CCF Raft model

This package contains an executable Lean model of CCF Raft
(`src/consensus/aft/raft.h`), its safety properties, machine-checked proofs of
those properties, and a replayer that checks recorded `raft_driver` runs
against the model. The module layout follows the Lean module guide,
`lean/AGENT.md` on the `dr-rework` branch.

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
| Network composition                  | `CCFRaft/Model.lean`, `CCFRaft/Shared/`                  |
| Definitions used by the statements   | `CCFRaft/Properties/Utils.lean`                          |
| Proof implementations                | `CCFRaft/Proofs/`                                        |
| Executable checks                    | `CCFRaft/Tests/`                                         |
| Trace replay                         | `CCFRaft/Replay.lean`, `replay/`. See `replay/README.md` |

Human review covers the model, the property statements, the definitions they
use, and the theorem links in `Proof.lean`. The build and the axiom audit
verify the proof implementations under `Proofs/`, which `.gitattributes`
marks `linguist-generated`.

`CCFRaft/Shared/` is a copy of `DisasterRecovery/Shared/` from the
`dr-rework` branch, with the namespace renamed and `Effect` changed to
`StateT Outputs Option` so that a local step can fail when it is disabled.

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
their order; committing the transaction retains only the last of them. CCF
itself records at most one configuration per transaction.
`activeConfigurations config log commitIndex` retains the last committed
configuration and every pending one. `configurationMembers` takes the union
of any supplied configuration list.

Retirement queries use the same history: `retirementIndexInLog` finds the
first change from membership to absence. `firstLogIndexAfter` finds a matching
signature or retirement record strictly after a supplied index.
`retiredCommittedNodes` unions the nodes named by retirement effects in a
log; passing `log.take commitIndex` restricts it to committed records.
A node's stored `retiredCommittedIndex` is the first commit frontier that
covered its retirement record, not the record's own position.

`Model/Messages.lean` defines the AppendEntries and RequestVote packets
nodes exchange, including the pre-vote and vote-proposal variants, and the
term each one carries.

`Model/Node.lean` defines how a node behaves. `Local.step` handles one event: an
`Input` or a message delivered from a source node. The inputs are
`append entries` (a leader appends a nonempty batch in one step, applying each
transaction's effects in order as `raft.h` hooks do, then commits at once if no
other active member exists), `sendEntries destination endIndex` (the previous
index comes from the leader's `sentIndex`; an equal end is a heartbeat),
`timeout .election` or `timeout .checkQuorum`, and
`nominateSuccessor destination` (a leader may nominate any eligible peer other
than itself; the model does not restrict the destination by replication ranking). Commit is
internal: a current-term AppendEntries acknowledgement, a promotion with no
other active member, or such an append commits in the same step. Retirement
clears leadership and saves a one-shot nomination permission with the outgoing
leader's term and precommit eligible peers. A separate nomination input consumes
that permission; any other local event expires it. Retired nonleaders without
this permission cannot nominate. A promotion also sends an empty AppendEntries
to every eligible peer. It runs in `NodeEffect`, which records sent messages and can
fail. A disabled event fails, discarding any messages sent before the
failure. An enabled event returns the next node state and sends messages
through the `send` callback in `caps`. A node reads only its own state, the explicitly supplied
`InitialConfig` value, and the delivered message.

A message with a newer term moves the receiver to that term as a follower
before the receiver handles it, in the same step. Vote proposals never
advance a term, and only a leader reads the term of an AppendEntries
response, as in `raft.h`. A same-term AppendEntries request makes a candidate
or pre-vote candidate step down, then the node handles the request.
Elections follow `raft.h`: entering a pre-vote round or a candidacy votes for
self and, in the same step, sends a request to every other active member. A
vote or pre-vote that reaches a quorum promotes the node at once, inside the
step that counted it, including a self vote.
Every AppendEntries request is consumed. As in `raft.h`, a request whose
previous index is below the commit index, or one that conflicts with the log
of a node that may no longer roll back, is dropped without a response.

`Model.lean` runs one copy of `Local.step` per node with
`Shared/MultiNodeTransitionSystem.lean`. Every listed node starts in
`initialNodeState`: bootstrap members at `BOOTSTRAP_TERM`, with the initial
leader's log preloaded with the bootstrap configuration transaction (identifier
`default`) at `BOOTSTRAP_TERM` and every other log empty, all with commit index 0. Every other
node has no role at term 0. The network is a multiset of envelopes. A
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

Each property has a `Witness` claim asserting that some valid trace satisfies
its premises. `Proofs/Witnesses.lean` proves each witness with a concrete
execution that the kernel evaluates. `Tests/ProofCoverage.lean` requires an
exported theorem and a witness for every claim.

The proofs say nothing about liveness, fairness, or the C++ implementation.

## Proofs

All proofs concern `Model.transitionSystem` directly. `Proofs/Direct/`
proves node-local commit bounds, signature frontiers, and committed-log
growth. `NodeInvariant` lifts a predicate preserved by every local step to
every node of every reachable state.

The cross-node invariant is stated over `Model.State` in
`Proofs/Invariant/Facts.lean`. `Inv c` means that some proof-only joined set
`J` satisfies `StateInvariant c J`. This includes
`SystemInductiveInvariant c`, with vote, log, election, and
configuration-activation histories, parameterized by `J`. It also requires
distinct node-table keys, bootstrap members and envelope endpoints in `J`,
and nodes outside `J` to remain in `initialNodeState`.

`Proofs/Invariant/State.lean` defines the only total node accessor,
`nodeOf c n := (nodeState c n).getD (initialNodeState config n)`, and proves lookup
laws for the concrete node list. Messages in flight are the model's own
envelopes in `c.network`. Message histories use `(source, target, payload)`
keys whose payloads are the types in `Model.Local`. The joined set stays
separate from the concrete state and grows when a configuration names new
nodes.

`Proofs/Invariant/Preservation/` proves preservation under concrete node-list
replacements and envelope-list updates, split into modules for incremental
builds. `Internal.lean` applies these lemmas to all 16 inputs of `Local.act`.
`Receive.lean` composes `observeTerm`, same-term step-down, and the model's
message handlers. A delivery removes one envelope with `removeOne` and
appends the handler's replies.

`Proofs/Invariant/Reachable.lean` proves `reachable_inv` by induction over
the concrete local and delivery steps. `Safety.lean` derives leader
uniqueness and same-state committed-log agreement from the invariant.
`Proofs/CommittedLogs.lean` carries the earlier node's committed log to the
later state, then applies same-state agreement. This proves the trace-wide
`CommittedLogsPrefix` claim.

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
lake exe mk_all --check --lib CCFRaft
lake build --wfail
lake lint
lake exe canonical-checks
python3 -m unittest discover -s replay/tests -p 'test_*.py'
../../scripts/lean-format-checks.sh ccf-raft
```

`--wfail` treats `sorry` as an error. `lake lint` runs
[axiom-audit](https://github.com/leanprover-community/axiom-audit); only
`propext`, `Classical.choice`, and `Quot.sound` are permitted.
`Tests/Architecture.lean` fails the build if the model, the properties, or
the replayer import a proof module. The formatting check runs
[leanfmt](https://github.com/duckki/leanfmt), pinned in `lakefile.toml`, over
every tracked Lean file in this package. Pass `-f` before the package name to
apply fixes.
