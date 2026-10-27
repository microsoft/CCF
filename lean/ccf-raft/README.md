# CCF-Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)), safety property statements and a timed liveness model.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).
The public liveness statement is `commit_liveness`: from a `StableState` snapshot, with no crashes, drops, successor nominations or configuration changes afterwards, the primary commits a request it holds within a time bound.
It is proved in [`CCFRaft/Proofs/Liveness`](CCFRaft/Proofs/Liveness), on top of the timed commit proof in [`CCFRaft/Proofs/Timed`](CCFRaft/Proofs/Timed); see [the liveness report](LIVENESS.md).

## Source map

| Area                                      | Source                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node state, log entries, log queries      | [`Model/NodeState.lean`](CCFRaft/Model/NodeState.lean)                                                                                                                                                                                                                                                  |
| Configurations, quorums, retirement       | [`Model/ClusterConfig.lean`](CCFRaft/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`)                                                                                                                                                                            |
| Messages                                  | [`Model/Messages.lean`](CCFRaft/Model/Messages.lean)                                                                                                                                                                                                                                                    |
| Protocol policy (one node's step)         | [`Model/Node.lean`](CCFRaft/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)                                                                                                                                                                                |
| Initial states and network composition    | [`Model.lean`](CCFRaft/Model.lean) (`initialNodeState`, `transitionSystem`)                                                                                                                                                                                                                             |
| Safety and liveness theorems, witnesses   | [`Properties.lean`](CCFRaft/Properties.lean)                                                                                                                                                                                                                                                            |
| Liveness events and packet identities     | [`Properties/Liveness/Model/Event.lean`](CCFRaft/Properties/Liveness/Model/Event.lean)                                                                                                                                                                                                                  |
| Recorded relational traces and models     | [`Properties/Liveness/Model/Trace.lean`](CCFRaft/Properties/Liveness/Model/Trace.lean) (`Model`, `Satisfies`, `Eventually`)                                                                                                                                                                             |
| Open world accessors and witness world    | [`Properties/Liveness/Model/World.lean`](CCFRaft/Properties/Liveness/Model/World.lean) (`HasProtocol`, `HasTime`, `HasLive`, `HasNetwork`), [`Properties/Liveness/Model/WitnessWorld.lean`](CCFRaft/Properties/Liveness/Model/WitnessWorld.lean) (`World`)                                              |
| Protocol model                            | [`Properties/Liveness/Model/Protocol.lean`](CCFRaft/Properties/Liveness/Model/Protocol.lean)                                                                                                                                                                                                            |
| Crash and absolute-time models            | [`Properties/Liveness/Model/Crash.lean`](CCFRaft/Properties/Liveness/Model/Crash.lean), [`Properties/Liveness/Model/Timing.lean`](CCFRaft/Properties/Liveness/Model/Timing.lean)                                                                                                                        |
| Packet ledger, delay constraint and sends | [`Properties/Liveness/Model/Delivery.lean`](CCFRaft/Properties/Liveness/Model/Delivery.lean), [`Properties/Liveness/Model/Packets.lean`](CCFRaft/Properties/Liveness/Model/Packets.lean)                                                                                                                |
| CCF scheduling assumptions                | [`Properties/Liveness/Model/Scheduling.lean`](CCFRaft/Properties/Liveness/Model/Scheduling.lean)                                                                                                                                                                                                        |
| Election deadlines and witness runs       | [`Properties/Liveness/Model/Timers.lean`](CCFRaft/Properties/Liveness/Model/Timers.lean) (`ElectionTimeouts`, `ElectionScheduling`), [`Properties/Liveness/Model/Policy.lean`](CCFRaft/Properties/Liveness/Model/Policy.lean) (`DuelWorld`, `Policy`, `run`)                                            |
| Public liveness import entry points       | [`Properties/Liveness/Model.lean`](CCFRaft/Properties/Liveness/Model.lean), [`Properties/Liveness/Assumptions.lean`](CCFRaft/Properties/Liveness/Assumptions.lean)                                                                                                                                      |
| Liveness starting snapshot                | [`Properties/Liveness/Assumptions/StableState.lean`](CCFRaft/Properties/Liveness/Assumptions/StableState.lean) (`StableState`)                                                                                                                                                                          |
| Supporting proofs and executions          | [`Proofs/`](CCFRaft/Proofs), with the commit-liveness proof in [`Proofs/Liveness/`](CCFRaft/Proofs/Liveness), [`Proofs/Leadership/`](CCFRaft/Proofs/Leadership), [`Proofs/Timed/`](CCFRaft/Proofs/Timed), [`Proofs/Replication/`](CCFRaft/Proofs/Replication) and [`Proofs/Duel/`](CCFRaft/Proofs/Duel) |
| Action-trace tests                        | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean)                                                                                                                                                                                                                                      |

Transition systems, the `CCF.Execution.Trace` and `CCF.Execution.Step` types shared by safety and liveness, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Liveness model components live under `Properties/Liveness/Model/` and are reexported by `Properties/Liveness/Model.lean`.
Short, single-declaration assumptions are defined directly in [`Properties/Liveness/Assumptions.lean`](CCFRaft/Properties/Liveness/Assumptions.lean).
Separate assumption modules are reserved for related groups of declarations or definitions exceeding 80 lines: [`StableLeader.lean`](CCFRaft/Properties/Liveness/Assumptions/StableLeader.lean), [`StableState.lean`](CCFRaft/Properties/Liveness/Assumptions/StableState.lean), [`Submitted.lean`](CCFRaft/Properties/Liveness/Assumptions/Submitted.lean), and [`Window.lean`](CCFRaft/Properties/Liveness/Assumptions/Window.lean).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Base actions are local inputs (including timeouts) or delivery of a queued message; the base protocol has no clock.
The optional liveness model records an initial world and a finite or infinite sequence of `CCF.Execution.Step W Event` values, each with explicit before-state, action and after-state.
`commit_liveness` quantifies over any world type `W` with the accessor instances it needs and uses the common `CCF.Execution.Trace W Liveness.Event`, independently of any transition system; its witness's trace is `Liveness.run {0} Proofs.Duel.Witness.policy sample` over `DuelWorld`.
`trace.stepAt` and `trace.stateAt` read the recording directly and return `Option`; state zero is the initial world and state `i + 1` is step `i`'s after-state.
The trace type links the initial world and adjacent recorded endpoints, including in finite and zero-step traces.
There is no replay or filtered protocol projection in this interface.

Each `Model W Event` is a TLA-style action: an initial-state predicate and a relation over a recorded step.
Validity against several models is plain conjunction; there is no composition operator, model ordering or variable ownership.
Models may constrain overlapping fields, and contradictory constraints simply admit fewer traces.
Accessor classes let models work with extensible world types while requiring only the fields they inspect.
Lean has no row types, so the open world is spelled as typeclass constraints; the closed `World S` in [`Properties/Liveness/Model/WitnessWorld.lean`](CCFRaft/Properties/Liveness/Model/WitnessWorld.lean) exists only for witnesses.
Scheduling adds no world variables.

Each public statement conjoins `Satisfies` for the protocol, timing, crash and delivery models inline; there is no bundled model predicate.
The protocol model `protocolModel config nodes` uses `Event.action` to execute local actions and deliveries in `Model.transitionSystem config nodes`; crash, drop and idle stutter in the protocol state.
The timing model permits any nondecreasing absolute time, advanced only by idle steps; every other event takes zero time.
The initial absolute time and live set are unrestricted.
The crash model directly projects to the existing `crashSystem`, requiring live actors and permanently removing crashed nodes.
Delivery requires only the receiver to be live, so a sender may crash after sending.
The delivery model starts with an empty pending ledger and zero issued packets; it tags each actual outgoing envelope with the next sequence number and the sending step's before-time as `sentAt`.
Delivery or drop must consume an existing occurrence before this step's outputs are added.
Delivery is FIFO with loss on each source-target channel, as CCF's channel nonce check enforces: a delivered packet is the oldest outstanding one on its channel, while drops are unrestricted.
Equal envelopes remain distinct transmissions, and an occurrence cannot be consumed twice or after a drop.
The optional `boundedDelayModel maxDelay` requires `0 <= maxDelay` and separately forbids an overdue pending packet to a live target; it permits drops, so it is weaker than an obligation to deliver.

`HeartbeatScheduling trace` and `SignatureScheduling trace` each take an `Option Real`: `none` requires eventual execution or the end of the obligation, and `some bound` also bounds that wait.
`CheckQuorumScheduling trace window` permits a quorum-check step-down only when some active configuration lacks a majority of the primary and peers whose AppendEntries responses, or the primary's own election, are less than `window` old; it constrains when the step-down may happen, not that it must.
`ElectionScheduling trace minimum jitter` takes two `Option Real` arguments and owns election-timeout validity through its `timeouts` component, `ElectionTimeouts trace minimum`.
Deadlines change only on resets and a node times out only once its deadline has passed; `some m` also draws each reset's deadline between `m` and `2 * m` after the reset, while `none` leaves that draw unconstrained.
Its `firing` component requires an eligible overdue node to time out eventually or cease being due, even with `jitter = none`; `some jitter` also bounds the wait from each recorded due state and, through `noOvershoot`, clock overshoot past its deadline.
It requires `HasTimers W`; `timingModel` alone governs clock advancement.
Proofs needing only the lower bound assume `ElectionTimeouts minimum`; the timing model then gives `ElectionSpacing minimum`, which `scheduling.spacing timing` derives from the combined predicate.
The heartbeat obligation is one send pass, a single `sendEntries` step, because CCF's `send_append_entries` runs under the consensus lock.
A pass sends single-term batches from the peer's send frontier through the primary's current log end; CCF also caps batches at `entries_batch_size`, and the model allows any split.
These are read-only predicates on the recorded trace, separate from model validity.
Heartbeat and signature scheduling, and the `firing` component of election scheduling, share `Scheduled trace bound Due Fires`, so a bounded obligation implies the unbounded one and is never vacuous on a finite or Zeno trace.
The background scheduling predicates, election spacing and timing bounds are in `Properties/Liveness/Model/Scheduling.lean`; combined election scheduling is in `Properties/Liveness/Model/Timers.lean`.
`Bounds` contains timing bounds only, not protocol configuration or node identities.

## Scope

Node join and snapshot installation are not modeled.
The timed commitment statement starts from a `StableState` snapshot: a live primary holding the request, every listed node live with the primary's term and log, and reconfiguration settled at the primary, meaning one active configuration and committed confirmation of every completed removal.
Other nodes need not have learned that completion, and no retirement-cleanup deadline is imposed.
From the snapshot it assumes no crashes, drops, successor nominations or configuration changes, and it derives, rather than assumes, that the primary stays primary until the request commits.
Elections, including how an execution reaches such a snapshot, are out of scope; see [the liveness report](LIVENESS.md#known-limitations).
Explicit real-time deadlines idealize the concrete tick-based timer, and the existing conservative `Bounds.electionTimeout` interpretation is unchanged.
`ElectionReset` accounts for represented CCF reset paths, including term adoption, regular-election starts, vote grants and quorum-check step-downs, while retaining message-handler guards and the same-term AppendEntries log-check distinction.

Like CCF's `recv_request_vote_unsafe`, the model refuses pre-votes while a primary is known, preventing a lagging follower from deposing a healthy primary.
This mirrors etcd's lease check and the Raft thesis's pre-vote leader check, but does not protect a primary from a lagging quorum.

## Validation

With the pinned Lean toolchain available, run from this directory:

```sh
lake exe cache get
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh ccf-raft
```

`lake check` builds the default target with compiler warnings, including `sorry`, treated as errors, before separately replaying the compiled proofs in Lean's kernel and rejecting nonstandard axioms.
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs explicit action traces from an initialized network: committing a client request, adding two nodes then electing a new primary and committing another request, and retiring a follower through committed confirmation at the leader.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
The retirement trace checks the new settlement predicate against pending membership changes, the lost commit trigger, and an appended but uncommitted confirmation.
These are regression examples, not exhaustive checking.
[`Tests/ElectionReset.lean`](CCFRaft/Tests/ElectionReset.lean) executes local protocol handlers and checks timer-reset classification for both reset and ignored/rejected-message cases.
`lake check` runs without sandboxing here, so build-time code must be trusted.
`CCFRaft.lean` reexports `Properties.lean` and its public imports transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Properties.lean` contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
Import `CCFRaft.Properties` and use `CCFRaft.Properties.<name>` for these declarations.
`Proofs/Direct/` establishes node-local commit invariants; `Proofs/Safety/` establishes the cross-node history invariant used for election safety and committed-log comparability.
`Proofs/Liveness/` proves `commit_liveness` from that invariant: `Proofs/Leadership/` keeps the primary stable through the commit window, `Proofs/Timed/` bounds the commit time within it, and `Proofs/Replication/` supplies replication and retirement facts; see [the liveness report](LIVENESS.md).
`Proofs/Witnesses.lean` and `Proofs/LivenessWitness.lean` supply concrete executions checked by the kernel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

## Future work

- Per-node clocks with bounded drift, instead of the one global `time`.
- Explicit `periodic` ticks, with a proof that CCF's tick-driven timer meets `ElectionTimeouts` rather than an assumption that it does.
- Tighter timing constraints and commit bound for `commit_liveness`; the proof's choices are not shown tight.
- A multi-node witness for `commit_liveness`, for example a manual liveness trace alongside [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean).
- Reaching a `StableState` snapshot, through election convergence and follower catch-up, and composing that with `commit_liveness` into one end-to-end statement.
- Message loss and minority crashes after the snapshot.
