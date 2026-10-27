# Liveness of the CCF-Raft model

[`Properties.lean`](CCFRaft/Properties.lean) states one liveness theorem, `commit_liveness`, and its witness, `commit_liveness_witness`.
Both are proved, by `Proofs.Liveness.commit_liveness` in [`Proofs/Liveness/MinimalCommit.lean`](CCFRaft/Proofs/Liveness/MinimalCommit.lean) and `Proofs.Liveness.MinimalWitness.commit_liveness_witness` in [`Proofs/Liveness/MinimalWitness.lean`](CCFRaft/Proofs/Liveness/MinimalWitness.lean).
`lake check` rejects proofs that depend on nonstandard axioms; see [the README](README.md#validation).
This report explains the statement, its premises and its witness, and records the model decisions behind them.

## The statement

`commit_liveness` bounds the time to commit a request, measured from one snapshot of an execution.
At index `start`, `leader` is a settled primary holding `request`, and every listed node is live and has its term and log (`Liveness.StableState`).
If, from `start` onward, nothing crashes, no packet is dropped, no successor is nominated and no configuration change is appended, then at some index within `committedWithin bounds maxDelay` of `start` the request is in the leader's committed log.

The theorem chooses two functions of the timing bounds `bounds` and the maximum message delay `maxDelay`:

- `timeoutConstraints bounds maxDelay`, a premise that the election timeout is long enough.
  The theorem also states that it is not vacuous: whatever the other bounds and the delay, every large enough election timeout meets it.
- `committedWithin bounds maxDelay`, the time within which the request commits.

Neither depends on the trace, the configuration, the number of nodes or the request.
Write `H`, `S` and `E` for `bounds.heartbeatInterval`, `bounds.signatureInterval` and `bounds.electionTimeout`, `d` for `maxDelay`, and `H'` for `max H 0`.
The proof chooses `11 * d + 7 * H' < E / 2` and `Proofs.Timed.commitDuration bounds d 0`; see [timing constants](#timing-constants).

The statement does not assume that the leader stays primary, or that the term stays quiet, after `start`.
The proof derives both for as long as the commit takes.

## Premises

Each premise models CCF, limits the scope, or is assumed by the proof; the table says which.
The counterexamples are prose arguments, not checked in Lean.

| Premise                                                                                                    | Why                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Satisfies` for `protocolModel config nodes`, `timingModel`, `crashModel` and `deliveryModel config nodes` | They define an execution of the existing protocol with absolute time, crashes and a packet ledger; see [execution and transport](#execution-and-transport).                                                                                                                              |
| `config`, and every configuration appended anywhere in the trace, name only nodes in `nodes`               | Only listed nodes have state, and `StableState` constrains only listed nodes. With configuration `{L, X}` and `X` unlisted, `X` never acknowledges, so nothing uncommitted at `start` commits.                                                                                           |
| `TimeDiverges trace`                                                                                       | Physical: real time does not stop. It also excludes finite traces. Without it, the primary can repeat send passes at one instant forever; bounded delay only stops time from passing a packet's deadline, so nothing need be delivered, and nothing commits.                             |
| `boundedDelayModel maxDelay`                                                                               | Without a delay bound, AppendEntries may arrive after any fixed time, so no commit time exists.                                                                                                                                                                                          |
| `HeartbeatScheduling (some H)`                                                                             | CCF sends to every peer each time `request_timeout` elapses (`Aft::periodic`). Without it, the primary need never send the signature that covers the request. If the primary could wait longer than half an election timeout between heartbeats, followers could time out and depose it. |
| `SignatureScheduling (some S)`                                                                             | CCF signs every `sig_ms_interval` while entries are unsigned. Without it, a stable, reliable execution may never commit because it never signs.                                                                                                                                          |
| `CheckQuorumScheduling E`                                                                                  | CCF steps down only when a configuration lacks recent acknowledgements. Without it, the protocol's quorum-check step-down is unconstrained, so the primary may step down at `start`, before the request commits, and elections may then duel forever.                                    |
| `ElectionScheduling (some (E / 2)) none`                                                                   | CCF draws each timeout between half and all of `election_timeout`. Without the lower end, any node may time out at any time and depose the primary. The proof uses only the `timeouts` component, `ElectionTimeouts`.                                                                    |
| `timeoutConstraints bounds maxDelay`                                                                       | Assumed by the proof; see [timing constants](#timing-constants).                                                                                                                                                                                                                         |
| `StableState trace start bounds nodes leader request`                                                      | The starting snapshot; see [the starting snapshot](#the-starting-snapshot).                                                                                                                                                                                                              |
| No crash from `start`                                                                                      | Scope. If the leader crashes at `start`, it takes no further step, so a request not committed at `start` never commits there.                                                                                                                                                            |
| No drop from `start`                                                                                       | Scope. Drops are the model's only message loss, and dropping every packet from `start` prevents any further commit. The statement assumes no loss rather than fair-loss links.                                                                                                           |
| No successor nomination from `start`                                                                       | Scope: a nominated successor starts an election for the next term.                                                                                                                                                                                                                       |
| No configuration change appended from `start`                                                              | Scope: the proof fixes one configuration; a change appended after `start` may remove the primary or add nodes that must catch up.                                                                                                                                                        |

## The starting snapshot

`Liveness.StableState trace start bounds nodes leader request`, in [`Properties/Liveness/Assumptions/StableState.lean`](CCFRaft/Properties/Liveness/Assumptions/StableState.lean), fixes the recorded state at index `start`.
It does not assert that the snapshot persists.
Its conjuncts are assumed by the proof; this report gives no counterexample showing that each is needed.

| Conjunct                                                                                                                 | Reason                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `start` names a recorded state, in which `leader` exists, is live and is primary                                         | The theorem is about an existing primary; elections are out of scope.                                                                                                                                         |
| `HasRequest leaderState.log request`                                                                                     | The request is in the leader's log, and so in every listed node's log, but need not be committed or covered by a signature. Submission is out of scope.                                                       |
| `ReconfigurationSettled leaderState`: one active configuration, and every completed removal has a committed confirmation | The commit argument fixes one configuration, and settlement rules out a primary left alone with a committable signature; see [a lost commit trigger](#a-lost-commit-trigger).                                 |
| Neither the leader nor any member of its active configurations was ever removed (`retirementIndexInLog` is `none`)       | From the definition's comment: a confirmed retirement outlasts a later re-addition, so such a node retires again once its commit index passes the old confirmation, forgets the primary and grants pre-votes. |
| No pending `proposeRequestVoteRequest` of the leader's term                                                              | An earlier nomination still in flight would make its target campaign for the next term, which the no-nomination premise excludes only from `start`.                                                           |
| Every listed node exists, is live, and has the leader's term and log                                                     | No node has a newer term, and no node lags, so the commit time is `commitDuration` with no backlog; see [a lagging follower deposes the primary](#a-lagging-follower-deposes-the-primary).                    |
| Every listed node other than the leader is a follower that knows the primary (`primaryKnown`)                            | None is campaigning, and none grants a pre-vote.                                                                                                                                                              |
| Every follower's election deadline is at least `E / 2` after `start`                                                     | No follower times out within `E / 2` of `start` (`timeout_late`); by then, every pre-vote grant sent before `start` has been delivered, and acknowledgements after `start` have reset its timer.              |
| The primary had an acknowledgement reset (`AckReset`) for every follower within `H` before `start` (`AckedAfter`)        | The quorum check counts acknowledgements from before `start`; with older ones, `CheckQuorumScheduling` may let the primary step down soon after `start`.                                                      |

## Proof outline

1. `commit_minimal` takes as anchor the primary and the members of the latest configuration in its log at `start`; the configuration premises put the anchor inside `nodes` ([`MinimalConfig.lean`](CCFRaft/Proofs/Liveness/MinimalConfig.lean)).
2. `minimal_good` ([`MinimalGood.lean`](CCFRaft/Proofs/Liveness/MinimalGood.lean)) turns the premises from `start` onward into a good period among the listed nodes (`GoodBase`), and `timeout_late` shows that no follower times out within `E / 2` of `start`.
3. `minimal_engine` ([`MinimalEngine.lean`](CCFRaft/Proofs/Liveness/MinimalEngine.lean)) shows that the anchor, starting from `MinInv`, is an `AnchorEngine` for `E / 2`: the term stays quiet among the listed nodes, and the anchor keeps knowing the primary, until an anchor node other than the primary times out.
   Every node keeps a plain extension of the primary's starting log, so every quorum a node can count includes a member of the anchor, and anchor nodes refuse pre-votes.
   `no_check_quorum` ([`MinimalAcks.lean`](CCFRaft/Proofs/Liveness/MinimalAcks.lean)) uses the acknowledgement conjunct of `StableState` to rule out quorum-check step-downs.
4. `stable_window_catchup_engine` ([`Proofs/Leadership/CatchUp.lean`](CCFRaft/Proofs/Leadership/CatchUp.lean)) turns the engine into a `StableWindow` of length `commitDuration bounds d 0`.
   A follower acknowledges only an AppendEntries that passed its log check, which reset its timer (`reset_of_ack`), and each anchor node acknowledges within `ackBound d H' 0 + H' + d` of every point of the window (`acks_before_timeout`); the timing constraint puts that below `E / 2`, so `recent_reset` rules out its timeout.
5. `synced_window` and `settled_window` ([`MinimalSynced.lean`](CCFRaft/Proofs/Liveness/MinimalSynced.lean)) show that every listed node's log stays a plain extension of the primary's starting log, and that reconfiguration stays settled.
6. `commit_of_stable` ([`Minimal.lean`](CCFRaft/Proofs/Liveness/Minimal.lean)) applies `Proofs.Timed.commit_within_duration`: a covering signature appears within `max S 0` (`signed_within`), and `quorum_commits` commits it within two more acknowledgement bounds.

## Timing constants

Keep the bounds abstract.
They are bounds on real time, not CCF's configuration values.
`H` bounds the time a primary takes to finish a due heartbeat send pass; CCF sends once `request_timeout` has elapsed, checked on each `periodic` tick, so `H` must cover `request_timeout`, the tick delay, and the work of issuing every batch through the current log end.
`S` bounds the time a primary with unsigned entries takes to sign; CCF signs once `sig_ms_interval` elapses, checked on each tick.
`E / 2` bounds from below the time from a timer reset to a timeout; CCF draws a timeout between half and all of `election_timeout` (`restart_election_timeout`), but counts it in ticks on the node's own clock, and the first tick after a reset also counts the time before it.
So `E` must be at most `election_timeout` minus twice the tick interval, and less if node clocks drift.
With those choices, the scheduling premises should admit every CCF execution in which the host ticks on time; this is argued from the code, not proved.

The proof's timing constraint, `11 * d + 7 * H' < E / 2`, is `ackBound d H' 0 + H' + d < E / 2`, where `ackBound d H' 0 = 10 * d + 6 * H'` is the time within which a follower with no backlog acknowledges ([`Proofs/Timed/Acks.lean`](CCFRaft/Proofs/Timed/Acks.lean)).
It keeps every anchor node's timer reset more often than the shortest reset-to-timeout time.
It also implies `12 * d + 8 * H' < E`, which `no_check_quorum` needs to keep acknowledgements younger than the quorum-check window.
The proof's commit time, `commitDuration bounds d 0 = max S 0 + 2 * max (ackBound d H' 0) 0`, allows `max S 0` for a covering signature, one `ackBound` for every member of a live quorum to acknowledge it, and a second for one more acknowledgement, which commits it ([`Proofs/Timed/Quorum.lean`](CCFRaft/Proofs/Timed/Quorum.lean)).
Neither constant is shown tight.

## The witness

`commit_liveness_witness` shows that the premises of `commit_liveness` other than `timeoutConstraints` hold together, for every `bounds` with `0 <= S` and every `0 <= maxDelay`.
It holds for every election timeout, so with the non-vacuity conjunct of `commit_liveness`, which changes only the election timeout, every premise is satisfiable.
Its execution is a one-node service: node 0 is the primary of configuration `{0}` throughout, appends request `10` and a signature at time zero, and then idles forever while time advances; `start` is index 1.
Its trace is `Liveness.run {0} Proofs.Duel.Witness.policy sample` over `Liveness.DuelWorld`, with every draw zero.
The execution is in [`Proofs/LivenessWitness.lean`](CCFRaft/Proofs/LivenessWitness.lean), and the premise lemmas are in [`Proofs/Liveness/MinimalWitness.lean`](CCFRaft/Proofs/Liveness/MinimalWitness.lean) and [`Proofs/Duel/Witness.lean`](CCFRaft/Proofs/Duel/Witness.lean).

The request is already committed at `start`, and with one node the per-follower conjuncts of `StableState` hold trivially, so the witness exercises no replication, acknowledgement or timer.
It shows that the premises are consistent, not that they hold together in a multi-node execution.
The canonical traces in [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean) exercise multi-node commitment and reconfiguration, but are not checked against the premises.

## Known limitations

- `committedWithin` is existential, and neither the proof's choice nor the timing constraint is shown tight.
- Stability is assumed only at the snapshot.
  Reaching it, by an election, follower catch-up, reconfiguration or retirement cleanup, is out of scope, and so is election convergence.
- From `start`, the execution has no crashes and no message loss; the statement does not cover a minority crashing or lossy links.
- The timer model is a precondition, not a refinement of CCF's tick-driven timer; the `ElectionTimeouts` docstring lists the differences.
- Time is one global clock; there are no per-node clocks or drift.
- The witness is a one-node execution.
- The proof relies on nodes that know the primary refusing pre-votes, which CCF does only since #8639; see [a lagging follower deposes the primary](#a-lagging-follower-deposes-the-primary).

## Execution and transport

The liveness definitions use a fully recorded relational trace over the existing multi-node protocol.
This is a TLA-style explicit-state formulation, not a replacement Raft algorithm.
`CCF.Execution.Trace W Event`, from the common package, records an initial world and a finite or infinite sequence of `CCF.Execution.Step W Event` values, each with explicit before-state, event and after-state.
`trace.stepAt i` reads step `i`, and `trace.stateAt 0` is the initial world while `trace.stateAt (i + 1)` is step `i`'s after-state; both return `none` past the end of a finite trace.
The trace type requires the first step to start at the initial world and each step to start where its predecessor ended.
An event, in [`Properties/Liveness/Model/Event.lean`](CCFRaft/Properties/Liveness/Model/Event.lean), is a local input, a delivery, a drop, a crash or an idle step.

A `Model W Event`, in [`Properties/Liveness/Model/Trace.lean`](CCFRaft/Properties/Liveness/Model/Trace.lean), is an initial predicate and a relation on recorded steps, and `Satisfies trace model` requires both.
Satisfying several models is plain conjunction; there is no composition operator, model ordering or variable ownership.
Models are generic in the world `W` and request only the accessors they inspect: `HasProtocol`, `HasTime`, `HasLive` and `HasNetwork` in [`Properties/Liveness/Model/World.lean`](CCFRaft/Properties/Liveness/Model/World.lean), and `HasTimers` in [`Properties/Liveness/Model/Timers.lean`](CCFRaft/Properties/Liveness/Model/Timers.lean).
`commit_liveness` quantifies over every such `W`.

| Model                        | Initial predicate                                                  | Next relation                                                                                                                                                                                                |
| ---------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `protocolModel config nodes` | `system.init (proto w)`                                            | Execute the event's action in `system`, or preserve `proto` for crash, drop and idle.                                                                                                                        |
| `timingModel`                | `True`                                                             | `time before <= time after`, with equality unless the event is idle.                                                                                                                                         |
| `crashModel`                 | `crashSystem.init (live w)`                                        | `crashSystem.step (live before) event = some (live after)`.                                                                                                                                                  |
| `deliveryModel config nodes` | `pending w = [] /\ issued w = 0`                                   | Consume an existing packet for delivery or drop, delivering only the oldest outstanding packet on its channel; append this step's actual outgoing packets with fresh sequence numbers, and advance `issued`. |
| `boundedDelayModel maxDelay` | `0 <= maxDelay`, and no pending packet to a live target is overdue | No pending packet to a live target was sent more than `maxDelay` before the after-state's time.                                                                                                              |

Here `system` is `Model.transitionSystem config nodes`.
`Proofs.Liveness.Admissible.reachable` shows that every recorded protocol state is reachable in that system, so the safety invariants apply.

The protocol model, in [`Properties/Liveness/Model/Protocol.lean`](CCFRaft/Properties/Liveness/Model/Protocol.lean), executes local inputs and deliveries with the unchanged `Model.transitionSystem` step.
The timing model, in [`Properties/Liveness/Model/Timing.lean`](CCFRaft/Properties/Liveness/Model/Timing.lean), permits any initial absolute time; only idle steps advance time, and every other event takes zero time, so a step happens at its before-time.
Without that, a single-node primary could sign, and so commit, the request in a step that also advances the clock past `committedWithin`, and no state within the bound would record the commit.
The crash model, in [`Properties/Liveness/Model/Crash.lean`](CCFRaft/Properties/Liveness/Model/Crash.lean), requires live actors and permanently removes crashed nodes; there is no same-identity restart, consistent with the [CCF consensus model](../../doc/architecture/consensus/index.rst).
Deliveries require only a live receiver, so a message sent before its sender crashes can still arrive.

The delivery model, in [`Properties/Liveness/Model/Delivery.lean`](CCFRaft/Properties/Liveness/Model/Delivery.lean), tags each actual outgoing envelope with the next sequence number and with `sentAt`, the sending step's before-time.
Delivery and drop consume an outstanding packet before this step's outputs are registered, rejecting fabrication, early consumption and reuse, including delivery after a drop.
Equal envelopes remain distinct transmissions.
Each source-target channel is FIFO with loss (`Event.InOrder`): a delivered packet is the oldest outstanding packet on its channel, and drops are unrestricted, so a packet overtakes an earlier one only if that one is lost.
This matches CCF's node-to-node channels, whose receivers reject any nonce that is not above the last one received (`Channel::decrypt` in [`src/node/channels.h`](../../src/node/channels.h)).
Without FIFO order, clients could append `k` entries after `start`, before the signature that covers the request, and the primary could send them to a follower as single-entry AppendEntries that arrive in reverse order.
Every batch except the earliest arrives before the entry it extends and is rejected, so the follower gains one entry per round trip, and the commit time grows with `k`, whereas `committedWithin` does not depend on it.
Drops are ghost events: the base protocol's network keeps a dropped envelope, but its tagged occurrence cannot be delivered.
`SentAt trace index packet` holds when the packet first appears in the ledger after step `index`.
`boundedDelayModel` stores no deadlines and permits drops, so it is weaker than an obligation to deliver.
`Proofs.Liveness.Admissible.consumed_within` shows that `TimeDiverges` and bounded delay together consume every outstanding packet within `maxDelay`, unless its target crashes.

No synchronized physical clocks, finite state-space bound or executable decision procedure for trace validity is assumed.
Joining and snapshot installation remain outside the underlying model.

## Scheduling constraints

CCF's background tasks are stated as read-only trace predicates in [`Properties/Liveness/Model/Scheduling.lean`](CCFRaft/Properties/Liveness/Model/Scheduling.lean), separate from model validity.
`HeartbeatScheduling` and `SignatureScheduling` take an `Option Real`: `none` requires eventual execution or the end of the obligation, and `some bound` also bounds that wait.
Both use `Scheduled trace bound Due Fires`: whenever `Due` holds, it later ceases or `Fires` runs, from a state within the bound, and a due obligation must resolve before a finite execution ends.
`commit_liveness` uses the bounded forms, since its commit time depends on them.

- A heartbeat obligation is one send pass, a single `sendEntries` step, because CCF's `send_append_entries` runs under the consensus lock.
  A pass sends single-term batches from the peer's send frontier through the primary's current log end; CCF also caps batches at `entries_batch_size`, and the model allows any split.
- A signature is due while the primary has unsigned entries or its latest signature is from an earlier term (`SignatureDue`).
- `CheckQuorumScheduling window` lets a primary step down on a quorum check only when some active configuration lacks a majority of itself and peers with an acknowledgement reset (`AckReset`) less than `window` earlier.
  It constrains when the step-down may happen, not that it must.
- `ElectionScheduling minimum jitter`, in [`Properties/Liveness/Model/Timers.lean`](CCFRaft/Properties/Liveness/Model/Timers.lean), gives each node a real-time election deadline and has components `timeouts`, `firing` and `noOvershoot`.
  Its `timeouts` component, `ElectionTimeouts minimum`, changes deadlines only on resets classified by `ElectionReset`, draws each reset's deadline between `m` and `2 * m` after it for `minimum = some m`, and forbids a timeout before its deadline.
  `firing` requires an eligible overdue node to time out or cease to be due, and `noOvershoot` bounds the clock's overshoot past a deadline when `jitter` is `some`.
  `commit_liveness` passes `some (E / 2)` and `none`, and its proof uses only `timeouts`.

`ElectionReset` records the steps that call `restart_election_timeout` in CCF: starting a pre-vote or regular election, stepping down on a quorum check, adopting a newer term, granting a regular vote, and accepting an AppendEntries term and log check.
A candidate steps down and resets on a same-term AppendEntries before checking the log, but an established follower does not reset on a failed check.
The timer model is a precondition about CCF's host driver, not a refinement of its tick-driven timer; the `ElectionTimeouts` docstring lists the differences.
`commit_liveness` uses only its lower end, which CCF meets once `Bounds.electionTimeout` allows for ticks and drift; see [timing constants](#timing-constants).
Zero-time steps are allowed; `TimeDiverges` excludes executions whose clock converges.

## CCF-specific obligations

CCF only advances commitment to signatures.
Perfect delivery and stable leadership do not commit an unsigned request, so `SignatureScheduling` obliges the primary to append a covering current-term signature.
An already replicated old-term signature is also insufficient for advancing a new primary's current-term commit scan, so a signature is also due while the latest one is from an earlier term.
`Proofs.Liveness.acknowledged_signature_commits` proves that the actual `advanceCommit` operation commits any current-term signature supported by the scan's configuration quorums.
It does not show that those acknowledgements arrive; in `commit_liveness` the timing argument does.

## A lost commit trigger

The primary runs its commit scan only after an append or a successful acknowledgement.
A configuration commit can make a later signature committable without either:

1. An older-term primary `A`, with configuration `{L, A}` active, appends configuration `{L}` and a signature.
   `L` receives them, but its acknowledgement is dropped, so neither node commits the change.
2. `L` is elected in term `T` with `A`'s vote, appends signature `h`, and `A` acknowledges it.
3. Before that acknowledgement arrives, `L` appends a request and signature `s`.
   `s` is not yet committable because `{L, A}` is still active.
4. The acknowledgement commits `h`, which retires `{L, A}`.
   `L` alone can now commit `s`, but the scan has already run.

If `A` then crashes, nothing reruns the scan.
CCF avoids this.
When a commit retires configurations, `aft::Aft::commit` calls `retired_node_cleanup`, which asks the node itself to run `set_retired_committed`.
That transaction records `A`'s retirement, and `replicate` runs `update_commit` when there are no other active nodes.

`commit_liveness` excludes the situation instead.
`StableState` requires `ReconfigurationSettled` at the leader, and with no configuration change appended from `start` it stays settled (`settled_window`).
`owing_of_exec` shows that a primary that alone makes an uncommitted current-term signature committable owes a retirement confirmation: the commit scan that made the signature committable retired the other members.
None of them has a confirmation in force, because every confirmation in a node's log follows a removal of its node that the node has committed, and no configuration names the node from that removal to the confirmation (`sane_of_exec`).
Settled reconfiguration leaves no confirmation owed, so `quorum_commits` uses `confirmation_owed` to rule out a primary alone, and commits through quorum acknowledgements, each of which reruns the scan.
The retirement trace in [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean) reproduces the stranded-signature state and checks that it, a pending removal and an uncommitted confirmation are not settled, while completion at the leader alone is.

`owing_of_exec` needed two model changes, both matching CCF.
First, a configuration that names a node clears that node's earlier confirmations in `retiredCommittedNodes`, like the fresh node record, with `retired_committed` unset, that CCF creates when a deleted node rejoins.
Without this, a node removed, confirmed, re-added and removed again keeps its old confirmation, so nothing is owed, the primary may not confirm it again, and the trigger is lost.
Second, `appendEntry` re-adds a removed node only once its confirmation is committed and still in force, as CCF only deletes, and so lets rejoin, a node whose `retired_committed` status is globally committed (`delete_retired_committed_node` in `src/node/rpc/node_frontend.h`).
Without this, a confirmation could follow a pending re-add and count while the node is active again.
`sane_of_exec` correspondingly shows that every re-add follows a committed confirmation, and no configuration names the node in between.

## A lagging follower deposes the primary

This was a liveness weakness of CCF itself, not of the model, and #8639 fixes it in both.
Before that fix, two CCF behaviours combined (`src/consensus/aft/raft.h`):

- `recv_append_entries` calls `restart_election_timeout` only after the `prev_term` check passes; a rejected AppendEntries leaves the follower's timer running.
- `recv_request_vote_unsafe` applied the known-leader check (`leader_id.has_value()`) and the voted-for check to `RegularVote` only.
  A pre-vote was granted to any candidate of the node's term whose committable log is at least as up to date as the node's own, even by a follower that is receiving heartbeats from a live primary.
  Raft's pre-vote, and etcd's lease check, reject such a request while the node has heard from a leader within an election timeout.

Worked example of the behaviour before the fix, three nodes `{L, f, g}`, election timeout `E = 7`, so a timer fires between 3.5 and 7 after its reset, heartbeat interval `H = 1` and message delay at most `d = 1`:

1. `L` is the primary of term `t`.
   Its log has 10 entries, and its last signature is entry 8, so entries 9 and 10 are not yet committable.
   `g` holds all 10 entries and accepts every heartbeat.
   `f` holds only the first 8: the AppendEntries carrying entries 9 and 10 was lost, and `f`'s timer was last reset, at time 0, when it accepted entry 8.
   Its timer fires at 3.5.
2. `L` believes it sent entries 9 and 10, so its heartbeat at time 1 carries `prev_idx = 10`.
   `f` fails the `prev_term` check at time 2, replies with a NACK and does not reset its timer.
   The NACK reaches `L` at time 3, so the repairing AppendEntries cannot reach `f` before time 4.
3. At 3.5 `f`'s timer fires.
   `f` becomes a pre-vote candidate of term `t` and sends `RequestPreVote` to `L` and `g`.
4. `g` is a content follower of `L`, but `f`'s last committable entry, 8, is also `g`'s, so `f`'s log counts as up to date, and pre-votes skip the `leader_id` check, so `g` grants.
   `f` has a pre-vote quorum `{f, g}` and becomes a candidate of term `t + 1`.
5. `f`'s `RequestVote` of term `t + 1` reaches `g`.
   `become_aware_of_new_term` calls `become_follower`, which resets `leader_id`, so the regular vote's known-leader check passes too, and `g` grants.
6. `f` is the primary of term `t + 1`, and `L` steps down at its next message from `g`.
   Entries 9 and 10 were never committable, so safety is intact, but a working primary was deposed by the follower it was repairing, while the quorum `{L, g}` was in sync.

A slow or lossy link to one follower can repeat this in every term.

#8639 applies the `leader_id` check in `recv_request_vote_unsafe` to pre-votes as well.
The model's `handleRequestPreVoteRequest` likewise grants a pre-vote only while the node knows no primary (`primaryKnown` is false), the counterpart of `leader_id` in `raft.h`.
As in CCF, a node learns the primary only from an AppendEntries that passes the log check, and forgets it on its own timeout, on adopting a new term and on stepping down, so `g` refuses in step 4, and `f`'s election fails.
The results do not cover CCF versions without this fix.

The change does not protect a primary from a lagging quorum.
If `g` also lacked entries 9 and 10, its timer would fire too; once both have fired, neither knows the primary, their logs are equally up to date, and each grants the other's pre-vote, so one of them deposes `L`.

In `commit_liveness`, `StableState` excludes the example's start: every listed node has the primary's log and knows the primary.
The proof does not rely on log checks passing after `start`: it takes timer resets from acknowledgements, and the timing constraint leaves room for a repair with no backlog (`stable_window_catchup_engine`).
It does rely on the pre-vote change: anchor nodes keep knowing the primary and so refuse pre-votes, and every quorum a node can count includes an anchor node.

## Literature

| Source                                                                                                                                                                                       | Relevant definition or result                                                                                                                           | Consequence for this model                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Alpern and Schneider, [Defining Liveness](https://www.cs.cornell.edu/fbs/publications/DefLiveness.pdf), 1985, sections 2-4                                                                   | A liveness property has no irremediable finite prefix; guaranteed service is a leads-to property.                                                       | `commit_liveness` is a bounded-response property, not a pure liveness property; see below.                                                 |
| Lamport, [The Temporal Logic of Actions](https://lamport.azurewebsites.net/pubs/lamport-actions.pdf), 1994, section 5.3                                                                      | Weak fairness concerns continuously enabled actions; strong fairness concerns actions enabled infinitely often.                                         | Each scheduling premise names the obligation it serves (`Scheduled`), not merely that some process keeps running.                          |
| Lamport, [Real Time is Really Simple](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/tr-2005-30.pdf), 2005, sections 2.5, 3.3 and 5                                     | An ordinary clock variable and upper/lower execution bounds express timed progress; time divergence and non-Zenoness require attention.                 | Real timestamps and deadline predicates are attached to executions without a different protocol semantics, and `TimeDiverges` is explicit. |
| Kaynar, Lynch, Segala and Vaandrager, [The Theory of Timed I/O Automata](https://groups.csail.mit.edu/tds/papers/Lynch/Monograph-second-edition.pdf), second edition, 2010, examples 5.6-5.7 | Composes a periodic sender, bounded-delay channel and timeout, then adds sender failures; assumes sending interval plus delay is less than the timeout. | This is close to the heartbeat, channel and election-timer decomposition, and to the timing constraint.                                    |
| Dwork, Lynch and Stockmeyer, [Consensus in the Presence of Partial Synchrony](https://groups.csail.mit.edu/tds/papers/Lynch/jacm88.pdf), 1988, introduction                                  | Separates safety from termination under bounds that may hold only after an unknown stabilization time.                                                  | The stable period and its environmental assumptions are explicit premises, not safety invariants.                                          |
| Ongaro and Ousterhout, [In Search of an Understandable Consensus Algorithm](https://raft.github.io/raft.pdf), 2014, sections 5.3, 5.6, 6 and 8                                               | Separates replication, timing-sensitive elections, joint quorums and client retries.                                                                    | Commit progress is proved conditionally on an existing primary, separately from election convergence.                                      |

For the separation of communication abstractions and timing assumptions, see also Cachin, Guerraoui and Rodrigues, [Introduction to Reliable and Secure Distributed Programming](https://www.distributedprogramming.net/content.shtml), second edition, 2011, sections 2.4-2.7.

Bounded response deadlines are not pure Alpern-Schneider liveness properties: a finite timed prefix can already miss a deadline.
This applies to the conclusion of `commit_liveness` and to the bounded scheduling premises.

## Rechecking

Use the commands in [the README](README.md#validation).
