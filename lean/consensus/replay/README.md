# CCF consensus protocol trace validation

Validate traces of [`cft.h`](../../../src/consensus/aft/cft.h) against M_tv, a Lean model of `cft.h` that takes one step per trace point, and check that every accepted trace refines the [clean consensus model](../README.md).
The `consensus-replay` executable validates captures from the native `cft_driver` and from real nodes.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/consensus`, build the validator and validate a saved trace:

```sh
lake build --wfail consensus-replay
./.lake/build/bin/consensus-replay path/to/trace.ndjson...
```

Each accepted trace prints `PASS` with its node, event and lock-hold counts; each rejected trace prints `FAIL` and the reason, usually the first event that the model cannot explain.
With `--refine`, an accepted trace is also checked hold by hold against the clean model (see below), and each finding prints `REFINE` and rejects the trace.
The exit status is 0 when every trace is accepted, 1 when any is rejected, and 2 on a usage error.

To generate captures, build the native driver and run the existing scenario test.
The driver links the [scenarios](../../../tests/cft_scenarios/README.md), which are Lean programs, so CMake must find `lake`.
Use a fresh build directory to avoid replaying stale captures from earlier runs.
This needs Python `msgpack` available to CTest:

```bash
set -euo pipefail
cmake -S ../.. -B /tmp/cft-build -GNinja
cmake --build /tmp/cft-build --target cft_driver
ctest --test-dir /tmp/cft-build -VV -R '^cft_scenario_test$' --no-tests=error
for trace in /tmp/cft-build/consensus/raw/*.ndjson; do
  ./.lake/build/bin/consensus-replay --refine "$trace"
done
```

The scenario runner writes the raw records to `consensus/raw/`.
The Fluentd tag is `ccf.cft`; packet message names are unprefixed, for example `append_entries` and `request_vote`.
Each event's `state` field is a snapshot of `aft::State`.
Events whose code reads or writes the `aft::Aft` variables `voted_for`, `votes_for_me`, `leader_id`, `is_new_follower` or `ticking` also carry those variables as top-level fields next to `state`, with their values when the event is traced; [`cft_trace_msgpack.h`](../../../src/consensus/aft/cft_trace_msgpack.h) lists the fields of each event.
`voted_for` and `leader_id` are a node ID or nil, and `votes_for_me` is an array, ordered by configuration index, of `{"idx", "quorum", "votes"}` maps whose `votes` lists the sorted IDs of the nodes that voted for this node in that configuration.

## Validation contract

A trace is a file of records `{process_id, h_ts, msg}`.
Records whose `msg` has a `cmd` are driver provenance and are ignored; every other record is one trace point of the node named by `msg.state.node_id` (`msg.node_id` for `retired_committed_tx`, which has no snapshot).
Records are split into one stream per node, ordered by `h_ts`; all of a node's records must come from one process.
`h_ts` is never compared across nodes, so captures with one process per node, or with shuffled lines, validate the same way.

Each node's state is the declared state ([`State`](../Consensus/TraceValidation/State.lean)), one field per `cft.h` member, extended by the position inside the current lock hold.
[`Aft`](../Consensus/TraceValidation/Aft.lean) mirrors the `cft.h` functions statement by statement; it takes one step per trace point, running the code from the previous trace point up to this one.
The first trace point of a lock hold opens a section; a silent release, inserted when the node's next event opens another section or its stream ends, runs the code after the last trace point and publishes the hold's sends.
Where `cft.h` depends on something no trace point records, such as a timer or a batch size, the handler follows the branch that the node's next event requires.

At every trace point, [`Observe`](../Consensus/TraceValidation/Observe.lean) compares the event with the declared state there: the `state` snapshot, the per-event state fields such as `match_idx`, `sent_idx`, `configurations` and `commit.idx`, and the values the model computed, such as packets.
Every trace point has a fixed set of fields (`Observe.traceFields`, as `cft_trace_msgpack.h` declares them); an event with a missing or unexpected field is rejected.
Every field is either compared or consumed as the step's input, as `Observe.inputFields` lists.
This includes the `aft::Aft` variables above, which are compared on exactly the events that carry them.
A receive delivers a message that its sender has already published with an identical packet; a dropped message stays in the network.

A node that joined from a snapshot holds only the ledger after it: its declared state has the snapshot's index and view (`base`, `baseView`) and the entries after the index.
Each release checks that the base is a committed signature in that view, and that the hold's outcome does not depend on the entries up to the base, which the node does not hold.
For the proof only, the model takes those entries, which no trace point records, from another node's committed ledger.

With `--refine`, [`Lockstep`](../Consensus/TraceValidation/Lockstep.lean) also checks every release against the [clean model](../Consensus/Model/Node.lean): the clean inputs of the hold are rebuilt, the clean `Node.step`s run from the node's clean state, and the result must agree ([`Abs`](../Consensus/TraceValidation/Abs.lean)) with the declared state, with the same sends in the same order, and satisfy the invariants the proofs use.
This check is a diagnostic and a regression oracle for the proofs, not part of what acceptance means.

## What acceptance means

An accepted trace is a behaviour of the clean model under a state refinement mapping.
The mapping is reviewed: the declared state ([`State`](../Consensus/TraceValidation/State.lean)) and the relation `related` of a clean node state to it ([`Abs`](../Consensus/TraceValidation/Abs.lean)).
The behaviour refinement is the one theorem [`TraceValidation.lean`](../Consensus/TraceValidation.lean) states, using the refinement statement of [`CCF.Observation`](../../common/CCF/Observation.lean).
`accepted_refines`: the validator observed exactly the streams' events, each consistent with the declared state at its trace point, and there is one trace of `Consensus.Model.transitionSystem` in which, at every lock-taking event, the node's clean state is `related` to its declared state.
Its proof, in [`TraceValidation/Proofs`](../Consensus/TraceValidation/Proofs), is not reviewed and uses only the standard axioms.
Properties are stated and proved of the clean model only ([`Properties.lean`](../Consensus/Properties.lean)); trace validation claims nothing more of the implementation than this refinement.
The proof reduces it to one obligation per `cft.h` handler, each stated in [`Obligation.lean`](../Consensus/TraceValidation/Proofs/Obligation.lean) and proved in its own file under [`Proofs/Handlers/`](../Consensus/TraceValidation/Proofs/Handlers) ([`Handlers.lean`](../Consensus/TraceValidation/Proofs/Handlers.lean) assembles them).

To review: `TraceValidation.lean`, `CCF.Observation`, and `State`, `Event`, `Action`, `Observe` and `Abs` in [`TraceValidation/`](../Consensus/TraceValidation).
`Handler`, `Aft`, `Machine` and `Validator` are the executable model and its scheduler, and `Invariant` and `Lockstep` the invariants and the diagnostic check; the proofs cover them.
The decoder (`Event`) and the per-node split are trusted.

## Known implementation and specification differences

Validation rejects some behaviours that `cft.h` can show but the clean model cannot express.
Each such diagnostic says "accepted by the implementation, rejected by validation" and "known implementation and specification difference".
A trace that shows one of them is rejected, even though the implementation behaved as designed.

| #   | Where                                                                    | `cft.h`                                                                                                                                                                                                     | Clean model                                                 | Reachable scenario                                                                                                                                                                                                                                                                    |
| --- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S1  | `Invariant` `peers`, and `Aft` `rollback` ("peers kept across rollback") | Keeps a peer in `all_other_nodes` across a rollback.                                                                                                                                                        | Drops it: a node's peers are its eligible peers.            | n0 appends a configuration adding n3, does not replicate it, and is partitioned. n1 wins the next view. When n0 rolls the configuration back, it keeps n3.                                                                                                                            |
| S2  | `Invariant` `empty_ledger_alone`                                         | Keeps peers across a rollback to an empty ledger.                                                                                                                                                           | A node without a log has no eligible peers.                 | As S1, when the rolled-back configuration was the node's only one.                                                                                                                                                                                                                    |
| S3  | `Aft` `electionGuard` ("election guard")                                 | Starts an election when it is ticking and not retired-committed.                                                                                                                                            | Also needs a role and membership of a signed configuration. | `ticking` is sticky. Leader n0 appends a configuration adding n3, then a signature, which reach only n3. n0 is partitioned, and n1, which lacks them, wins. n3 rolls them back, still ticks, times out and stands for election. The native driver also ticks nodes that have no role. |
| S4  | `Aft` `setRetiredCommitted` ("successor nomination")                     | Nominates after erasing the peers whose retirement commits in the same commit.                                                                                                                              | Nominates from the peers as they were before the commit.    | One `remove_node` proposal retires primary n0 and n1, and one `set_retired_committed` transaction marks both. When it commits, `cft.h` erases n1 before it nominates; the clean model may pick n1, for example when n1 has the highest match index.                                   |
| S5  | `Aft` `retiredHooks` ("retirement confirmation")                         | `hooks.h` confirms a retired node again whenever its record is rewritten with `retired_committed`.                                                                                                          | Confirms only completed, unconfirmed retirements.           | A second `remove_node` proposal for a retired-committed node, before `retired_nodes_cleanup` deletes its row, rewrites the record.                                                                                                                                                    |
| S6  | `Aft` `retiredHooks` ("empty configuration")                             | `hooks.h` adds an empty configuration when the last node removes itself.                                                                                                                                    | Requires a non-empty configuration.                         | `remove_node` of the only node of a one-node service, which the default constitution does not forbid.                                                                                                                                                                                 |
| S7  | `Aft` `recvRequestVoteResponse` (pre-votes)                              | Ignores a granted pre-vote from a node that is in no active configuration.                                                                                                                                  | Counts the pre-vote of any eligible peer.                   | Pre-vote candidate n1 asks n3 in view 2. n1 learns a committed configuration without n3 and steps down. It starts a new pre-vote in view 2, and n3's late grant arrives.                                                                                                              |
| S8  | `Aft` `recvProposeRequestVote`                                           | Ignores the proposal on a node that is not ticking.                                                                                                                                                         | Starts an election.                                         | A joiner is named by a configuration that a configuration without it supersedes before the next signature. It never ticks, but it is a member of a signed active configuration, so the primary can nominate it.                                                                       |
| S9  | `Machine` `ghostFree` ("depends on the ledger up to the snapshot base")  | A primary that joined from a snapshot sends AppendEntries below its snapshot base; the host ([`node_connections.h`](../../../src/host/node_connections.h)) cannot read those entries and drops the message. | Sends the entries.                                          | n3 joins from a snapshot at seqno s and later becomes primary while n1 lags below s, for example after a long partition. n1 never catches up from n3, which is a liveness issue.                                                                                                      |

Every other rejection is of something `cft.h` cannot do: a mirror of one of its assertions or throws, a fact about the trace format, a step that would need two leaders in one view or a faulty peer, or an entry that CCF never writes.

Validation also tolerates the following without checking them exactly.

- **T1:** a node that joined from a snapshot may declare its first configuration at a later index than the ledger has it, at or below its commit index, because the snapshot hook reports the version of the last write to the nodes table.
  `cft.h` compares that index only with later configurations and with indexes above the commit index, so the behaviour is the same.
- **T2:** inputs that no trace point records are read from the node's next events: the batch size, `request_timeout`, the CheckQuorum acknowledgement timers, the flush threshold, the out-of-lock hook's snapshot version and `force_become_primary`.
  Every consequence of each one is still checked.
- **T3:** the view history that a node joining from a snapshot receives with it is not traced, so M_tv takes the donor's view history up to the snapshot base.
  The two are equal: both give each index up to the base the term of its committed entry (`inv`'s `terms_are_views`), so a snapshot whose prefix spans several views is modelled exactly.
  The entries below the base remain a ghost, and any read of them is rejected (S9).
- **T4:** on an election timeout with no configurations, `cft.h` returns early; the proof matches it with no clean step.

## Source

- [`TraceValidation/`](../Consensus/TraceValidation): declared state, events, observation, abstraction, M_tv, the validator and proofs.
- [`ReplayMain.lean`](ReplayMain.lean): validation CLI.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): native scenario runner and capture generation.

See [fixtures](fixtures/README.md) for examples and expected diagnostics.
