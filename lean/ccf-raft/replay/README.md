# Trace replay

`run_scenarios.py` runs `raft_driver` for every file under `tests/raft_scenarios`
and saves stdout and stderr verbatim. It passes stdout through `reduction.py`
to produce `ccfraft-replay/v4` actions and observations, then runs the Lean replayer.
Earlier schemas are rejected; regenerate replay JSON from the raw capture.

The reduction rules are the branches of the `while events` loop in
`reduction.py`. Each rule names itself in the emitted `origin` so a failing
instruction points back to the branch and the raw event that produced it.

## Commands

Run from `lean/ccf-raft`.

| Command                                                       | Result                                                     |
| ------------------------------------------------------------- | ---------------------------------------------------------- |
| `python3 replay/reduction.py INPUT OUTPUT.json`               | Replay JSON                                                |
| `python3 replay/run_scenarios.py DRIVER --output DIRECTORY`   | Every scenario, per-scenario artifacts, and `summary.json` |
| `python3 -m unittest discover -s replay/tests -p 'test_*.py'` | Reduction and replay regression tests                      |

`run_scenarios.py` selects every regular file under the scenario directory,
recursively and sorted, matching `tests/raft_scenarios_runner.py`. A capture
error, driver stderr output, reduction error, disabled action, or observation
mismatch fails that scenario. The runner continues through the rest and exits
nonzero if any failed. It deletes the old `summary.json` before starting, so an
interrupted run cannot leave a stale success behind.

`--raw-directory DIRECTORY` replays existing `<scenario>.stdout` captures
instead of running the driver. A missing capture is a failure, not a skip.
Reusing captures does not test a changed implementation.

`test_replay.py` needs the built `.lake/build/bin/ccfraft-replay` and fails if
it is absent. `test_reduction.py` runs without it.

## What the code does not tell you

Committable indices are a cache, not the set of signatures. A batch can keep
markers 5 and 7 while the log also holds signature 6. So each recorded marker
becomes an `entry` observation requiring a signature at that index, and an
absent marker asserts nothing. This matches `CommittableIndices` in
`tla/consensus/ccfraft.tla`.

Vote and pre-vote responses use the `send_request_vote_response` trace event;
`packet.msg` distinguishes the two. The model's `receive` generates the
response, and the send event checks its packet and the sender's resulting state.

A higher-term nomination does not advance the receiver's term.
`recv_propose_request_vote` acts only on a same-term nomination. An ignored
nomination still consumes the packet.

`step_down_and_nominate_successor` traces before `become_retired` clears the
leadership role, so its snapshot still says leader. The reducer checks that raw
fact and excludes `role` from the post-action observation.

Actions are `append` (`node`, nonempty `entries`), `sendEntries` (`source`,
`destination`, `endIndex`), `timeout` (`node`, `timeout` of `election` or
`checkQuorum`), `nominateSuccessor` (`node`, `destination`), `receive` and `drop`. Each driver
`replicate` writes one entry, so it becomes a one-entry `append`. A
`globally_committable` write is a signature. Any other write is a transaction
whose identifier is `file:line` of its `replicate` record. That includes
configuration and retirement writes, because the trace carries no transaction
id. Its effects are a configuration from a following `add_configuration`, or
a `retiredCommitted` record naming the nodes of the `cleanup_nodes` command. The
bootstrap configuration entry is preloaded with the empty identifier, which no
recorded `file:line` can equal.
The singleton append boundary is justified by `RaftDriver::_replicate` in
`src/consensus/aft/test/driver.h`, which calls Raft with a singleton
`BatchVector`. This reducer is not a general production-trace batch reducer:
the per-entry `replicate` callbacks in `raft.h` do not record batch boundaries.
Replaying multi-entry C++ calls atomically needs additional trace evidence;
adjacent callbacks alone do not establish a batch boundary.

Callbacks that `raft.h` runs inside one operation form one action with it:
new-peer heartbeats and a lone-leader commit inside `append`, a commit
inside an AppendEntries-response `receive`, and the
commit and heartbeats of `become_leader`. No commit, promotion, or vote send is
a standalone action, so an ungrouped leader `commit` is a reduction error. A
standalone `send_append_entries` becomes `sendEntries`. The reducer requires its
`prev_idx` to equal the recorded `sent_idx`, from which the model derives it. A
`step_down_and_nominate_successor` outside a commit must come from a
`nominate_successor` command. Every nomination callback becomes its own
`nominateSuccessor` action with the recorded destination, including callbacks
inside retirement commits. The reducer then observes the queued proposal.

Elections are atomic, as in `raft.h`. `become_pre_vote_candidate` and
`become_candidate` events form one `timeout` action together with their nested
self-quorum promotions (`become_candidate`, `become_leader`) and every
`send_request_vote` callback that follows. The reducer checks that the
requests go, in ascending order, to every other node in the traced active
configurations, and observes each queued request. A `become_candidate` or
`become_leader` event right after a vote or pre-vote response, or a
`become_candidate` after a vote proposal, belongs to that `receive`.
When a promotion records configurations, its heartbeat callbacks must cover
every other active member. Extra retained peers are checked against queued
model packets too; the snapshot alone cannot enumerate peers retained after
rollback.

Nomination destinations are model inputs guarded by eligible-peer membership
and exclusion of self. The model intentionally does not check C++ successor
ranking or unordered-map tie breaking. Terminal retirement records the
outgoing leader's term and eligible-peer set before commit prunes old
configurations and clears leadership. The following explicit nomination can
use that captured permission once; another local event expires it. An arbitrary
retired nonleader cannot nominate. Raw terminal snapshots still have the
leader role and completed retirement phase: these are audited when grouping,
not confused with the model's postcommit role. Packet destination, term, queue
ordering, and delivery evidence remain checked.

A `become_follower` event inside a receive is not a separate action. The model
adopts the newer term, or steps a same-term candidate down, inside the one
`receive`. Its observation follows the receive and checks only `role` and
`currentTerm`, because the rest of the receive can change the other fields.

The model's network is a multiset of envelopes, and the replayer resolves each
`receive` to the oldest pending envelope from that source to that destination,
which is the order `raft_driver` delivers in. A `drop` does not step the model.
The replayer records the envelope as dropped and never delivers it or shows it
to a message observation. The envelope stays in the model's network, as any
undelivered message does.

Shuffled queues (`shuffle_one`, `shuffle_all`) are rejected. Every drop removes
occurrence zero because `RaftDriver::drop_pending_to` drains the queue in order.

## Fixtures

Fixtures live in `replay/tests/fixtures`.

| File                             | Contents                                                             |
| -------------------------------- | -------------------------------------------------------------------- |
| `bootstrap.ndjson`               | The five-event bootstrap prelude                                     |
| `configuration_callback.ndjson`  | A configuration change and the new-peer heartbeat                    |
| `missing_prefix_response.ndjson` | A fresh follower's NACK to a heartbeat with a nonzero previous index |
| `startup.ndjson`                 | Every Raft record from the `startup` scenario                        |
| `drop_resend.ndjson`             | Same-sender packet events for drop and resend accounting             |
| `terminal_retirement.stdout`     | Full `reconfig_0_1` capture: retirement commit and nomination        |
| `retire_follower.stdout`         | Full `retire_one` capture: retirement indices in follower callbacks  |

`vote_responses.ndjson` is a prefix of the `pre_vote` capture covering granted
votes and granted and denied pre-votes.

Some `.ndjson` files are partial excerpts; others include bootstrap and replay independently.
The `.stdout` files are complete driver captures.
