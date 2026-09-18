# Trace replay

`run_scenarios.py` runs `raft_driver` for every file under `tests/raft_scenarios`
and saves stdout and stderr verbatim. It passes stdout through `reduction.py`
to produce `ccfraft-replay/v2` actions and observations, then runs the Lean replayer.

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
`packet.msg` distinguishes the two. The model's `receive` action generates the
response, and the send event checks its packet and the sender's resulting state.

A higher-term nomination does not advance the receiver's term.
`recv_propose_request_vote` acts only on a same-term nomination. An ignored
nomination still consumes the packet.

`step_down_and_nominate_successor` traces before `become_retired` clears the
leadership role, so its snapshot still says leader. The reducer checks that raw
fact and excludes `role` from the post-action observation.

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
