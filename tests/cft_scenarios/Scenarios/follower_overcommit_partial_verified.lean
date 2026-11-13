-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Repro for #8172: a follower may commit a divergent local suffix beyond the
-- range verified by an AppendEntries request. This scenario reproduces that
-- issue.
--
-- Common committed prefix ends at 2.4. Node 1 then leads term 3:
--   - [5,6]@3 is shared with every node.
--   - [7,8]@3 is shared only with node 2 and remains divergent.
-- Node 0 later leads term 4, creates and commits conflicting [7,8]@4 with
-- nodes 3 and 4.
--
-- A delayed term-3 NACK from node 2 then backs node 0's sentIndex[2] to 4.
-- The next periodic sends two AEs split at the term boundary:
--   1. prev=4, idx=6, matching [5,6]@3, leaderCommit=8
--   2. prev=6, idx=8, conflicting [7,8]@4, leaderCommit=8
--
-- Delivering only (1) takes the already-done path. The buggy implementation
-- commits node 2's local signature at 8, although the request verified only
-- through index 6. Node 2 commits [7,8]@3 while node 0 committed [7,8]@4.
initialize scenario "follower_overcommit_partial_verified" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2, 3, 4]
  emitSignature 2
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertStateSync

  -- Queue a term-2 heartbeat to node 2. It will be delivered after node 2
  -- observes term 3, producing the delayed NACK used at the end.
  periodicOne 0 10
  dropPendingTo 0 1
  dropPendingTo 0 3
  dropPendingTo 0 4

  -- Node 1 wins term 3 with nodes 2 and 3. Deliver the queued heartbeat after
  -- node 2 processes the vote request, but leave its NACK to node 0 pending.
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 2
  dispatchSingle 1 3
  dispatchSingle 1 0
  dispatchSingle 1 4
  dispatchSingle 2 1
  dispatchSingle 3 1
  dispatchSingle 0 1
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Candidate"
  assertDetail 1 "current_view" 3
  dispatchSingle 1 2
  dispatchSingle 0 2
  dispatchSingle 1 3
  dispatchSingle 1 0
  dispatchSingle 1 4
  dispatchSingle 2 1
  dispatchSingle 3 1
  dispatchSingle 0 1
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 3

  -- Drain the leader's immediate empty heartbeats so later dispatches select the
  -- entry-bearing [5,6] request.
  dispatchSingle 1 0
  dispatchSingle 1 2
  dispatchSingle 1 3
  dispatchSingle 1 4
  dispatchSingle 0 1
  dispatchSingle 2 1
  dispatchSingle 3 1
  dispatchSingle 4 1

  -- Build [5,6]@3 and share it with every node.
  replicate 3 "shared"
  emitSignature 3
  periodicOne 1 10
  dispatchSingle 1 0
  dispatchSingle 1 2
  dispatchSingle 1 3
  dispatchSingle 1 4
  dropPendingTo 0 1
  dropPendingTo 3 1
  dropPendingTo 4 1
  assertLastTxid 0 "3.6"
  assertLastTxid 2 "3.6"
  assertLastTxid 3 "3.6"
  assertLastTxid 4 "3.6"

  -- Build a divergent signed suffix [7,8]@3 only on node 2.
  replicate 3 "old-branch"
  emitSignature 3
  periodicOne 1 10
  dropPendingTo 1 0
  dropPendingTo 1 3
  dropPendingTo 1 4
  dispatchSingle 1 2
  dropPendingTo 2 1
  assertLastTxid 2 "3.8"
  assertLastTxid 0 "3.6"

  -- Node 0 wins term 4 with nodes 3 and 4, retaining the shared prefix.
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dropPendingTo 0 1
  dropPendingTo 0 2
  dispatchSingle 0 3
  dispatchSingle 0 4
  dispatchSingle 3 0
  dispatchSingle 4 0
  assertDetail 0 "leadership_state" "Candidate"
  assertDetail 0 "current_view" 4
  dropPendingTo 0 1
  dropPendingTo 0 2
  dispatchSingle 0 3
  dispatchSingle 0 4
  dispatchSingle 3 0
  dispatchSingle 4 0
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 0 "current_view" 4

  -- Build conflicting [7,8]@4 and commit it with nodes 3 and 4.
  replicate 4 "new-branch"
  emitSignature 4
  periodicOne 0 10
  dropPendingTo 0 1
  dropPendingTo 0 2
  dispatchSingle 0 3
  dispatchSingle 0 4
  dispatchSingle 3 0
  dispatchSingle 4 0
  dispatchSingle 0 3
  dispatchSingle 0 4
  dispatchSingle 3 0
  dispatchSingle 4 0
  assertCommitIdx 0 8
  assertLastTxid 0 "4.8"
  assertLastTxid 2 "3.8"

  -- Deliver the retained NACK. It resets node 0's sentIndex[2] to 4.
  summariseMessages 2 0
  dispatchSingle 2 0

  -- Node 0 queues [5,6]@3 and [7,8]@4 as separate messages. The first message is
  -- already present on node 2 but carries leaderCommit=8.
  periodicOne 0 10
  summariseMessages 0 2

  -- Node 2 only commits through the range verified by this request.
  dispatchSingle 0 2
  assertCommitIdx 2 6
