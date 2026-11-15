-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

private def assertPending (source target : NodeId) (count : Nat) : IO Unit := do
  let pending ← pendingMessages source target
  let link := s!"from {source.text} to {target.text}"
  unless pending.size == count do
    throw (IO.userError s!"Expected {count} messages {link}, got {pending}")

-- A node which joins from a snapshot does not know a node which retired
-- before it. Node 2 retires, and node 3 then joins from a snapshot whose
-- configuration is nodes 0 and 1. When node 3 is elected, the retirement of
-- node 2 is not confirmed, so nodes 0 and 1 still know node 2. Node 3 sends it
-- nothing, and confirms its retirement all the same.
-- Found by `cft_model_driver --explore`.
initialize scenario "join_from_snapshot_after_retirement" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  -- Initial network state [0, 1, 2]
  assertCommitIdx 0 3
  assertCommitIdx 1 3
  assertCommitIdx 2 3

  -- 2 retires at 2.4, and every node commits its retirement
  swapNodes 2 (retire := [2])
  replicate 2 [signature]
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 5
  assertCommitIdx 1 5
  assertDetail 2 "retirement_phase" "Completed"

  -- 3 joins from a snapshot at 2.5, which 2 has left
  trustNodeFromSnapshot 2 3
  assertLastTxid 3 "2.5"
  assertConfig 3 5 [0, 1]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 7
  assertCommitIdx 3 7

  -- 3 is elected in term 3, with the vote of 1
  periodicOne 3 100
  assertDetail 3 "leadership_state" "PreVoteCandidate"
  dispatchOne 3
  dispatchOne 1
  assertDetail 3 "leadership_state" "Candidate"
  dispatchOne 3
  dispatchOne 1
  assertDetail 3 "leadership_state" "Leader"

  -- 3 sends its first entries to 0 and 1, and not to 2
  assertPending 3 0 1
  assertPending 3 1 1
  assertPending 3 2 0
  dispatchAll

  -- 3 confirms the retirement of 2 at 3.8, and commits it at 3.9
  cleanupRetired 3
  assertLastTxid 3 "3.8"
  replicate 3 [signature]
  periodicOne 3 10
  assertPending 3 2 0
  dispatchAll
  assertCommitIdx 3 9
  periodicOne 3 10
  dispatchAll

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 9
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 9
  assertDetail 3 "leadership_state" "Leader"
  assertLastTxid 2 "2.7"
