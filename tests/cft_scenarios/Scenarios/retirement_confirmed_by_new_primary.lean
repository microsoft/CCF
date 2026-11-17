-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

private def assertPending (source target : NodeId) (count : Nat) : IO Unit := do
  let pending ← pendingMessages source target
  let link := s!"from {source.text} to {target.text}"
  unless pending.size == count do
    throw (IO.userError s!"Expected {count} messages {link}, got {pending}")

-- A node which is elected confirms the retirement which the primary before it
-- committed, and did not confirm. Consensus asks each primary to clean up
-- retired nodes: node 0 when it commits the configuration which removes node
-- 2, and node 1 when it is elected. `cleanupRetired` is what a primary then
-- does. Once the confirmation is committed, no node sends to node 2.
initialize scenario "retirement_confirmed_by_new_primary" do
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

  -- 2 retires, and every node commits its retirement
  swapNodes 2 (retire := [2])
  replicate 2 [signature]
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 5
  assertCommitIdx 1 5
  assertDetail 2 "retirement_phase" "Completed"

  -- 0 has not confirmed the retirement when 1 is elected in term 3
  periodicOne 1 100
  dispatchOne 1
  dispatchOne 0
  dispatchOne 1
  dispatchOne 0
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 0 "leadership_state" "Follower"
  dispatchAll

  -- 1 confirms the retirement of 2 at 3.6, and commits it at 3.7
  cleanupRetired 3
  assertLastTxid 1 "3.6"
  replicate 3 [signature]
  periodicOne 1 10
  assertPending 1 2 1
  dispatchAll
  assertCommitIdx 1 7
  periodicOne 1 10
  dispatchAll
  assertCommitIdx 0 7

  -- Neither 0 nor 1 knows 2 any longer, which has nothing left to confirm
  periodicOne 1 10
  assertPending 1 2 0
  dispatchAll
  cleanupRetired 3
  assertLastTxid 1 "3.7"

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 7
  assertDetail 1 "leadership_state" "Leader"
  assertCommitIdx 1 7
