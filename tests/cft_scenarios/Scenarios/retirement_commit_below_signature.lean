-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Node 2 has signed its retirement, but a delayed ACK only lets the leader
-- commit an earlier signature. Learning that commit must leave node 2 Signed.
initialize scenario "retirement_commit_below_signature" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2]
  emitSignature 2
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync
  assertCommitIdx 2 4

  -- Both backups hold signature 5, but neither ACK has reached the leader.
  emitSignature 2
  periodicOne 0 10
  dispatchSingle 0 1
  dispatchSingle 0 2
  assertLastTxid 2 "2.5"
  assertCommitIdx 0 4
  dropPending 2

  -- Only node 2 receives the retirement order and its signature at 7.
  swapNodes 2 (retire := [2])
  emitSignature 2
  periodicOne 0 10
  dropPendingTo 0 1
  dispatchSingle 0 2
  assertDetail 2 "membership_state" "Retired"
  assertDetail 2 "retirement_phase" "Signed"
  assertLastTxid 2 "2.7"
  assertCommitIdx 2 4

  -- The ACK for 5 satisfies both configurations, but does not commit retirement.
  dispatchSingle 1 0
  assertCommitIdx 0 5
  periodicOne 0 10
  dispatchSingle 0 2
  assertCommitIdx 2 5
  assertDetail 2 "retirement_phase" "Signed"
  assertLastTxid 2 "2.7"

  -- Once node 1 catches up, the retirement signature can commit normally.
  dispatchAll
  periodicOne 0 10
  dispatchAll
  assertCommitIdx 0 7
  periodicOne 0 10
  dispatchAll
  assertCommitIdx 2 7
  assertDetail 2 "retirement_phase" "Completed"
  loopUntilSync
