-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Node 2 receives an order to retire, but the reconfiguration remains unsigned
-- and uncommitted. It wins a new-term election with quorums from both active
-- configurations, rolls back the abandoned reconfiguration, and becomes active.
initialize scenario "retirement_rollback" do
  startNode 0
  replicate 2 [signature]
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  swapNodes 2 (retire := [2])
  periodicOne 0 10
  dropPendingTo 0 1
  dispatchSingle 0 2
  assertDetail 2 "membership_state" "Retired"
  assertDetail 2 "retirement_phase" "Ordered"
  assertLastTxid 2 "2.5"
  dropPending 2

  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchSingle 2 0
  dispatchSingle 0 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Candidate"
  dispatchSingle 2 0
  dispatchSingle 0 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Leader"
  assertDetail 2 "membership_state" "Active"
  assertAbsentConfig 2 5
  assertLastTxid 2 "2.4"
  loopUntilSync
