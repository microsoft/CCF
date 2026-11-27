-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Node 2 receives both a reconfiguration retiring it and a following signature
-- (reaching RetirementPhase::Signed), while neither is committed. A quorum of
-- the active configuration elects node 1 in a new term without those entries,
-- and replicating the new term's entry rolls back node 2 from Signed through
-- Ordered back to Active.
initialize scenario "retirement_signed_rollback" do
  startNode 0
  replicate 2 [signature]
  trustNodes 2 [1, 2, 3, 4]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync
  assertCommitIdx 0 4

  swapNodes 2 (retire := [2])
  replicate 2 [signature]
  periodicOne 0 10
  dropPendingTo 0 1
  dropPendingTo 0 3
  dropPendingTo 0 4
  dispatchSingle 0 2
  assertDetail 2 "membership_state" "Retired"
  assertDetail 2 "retirement_phase" "Signed"
  assertLastTxid 2 "2.6"
  assertCommitIdx 2 4
  dropPending 2

  -- Nodes 1, 3, and 4 form a quorum of configuration 3 and hold only up to 2.4.
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 1 4
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Candidate"
  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 1 4
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 3

  replicate 3 [signature]
  periodicOne 1 10
  dispatchOne 1
  assertDetail 2 "membership_state" "Active"
  assertAbsentConfig 2 5
  assertLastTxid 2 "3.5"
  loopUntilSync
