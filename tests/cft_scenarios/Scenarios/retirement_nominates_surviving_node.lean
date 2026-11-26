-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Node 1 confirms its own retirement and that of node 2 in one transaction.
-- Even though node 2 has acknowledged more, it must nominate surviving node 0.
initialize scenario "retirement_nominates_surviving_node" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  periodicOne 1 100
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  assertDetail 1 "leadership_state" "Leader"

  swapNodes 3 [1, 2] []
  replicate 3 [signature]
  periodicOne 1 10
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  periodicOne 1 10
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  assertCommitIdx 0 5
  assertCommitIdx 2 5
  assertDetail 1 "retirement_phase" "Completed"
  assertDetail 2 "retirement_phase" "Completed"

  cleanupNodes 3 [1, 2]
  replicate 3 [signature]
  periodicOne 1 10
  replicate 3 [signature]
  periodicOne 1 10

  -- Node 2 acknowledges 3.8; node 0 only acknowledges 3.7.
  dispatchSingle 1 2
  dispatchSingle 1 2
  dispatchOne 2
  dispatchSingle 1 0
  dispatchSingle 0 1
  assertCommitIdx 1 7
  assertDetail 1 "retirement_phase" "RetiredCommitted"
  assertDetail 1 "leadership_state" "None"

  dispatchSingle 1 0
  dispatchSingle 1 0
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 0 "current_view" 4
  assertDetail 2 "leadership_state" "Follower"

  replicate 4 [signature]
  periodicOne 0 10
  dispatchAll
  assertCommitIdx 0 9
