-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A primary which retires with a node of a higher identifier may nominate
-- that node. One transaction confirms the retirement of nodes 1 and 2. CCF
-- confirms them in the order of their identifiers, so node 1, the primary,
-- still knows node 2 when its own retirement is confirmed, and nominates it,
-- because it has acknowledged more than node 0. Node 2 is elected, commits
-- the confirmation in its turn, and nominates node 0, which stays.
-- Found by `cft_model_driver --explore`, from
-- `retired_committed_delayed_nomination`, then written to end with the node
-- which stays as primary.
initialize scenario "retirement_nominates_higher_node" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  -- Initial network state [0, 1, 2], committed at 2.3

  -- 1 is elected in term 3
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

  -- 1 removes itself and 2 at 3.4, and signs at 3.5, which commits
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

  -- 1 confirms both retirements at 3.6, and signs at 3.7 and at 3.8
  cleanupNodes 3 [1, 2]
  replicate 3 [signature]
  periodicOne 1 10
  replicate 3 [signature]
  periodicOne 1 10

  -- 2 acknowledges 3.8, and 0 only 3.7, which commits the confirmation
  dispatchSingle 1 2
  dispatchSingle 1 2
  dispatchOne 2
  dispatchSingle 1 0
  dispatchSingle 0 1
  assertCommitIdx 1 7
  assertDetail 1 "retirement_phase" "RetiredCommitted"
  assertDetail 1 "leadership_state" "None"

  -- 1 has nominated 2, which is elected in term 4 with the vote of 0
  dispatchSingle 1 0
  dispatchSingle 1 2
  dispatchOne 2
  dispatchOne 0
  assertDetail 2 "leadership_state" "Leader"
  assertDetail 2 "retirement_phase" "Completed"

  -- 2 signs at 4.9, which commits the confirmation of its own retirement
  replicate 4 [signature]
  periodicOne 2 10
  dispatchOne 2
  dispatchOne 0
  assertCommitIdx 2 9
  assertDetail 2 "retirement_phase" "RetiredCommitted"
  assertDetail 2 "leadership_state" "None"

  -- 2 has forgotten 1, and nominated 0, which is elected in term 5
  dispatchOne 2
  assertDetail 0 "leadership_state" "Leader"

  assertCommitIdx 0 5
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 7
