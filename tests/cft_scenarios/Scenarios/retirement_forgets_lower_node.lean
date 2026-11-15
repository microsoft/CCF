-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A primary which retires with a node of a lower identifier does not nominate
-- that node. One transaction confirms the retirement of nodes 0 and 2. CCF
-- confirms them in the order of their identifiers, and forgets each node
-- other than itself as it does. So node 2, the primary, has forgotten node 0
-- when its own retirement is confirmed, and nominates node 1, although node 0
-- has acknowledged more.
-- Found by `cft_model_driver --explore`, from
-- `retired_committed_delayed_nomination`, then written so that every node
-- learns of its retirement.
initialize scenario "retirement_forgets_lower_node" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  -- Initial network state [0, 1, 2], committed at 2.3

  -- 2 is elected in term 3
  periodicOne 2 100
  dispatchOne 2
  dispatchOne 0
  dispatchOne 1
  dispatchOne 2
  dispatchOne 0
  dispatchOne 1
  dispatchOne 2
  dispatchOne 0
  dispatchOne 1
  assertDetail 2 "leadership_state" "Leader"

  -- 2 removes 0 and itself at 3.4, and signs at 3.5, which commits
  swapNodes 3 [0, 2] []
  replicate 3 [signature]
  periodicOne 2 10
  dispatchOne 2
  dispatchOne 0
  dispatchOne 1
  periodicOne 2 10
  dispatchOne 2
  dispatchOne 0
  dispatchOne 1
  assertCommitIdx 0 5
  assertCommitIdx 1 5
  assertDetail 0 "retirement_phase" "Completed"
  assertDetail 2 "retirement_phase" "Completed"

  -- 2 confirms both retirements at 3.6, and signs at 3.7 and at 3.8
  cleanupNodes 3 [0, 2]
  replicate 3 [signature]
  periodicOne 2 10
  replicate 3 [signature]
  periodicOne 2 10

  -- 0 acknowledges 3.8, and 1 only 3.7, which commits the confirmation
  dispatchSingle 2 0
  dispatchSingle 2 0
  dispatchOne 0
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertCommitIdx 2 7
  assertDetail 2 "retirement_phase" "RetiredCommitted"
  assertDetail 2 "leadership_state" "None"

  -- 2 has nominated 1, the only node left, which is elected in term 4
  dispatchOne 2
  assertDetail 1 "leadership_state" "Leader"

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 5
  assertCommitIdx 1 5
