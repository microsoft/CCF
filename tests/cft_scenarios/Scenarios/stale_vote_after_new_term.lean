-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node ignores a vote for an election which it has since lost. Node 2
-- campaigns in term 3, and the vote of node 4 is held. While node 2 is
-- disconnected, node 1 is elected in term 4. Node 2 hears of that term, and
-- only then does the vote arrive.
-- Found by `cft_model_driver --explore`, from `soft_rollback`.
initialize scenario "stale_vote_after_new_term" do
  startNode 0
  trustNode 2 1
  trustNodes 2 [2, 3, 4]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicOne 2 110
  dispatchOne 2
  dispatchSingle 3 2
  dispatchSingle 4 2
  dispatchOne 2
  disconnectNode 2
  holdNth 4 2 0
  periodicOne 1 110
  dispatchAll
  reconnectNode 2
  periodicAll 10
  dispatchAll
  dispatchHeld 0

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 4
  assertDetail 1 "leadership_state" "Leader"
  assertCommitIdx 1 4
  assertDetail 2 "leadership_state" "Follower"
  assertCommitIdx 2 4
  assertDetail 3 "leadership_state" "Follower"
  assertCommitIdx 3 4
  assertDetail 4 "leadership_state" "Follower"
  assertCommitIdx 4 4
