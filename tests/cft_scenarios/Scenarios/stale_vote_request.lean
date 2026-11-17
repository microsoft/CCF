-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node refuses a vote in a term which it has left. Node 1 is elected in
-- term 3 with the vote of node 0, and its requests to node 2 are delayed.
-- Node 0 then campaigns, and node 2 hears of term 4 from it before the
-- request of node 1 for a vote in term 3 arrives.
-- Found by `cft_model_driver --explore`, from `indirect_commit_stale_leader`,
-- then written to end with one primary.
initialize scenario "stale_vote_request" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicOne 1 110
  dispatchSingle 1 0
  dispatchSingle 0 1
  dispatchSingle 1 0
  dispatchSingle 0 1
  periodicOne 0 110
  dispatchSingle 0 2
  dispatchSingle 2 0
  dispatchSingle 0 2
  dispatchSingle 1 2
  dispatchSingle 1 2
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 3
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 3
  assertDetail 2 "leadership_state" "Follower"
  assertCommitIdx 2 3
