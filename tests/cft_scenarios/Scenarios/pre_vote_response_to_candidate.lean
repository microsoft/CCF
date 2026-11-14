-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A candidate ignores the answer to its request for a pre-vote. Nodes 1 and 2
-- campaign at once, and each becomes a candidate in term 3 on the pre-vote of
-- the other. Node 0 votes for node 1 in term 3 before it answers the request
-- for a pre-vote of node 2, so its answer reaches a candidate of that term.
-- Found by `cft_model_driver --explore`, from `replicate_on_latest_leader`,
-- then written to end with one primary.
initialize scenario "pre_vote_response_to_candidate" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicOne 1 100
  periodicOne 2 100
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 0
  dispatchSingle 1 0
  dispatchSingle 2 0
  dispatchOne 0

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 3
  assertDetail 1 "leadership_state" "Leader"
  assertCommitIdx 1 3
  assertDetail 2 "leadership_state" "Candidate"
  assertCommitIdx 2 3
