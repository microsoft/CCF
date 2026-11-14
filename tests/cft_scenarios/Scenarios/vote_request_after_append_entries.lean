-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node refuses a vote only because it knows the primary of the term. Node 2
-- is elected in term 3 with the vote of node 1. Its first AppendEntries
-- overtakes its requests to node 0, which learns of the term and its primary,
-- and then refuses the vote without having voted for another node.
-- Found by `cft_model_driver --explore`, from
-- `retired_committed_delayed_nomination`.
initialize scenario "vote_request_after_append_entries" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicOne 0 10
  dispatchSingle 0 2
  dispatchSingle 2 0
  periodicOne 2 100
  dispatchSingle 2 1
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  dispatchNth 2 0 2
  dispatchSingle 2 0
  dispatchSingle 2 0

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 3
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 0
  assertDetail 2 "leadership_state" "Leader"
  assertCommitIdx 2 3
