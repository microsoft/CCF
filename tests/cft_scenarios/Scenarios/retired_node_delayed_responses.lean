-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Retain vote and append responses from node 1 while node 0 is re-elected, then
-- retire and clean up node 1. Its delayed responses must be ignored after its
-- consensus peer state has been removed.
initialize scenario "retired_node_delayed_responses" do
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

  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  dropPending 0
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dispatchSingle 0 1
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Candidate"
  dispatchSingle 0 1
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Leader"
  dropPending 0

  swapNodes 3 (retire := [1])
  replicate 3 [signature]
  periodicOne 0 10
  dispatchSingle 0 1
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertCommitIdx 0 6

  cleanupNodes 3 [1]
  replicate 3 [signature]
  periodicOne 0 10
  dropPendingTo 0 1
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertCommitIdx 0 8

  dispatchSingle 1 0
  dispatchSingle 1 0
  dispatchSingle 1 0
  assertDetail 0 "leadership_state" "Leader"
  loopUntilSync
