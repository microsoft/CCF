-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "pre_vote_split" do
  startNode 0
  replicate 2 [signature]
  swapNodes 2 (trust := [1])
  replicate 2 [signature]

  swapNodes 2 (trust := [2])
  replicate 2 [signature]

  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertCommitIdx 0 6
  assertConfig 0 5 [0, 1, 2]
  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 1 6
  assertConfig 1 5 [0, 1, 2]
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 2 6
  assertConfig 2 5 [0, 1, 2]
  assertDetail 2 "leadership_state" "Follower"

  -- Node 2 completes both election phases while node 0 is partitioned.
  disconnectNode 0
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  assertDetail 2 "current_view" 2

  dispatchSingle 2 1
  dispatchSingle 1 2

  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 2 "current_view" 3

  dispatchSingle 2 1
  dispatchSingle 1 2

  assertDetail 2 "leadership_state" "Leader"

  loopUntilSync

  -- Node 1 can then complete both phases and replace node 2.

  disconnectNode 0
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  assertDetail 1 "current_view" 3
  dispatchSingle 1 2
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Candidate"
  assertDetail 1 "current_view" 4

  dispatchSingle 1 2
  dispatchSingle 2 1

  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 4
