-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "pre_vote" do
  startNode 0
  emitSignature 2
  swapNodes 2 (trust := [1, 2])
  emitSignature 2

  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll

  -- All nodes just have config {0,1,2}
  assertCommitIdx 0 4
  assertAbsentConfig 0 1
  assertConfig 0 3 [0, 1, 2]

  assertCommitIdx 1 4
  assertAbsentConfig 1 1
  assertConfig 1 3 [0, 1, 2]

  assertCommitIdx 2 4
  assertAbsentConfig 2 1
  assertConfig 2 3 [0, 1, 2]

  -- Node 1 steps up as a pre-vote candidate
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"

  -- Node 2 responds to pre-vote request,
  -- but does not update its term
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Follower"
  assertDetail 2 "current_view" 2

  -- Node 1 becomes candidate and then leader for term 3
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Candidate"
  assertDetail 1 "current_view" 3
  dispatchSingle 1 2
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Leader"

  -- Node 0 is unable to become a candidate
  -- Node 0 steps down via CheckQuorum
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  assertDetail 0 "current_view" 2

  -- Upon receiving AppendEntries from Node 1,
  -- Node 0 becomes a follower in view 3
  dispatchSingle 1 0
  dispatchSingle 1 0
  assertDetail 0 "current_view" 3
  assertDetail 0 "leadership_state" "Follower"

  dispatchAll
  periodicOne 0 10
  dispatchAll

  assertCommitIdx 0 4
  assertDetail 0 "current_view" 3
  assertCommitIdx 1 4
  assertDetail 1 "current_view" 3
  assertCommitIdx 2 4
  assertDetail 2 "current_view" 3

  -- PreVotes can be denied if they are from an older log
  emitSignature 3
  periodicOne 1 10
  dispatchSingle 1 2

  -- Node 0 becomes a prevote candidate but cannot be elected
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  assertDetail 0 "current_view" 3
  summariseLog 0
  -- n[0]: 2.1, 2.2, 2.3, [2.4] (ts=351)
  assertDetail 2 "leadership_state" "Follower"
  summariseLog 2
  -- n[2]: 2.1, 2.2, 2.3, [2.4], 3.5 (ts=351)

  dispatchSingle 0 2
  dispatchSingle 2 0

  -- Node 0 is still a PreVoteCandidate as Node 2 denied its pre-vote request
  assertDetail 0 "leadership_state" "PreVoteCandidate"

  -- Node 0 will fall back to a follower when it receives an append entries
  dispatchSingle 1 0
  assertDetail 0 "leadership_state" "Follower"
