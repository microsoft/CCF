-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Start a 3-node network
initialize scenario "liveness_through_conflict" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNodes 2 [1, 2]
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  periodicAll 10
  dispatchAll

  assertStateSync

  stateAll

  -- Original primary node 0 produces a small suffix, doesn't get to share it
  replicate 2 [signature]
  replicate 2 [signature]

  -- Node 1 calls and wins an election
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchOne 1
  dispatchOne 2
  assertDetail 1 "leadership_state" "Candidate"
  dispatchOne 1
  dispatchOne 2
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 produces multiple heartbeat AEs before emitting a signature!
  periodicOne 1 10
  periodicOne 1 10
  replicate 3 [signature]

  -- With a few iterations node 1 should be able to bring all nodes in-sync
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
