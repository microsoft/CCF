-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Test what happens when a node is re-elected, and receives messages from previous terms
initialize scenario "reelection" do
  startNode 0
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNodes 2 [1, 2]
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"

  -- Start from a steady state
  periodicAll 10
  dispatchAll
  assertStateSync

  -- Produce more entries
  emitSignature 2
  emitSignature 2

  -- Send AEs, but don't get responses yet
  periodicOne 0 10
  dispatchOne 0

  -- Time out, call a new election
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"

  -- Receive vote responses and AEs
  dispatchAll

  stateAll
  assertDetail 0 "leadership_state" "Leader"
