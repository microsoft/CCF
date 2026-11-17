-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- This scenario checks that an election completes successfully and with the right
-- quorums when a reconfiguration is in flight
-- Note: This is a fix for the issue described in https://github.com/microsoft/CCF/issues/3948
initialize scenario "election_while_reconfiguration" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 [signature] -- Initial configuration: C0=[0,1]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertStateSync

  -- Reconfiguration: add three nodes
  trustNodes 2 [2, 3, 4] -- New configuration: C1=[0,1,2,3,4] in term 2 (quorum=3)
  replicate 2 [signature]
  periodicAll 10

  -- New nodes first respond with NACKs as they don't have full history
  dispatchOne 0

  periodicAll 10
  dispatchOne 2
  dispatchOne 3
  dispatchOne 4

  periodicAll 10
  dispatchOne 0

  stateAll -- All nodes have seen the reconfiguration entry
  assertCommitIdx 0 4 -- But it is not committed, because 0 has not heard back from 1

  -- One new node calls for an election (e.g. because primary 0 is dead)
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchOne 2

  dispatchOne 3 -- 3 sends vote response to 2
  assertDetail 2 "leadership_state" "PreVoteCandidate"

  dispatchOne 4 -- 4 sends vote response to 2:

  -- Even though PreVoteCandidate 2 has received a majority of votes in C1, it does not have any votes
  -- from C0 and so remains PreVoteCandidate
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  stateAll

  dispatchOne 0 -- 0 sends vote response to 2
  assertDetail 2 "leadership_state" "PreVoteCandidate"

  dispatchOne 1 -- 1 sends vote response to 2

  -- Eventually, 2 has received votes from a majority of nodes in _both_ configurations
  stateAll
  assertDetail 2 "leadership_state" "Candidate"
  dispatchOne 2
  dispatchOne 0
  dispatchOne 1
  dispatchOne 3
  dispatchOne 4
  assertDetail 2 "leadership_state" "Leader"

  -- But commit has not progressed yet
  assertCommitIdx 2 4

  -- New primary appends a new committable entry to confirm its primaryship
  replicate 3 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
