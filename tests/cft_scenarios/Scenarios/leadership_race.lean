-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Exercise operations which race with a leader losing its quorum. A client write
-- and leadership-transfer request are ignored while no primary exists, and the
-- surviving quorum elects a replacement before the network heals.
initialize scenario "leadership_race" do
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

  dropPending 0
  disconnectNode 0
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  replicate latest ["write while leaderless"]
  nominateSuccessor 0
  stateOne 0

  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Candidate"
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Leader"

  loopUntilSync
