-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Model two backups timing out together. Once node 1 wins, node 3 rejects node
-- 2's delayed same-term vote request because it knows the leader. Node 2 then
-- ignores the delayed rejection after entering a new pre-vote round.
initialize scenario "delayed_vote_requests" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2, 3, 4]
  emitSignature 2
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 1 4
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Candidate"

  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchSingle 2 3
  dispatchSingle 3 2
  dispatchSingle 2 4
  dispatchSingle 4 2
  assertDetail 2 "leadership_state" "Candidate"

  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 1 4
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Leader"

  dispatchSingle 1 3
  dropPendingTo 1 2
  periodicOne 1 10
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Follower"

  dispatchSingle 2 3
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchSingle 3 2
  assertDetail 2 "leadership_state" "PreVoteCandidate"

  dropPending 0
  dropPending 1
  dropPending 2
  dropPending 3
  dropPending 4
  loopUntilSync
