-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Deliver a leadership nomination after its recipient has advanced to a later
-- term. The delayed proposal must be ignored without changing the candidate.
initialize scenario "late_nomination" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2]
  emitSignature 2

  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync
  assertDetail 0 "current_view" 2
  assertDetail 2 "current_view" 2

  -- Equal progress makes node 2 the deterministic nomination target.
  nominateSuccessor 0

  -- Node 2 obtains a pre-vote from node 1, without receiving the queued proposal.
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  assertDetail 2 "current_view" 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 2 "current_view" 3

  -- The term-2 proposal is now stale and must not restart node 2's candidacy.
  dispatchSingle 0 2
  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 2 "current_view" 3

  -- Complete the election and converge the nodes.
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Leader"
  loopUntilSync
