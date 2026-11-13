-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Regression test for a previous same-term election-safety violation involving
-- pre-vote.
--
-- Nodes 0 and 2 become candidates in term 3. Node 0 wins with node 1's vote.
-- Node 1 then times out into PreVoteCandidate without changing its vote for
-- node 0. Previously, an unmatched AppendEntries from node 0 made node 1 step
-- down and cleared that vote, so node 1 granted node 2's delayed vote request
-- and both nodes became leaders in term 3. This test asserts that same-term
-- step-down now preserves node 1's vote, so node 2 remains a candidate.
initialize scenario "pre_vote_double_leader" do
  startNode 0
  replicate 2 [signature]

  trustNodes 2 [1, 2]
  replicate 2 [signature]

  -- Bring every node to the same committed prefix.
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync
  assertCommitIdx 0 4

  -- Give future leader node 0 a longer committable suffix. Its first heartbeat
  -- will refer to index 5, which node 1 does not have.
  replicate 2 [signature]
  assertLastTxid 0 "2.5"
  assertLastTxid 1 "2.4"
  assertLastTxid 2 "2.4"
  dropPending 0

  -- Node 0 first fails CheckQuorum. Nodes 0 and 2 then start pre-vote rounds in
  -- term 2.
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  dropPending 0
  periodicOne 0 100
  periodicOne 2 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  assertDetail 0 "current_view" 2
  assertDetail 2 "current_view" 2

  -- Short-log node 1 grants a pre-vote to both prospective candidates.
  dropPendingTo 0 2
  dropPendingTo 2 0
  dispatchSingle 0 1
  dispatchSingle 2 1
  dispatchSingle 1 0
  dispatchSingle 1 2
  assertDetail 0 "leadership_state" "Candidate"
  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 0 "current_view" 3
  assertDetail 2 "current_view" 3

  -- Node 1 votes for node 0, electing it. Keep node 2's request delayed.
  dropPendingTo 0 2
  dropPendingTo 2 0
  dispatchSingle 0 1
  dispatchSingle 1 0
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 0 "current_view" 3
  assertDetail 2 "leadership_state" "Candidate"

  -- Retain only node 0's unmatched AppendEntries to node 1.
  dropPendingTo 0 2

  -- Node 1 keeps its term-3 vote for node 0 when it becomes a pre-vote
  -- candidate. Drop its speculative pre-vote requests.
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  assertDetail 1 "current_view" 3
  dropPending 1

  -- Node 0's unmatched AppendEntries makes node 1 a follower without teaching it
  -- the leader. The same-term transition preserves node 1's vote for node 0.
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 1 "current_view" 3
  assertLastTxid 1 "2.4"
  dropPending 1

  -- Node 1 rejects node 2's delayed request because it already voted for node 0.
  -- Node 2 remains a candidate, preventing a second leader in term 3.
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 0 "leadership_state" "Leader"
  -- Before same-term step-down preserved voted_for, node 1 granted this vote and
  -- this assertion expected node 2 to have become a second leader in term 3.
  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 0 "current_view" 3
  assertDetail 2 "current_view" 3

  -- Preserve a path back to liveness for the scenario driver. With all pending
  -- messages dropped, node 0 can converge the network after proving the second
  -- election was rejected.
  dropPending 0
  dropPending 1
  dropPending 2
  loopUntilSync
