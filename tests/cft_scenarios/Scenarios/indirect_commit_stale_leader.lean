-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Reproduce a stale-leader shape where an entry from an old term is only
-- committed indirectly by a later leader's signature.
--
-- Node 0 appends e2/s2 locally in term 2. Node 1 then wins term 3 with node 2,
-- and appends a conflicting e3/s3 at the same indexes, but does not replicate it.
-- Node 0 wins term 4 with node 2, keeps its committable e2/s2 suffix, appends
-- e4/s4, and commits through the term-4 signature.
initialize scenario "indirect_commit_stale_leader" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNodes 2 [1, 2]
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertStateSync

  -- Node 0 locally appends and signs a term-2 client entry at indexes 5 and 6,
  -- but does not replicate it.
  replicate 2 "e2"
  emitSignature 2
  assertLastTxid 0 "2.6"

  -- Node 1 times out and wins term 3 with node 2. Node 0 observes the newer-term
  -- vote request and steps down, but Node 1 only needs node 2's vote to win.
  periodicOne 1 110
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 0
  dispatchSingle 1 2
  dispatchSingle 0 1
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Candidate"
  dispatchSingle 1 0
  dispatchSingle 1 2
  dispatchSingle 0 1
  dispatchSingle 2 1
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 appends and signs a conflicting term-3 entry at indexes 5 and 6, but
  -- keeps it local. Node 2 still has only the shared prefix committed to index 4.
  replicate 3 "e3"
  emitSignature 3
  assertLastTxid 1 "3.6"
  assertCommitIdx 1 4
  assertCommitIdx 2 4

  -- Isolate stale leader Node 1. Node 0 can now win term 4 with Node 2 because
  -- Node 0's committable suffix is at least as up-to-date as Node 2's prefix.
  disconnectNode 1
  periodicOne 0 110
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Candidate"
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Leader"
  assertLastTxid 0 "2.6"

  -- Node 0 appends and signs in term 4, then brings Node 2 up to index 8. Committing
  -- s4 at index 8 indirectly commits the earlier term-2 e2/s2 suffix at 5 and 6,
  -- while stale leader Node 1 still has the conflicting e3/s3 suffix.
  replicate 4 "e4"
  emitSignature 4

  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll

  assertCommitIdx 0 8
  assertCommitSafety 0
  assertLastTxid 2 "4.8"
  assertDetail 1 "leadership_state" "Leader"
  assertLastTxid 1 "3.6"

  loopUntilSync
