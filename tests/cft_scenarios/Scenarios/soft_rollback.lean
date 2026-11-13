-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A higher-term vote request must not roll back a node's unsigned suffix.
-- Five nodes let a short-log candidate obtain a genuine pre-vote quorum.
initialize scenario "soft_rollback" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  trustNodes 2 [2, 3, 4]
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertStateSync

  -- Node 0 emits an entry, and signature
  replicate 2 "hello world"
  emitSignature 2
  periodicAll 10

  -- But only succeeds in replicating this to node 1
  dropPendingTo 0 2
  dropPendingTo 0 3
  dropPendingTo 0 4
  dispatchAll

  -- Two copies retain the signed suffix, below the three-node commit quorum.
  stateAll
  assertCommitIdx 0 6
  assertLastTxid 1 "2.8"

  -- Disconnect node 0. Not strictly required, but simplifies work going forwards
  disconnectNode 0

  -- Node 1 wins both election phases with the short-log followers.
  periodicOne 1 110
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchAll
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 may do work in this term, but crucially doesn't get as far as emitting a signature
  replicate 3 "saluton mondo"
  replicate 3 "ah well nevertheless"
  stateAll
  assertLastTxid 1 "3.10"

  -- Nodes 3 and 4 still have the same short log as node 2.
  -- Their pre-votes let node 2 become a real term-4 candidate.
  assertLastTxid 3 "2.6"
  assertLastTxid 4 "2.6"
  periodicOne 2 110
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchOne 2
  dispatchSingle 3 2
  dispatchSingle 4 2
  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 2 "current_view" 4

  -- Node 2's RequestVote reaches Node 1, causing it to advance term but not roll-back
  dispatchOne 2

  -- Node 1 should retain the whole state 3.10 it had previously
  stateAll
  assertDetail 1 "current_view" 4
  assertLastTxid 1 "3.10"
  assertDetail 2 "current_view" 4
  assertLastTxid 2 "2.6"

  -- Node 3's regular vote plus node 2's self-vote make node 1's vote decisive.
  dispatchSingle 3 2
  assertDetail 2 "leadership_state" "Candidate"

  -- Node 1 should not vote for node 2!
  dispatchOne 1
  assertDetail 2 "leadership_state" "Candidate"

  -- Leave node 4's positive regular vote response undelivered, then disconnect node 2.
  -- Node 1 can win a new election with node 0 and the short-log followers.
  reconnectNode 0
  disconnectNode 2

  -- Despite not being able to currently _commit_ the entries it holds, node 1
  -- should be able to win an election by advertising them!
  periodicOne 1 110
  dispatchAll
  stateAll
  assertDetail 1 "leadership_state" "Leader"

  -- Regardless of earlier disagreements, we can all agree now
  reconnectNode 2
  replicate 5 "place trace checker"
  emitSignature 5
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
