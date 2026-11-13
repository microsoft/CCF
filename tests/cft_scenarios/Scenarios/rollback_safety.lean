-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Set up 5 node network
initialize scenario "rollback_safety" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNodes 2 [1, 2, 3, 4]
  emitSignature 2

  dispatchAll

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  assertCommitIdx 0 4

  assertStateSync
  -- All nodes in agreement

  -- Nodes 3 and 4 are partitioned, so the remaining 3 need unanimity for commit
  disconnectNode 3
  disconnectNode 4

  -- Node 0 produces a suffix
  replicate 2 "hello"
  emitSignature 2
  replicate 2 "world"
  emitSignature 2

  -- Node 0 shares this suffix with 1
  periodicOne 0 10
  dropPendingTo 0 2
  dispatchOne 0

  -- Node 1 calls and wins an election
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  assertDetail 1 "leadership_state" "Candidate"
  dispatchOne 1
  dispatchOne 0
  dispatchOne 2
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 sends a late heartbeat, producing a NACK
  dropPendingTo 1 0
  dropPendingTo 2 1 -- Ensure nothing else is in the message queue
  dispatchOne 1

  -- NB: The 2->1 channel now contains a NACK at 2.4.
  -- We need to keep this around, and don't touch this channel for a while

  -- Node 0 calls and wins an election
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dispatchOne 0
  dispatchOne 1
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Candidate"
  dispatchOne 0
  dispatchOne 1
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Leader"

  -- Node 0 emits a fresh signature, so that they can advance commit
  emitSignature 4

  -- Node 0 sends heartbeats
  periodicOne 0 10
  dispatchOne 0

  -- Node 0 receives responses, setting initial next_index
  dispatchOne 1
  dispatchSingle 2 0 -- NB: dispatch_single, to avoid touching the NACK for 1
  dispatchSingle 2 0

  -- Node 0 sends useful AEs
  periodicOne 0 10
  dispatchOne 0

  -- Node 0 receives response, advancing commit
  dispatchOne 1
  dispatchSingle 2 0
  dispatchSingle 2 0

  assertCommitIdx 0 9

  -- Note that the peers have not yet advanced commit
  assertCommitIdx 1 4
  assertCommitIdx 2 4

  assertCommitSafety 0

  -- Node 1 calls and wins an election
  -- To win, it now needs a vote from one of the previous dead nodes (we can't touch the 2->1 channel!)
  reconnectNode 3
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchOne 1
  dispatchOne 0
  dispatchOne 3
  assertDetail 1 "leadership_state" "Candidate"
  dispatchOne 1
  dispatchOne 0
  dispatchOne 3
  assertDetail 1 "leadership_state" "Leader"

  -- Don't need this heartbeat AE, drop it
  dropPendingTo 1 2

  -- Now we deliver a stale NACK
  dispatchSingle 2 1

  -- 1 may now believe 2's log is too short!

  -- Node 1 produces AEs
  periodicOne 1 10

  stateAll
  assertCommitSafety 0 -- Sanity check, we're fine here

  -- This AE reaches 2
  dispatchSingle 1 2

  -- 2 had better not rollback and break commit safety!
  stateAll
  assertCommitSafety 0
