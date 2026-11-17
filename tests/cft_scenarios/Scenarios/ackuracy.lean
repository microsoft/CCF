-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Start a 5-node network
initialize scenario "ackuracy" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNodes 2 [1, 2, 3, 4]
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  periodicAll 10
  dispatchAll

  assertStateSync

  stateAll

  -- Node 0 produces an unshared suffix
  replicate 2 [signature]
  replicate 2 [signature]
  replicate 2 [signature]

  -- Node 1 calls and wins an election
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 3
  dispatchSingle 3 1
  assertDetail 1 "leadership_state" "Candidate"
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 3
  dispatchSingle 3 1
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 produces a conflicting suffix
  replicate 3 [signature]
  replicate 3 [signature]
  replicate 3 [signature]

  -- Node 1 tries to share this
  periodicOne 1 10
  dropPending 1 -- First forget prior messages
  periodicOne 1 10 -- This is an empty heartbeat
  dispatchSingle 1 0

  -- The 0->1 channel now contains a NACK, which we take great care to retain for a while!
  summariseMessages 0 1

  -- Node 1 shares their suffix successfully with node 2
  dispatchSingle 1 2
  dispatchSingle 2 1
  periodicOne 1 10
  dispatchSingle 1 2

  -- Node 2 calls and wins an election
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchSingle 2 3
  dispatchSingle 3 2
  dispatchSingle 2 4
  dispatchSingle 4 2
  assertDetail 2 "leadership_state" "Candidate"
  dispatchSingle 2 3
  dispatchSingle 3 2
  dispatchSingle 2 4
  dispatchSingle 4 2
  assertDetail 1 "leadership_state" "Leader"

  -- Node 2 updates node 0 with the suffix produced by node 1
  dropPending 2
  periodicOne 2 10
  dispatchOne 2
  dispatchSingle 0 2
  periodicOne 2 10
  dispatchOne 2
  dispatchSingle 0 2
  periodicOne 2 10
  dispatchOne 2
  dispatchSingle 0 2

  -- Node 2 extends this suffix, shares it with node 0
  replicate 4 [signature]
  replicate 4 [signature]
  periodicOne 2 10
  dispatchSingle 2 0

  -- Node 1 calls and wins an election
  dropPending 1
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 1 4
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Candidate"
  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 1 4
  dispatchSingle 4 1
  assertDetail 1 "leadership_state" "Leader"
  dropPending 1

  -- Node 1 creates an alternative branch from 2's recent suffix
  replicate 5 [signature]
  replicate 5 [signature]

  -- Node 1 shares this with 3, so that it is only needs 1 more ACK to advance commit
  periodicOne 1 10
  dispatchSingle 1 3
  dispatchSingle 3 1
  periodicOne 1 10
  dispatchSingle 1 3
  dispatchSingle 1 3
  dispatchSingle 3 1
  dispatchSingle 3 1

  -- Node 1 finally receives that stale NACK from 0
  dropPending 1
  stateAll
  summariseMessages 0 1
  dispatchSingle 0 1
  summariseMessages 0 1

  -- Node 1 now has an underestimate of its match with 0, so will produce some redundant (matching) AEs
  periodicOne 1 10

  -- The lead AE in the 1->0 should now be a NOP, containing entirely entries that 0 already has
  dispatchSingle 1 0

  -- What did 0 produce as the response, and how does node 1 handle that?
  dispatchSingle 0 1

  summariseLogsAll
  stateAll

  assertCommitSafety 1
