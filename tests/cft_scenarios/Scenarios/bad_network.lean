-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "bad_network" do
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

  trustNode 2 2
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"

  -- An initial entry is written and successfully replicated
  replicate 2 "helloworld"
  emitSignature 2

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync

  -- An additional entry takes much longer to replicate, as it is lost on bad connection between nodes
  replicate 2 "salutonmondo"
  emitSignature 2

  periodicAll 10
  dropPending 0
  dispatchAll

  periodicAll 10
  dropPending 0
  dispatchAll

  -- Before either follower times out, the message eventually reaches Node 1 (though not Node 2)
  periodicAll 10
  dropPendingTo 0 2

  -- N0->N1 "Are you up-to-date?"
  dispatchAllOnce

  -- N1->N0 "No, I'm not"
  dispatchAllOnce

  -- N0->N1 "Here's the bit you're missing"
  dispatchAllOnce

  -- N1->N0 "Ok, I've got it"
  dropPendingTo 1 0 -- This is dropped!
  dispatchAllOnce

  -- At this point, 2.10 is committed, but nobody knows that yet

  -- Eventually Node 2 is partitioned for so long that it calls an election
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  assertDetail 2 "current_view" 2

  -- But this pre-vote request is lost!
  periodicAll 10
  assertDetail 1 "leadership_state" "Follower"
  dropPending 1 -- The ACKs from 1 are constantly dropped
  dropPending 2
  dispatchAllOnce

  periodicAll 10
  dropPending 1 -- The ACKs from 1 are constantly dropped
  dropPending 2
  dispatchAllOnce

  -- Eventually Node 2 is partitioned for so long that it calls many more elections, which nobody hears about
  periodicOne 2 100
  dropPending 2

  periodicOne 2 100
  dropPending 2

  periodicOne 2 100
  dropPending 2

  assertDetail 2 "leadership_state" "PreVoteCandidate"
  assertDetail 2 "current_view" 2

  -- Eventually Node 1 stops hearing from Node 0, and calls an election
  stateAll
  dropPending 1
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchAllOnce -- Finally, everyone hears about this!

  dropPending 0 -- Node 0's pre-vote response is dropped.
  dispatchAllOnce -- Node 2 grants the more up-to-date node 1 a pre-vote.
  assertDetail 1 "leadership_state" "Candidate"
  assertDetail 1 "current_view" 3

  -- The regular vote round also succeeds using only node 2's response.
  dispatchAllOnce
  dropPending 0
  dispatchAllOnce

  -- Node 1 is now primary, though it still doesn't know that 2 is committed
  stateAll
  assertDetail 1 "leadership_state" "Leader"

  -- Now we allow the network to heal and return to normal
  periodicAll 10
  dispatchAllOnce -- "Where are you?"

  periodicAll 10
  dispatchAllOnce -- "Out-of-date"

  periodicAll 10
  dispatchAllOnce -- "Here's latest"

  stateAll
  assertStateSync
