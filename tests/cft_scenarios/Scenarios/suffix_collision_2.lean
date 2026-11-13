-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "suffix_collision_2" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  trustNode 2 2
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertStateSync

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"

  replicate 2 ["hello world"]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll

  replicate 2 ["saluton mondo"]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  -- All nodes agree so far
  stateAll
  assertStateSync

  -- Node 0 is partitioned, and replicates more items
  disconnect 0 1
  disconnect 0 2

  replicate 2 ["drop me 1"]
  replicate 2 ["drop me 2"]
  replicate 2 ["drop me 3"]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll

  stateAll

  -- Node 1 calls an election, and wins
  periodicOne 1 110
  dispatchAll

  periodicAll 10
  dispatchAll -- This AppendEntries starts at a point that Node 1 would accept, but is dropped

  stateAll

  -- Node 1 replicates new entries
  replicate 3 ["keep me 1"]
  replicate 3 [signature]
  periodicAll 10
  dispatchAll

  replicate 3 ["keep me 2"]
  replicate 3 [signature]
  periodicAll 10
  dispatchAll

  stateAll

  -- Nodes 1 and 2 advance multiple terms and new entries
  periodicOne 2 110
  dispatchAll

  periodicAll 10
  dispatchAll

  replicate 4 ["keep me term 4"]
  replicate 4 [signature]

  periodicAll 10
  dispatchAll

  periodicOne 1 110
  dispatchAll

  periodicAll 10
  dispatchAll

  replicate 5 ["keep me term 5"]
  replicate 5 [signature]

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll

  -- Network heals
  connect 0 1
  connect 0 2

  -- Node 0 hears they were deposed
  periodicAll 10
  dispatchAll
  stateAll

  -- Node 1 tries to bring node 0 back in line
  -- But we get unlucky with timing, and node 1 continually follows up with a heartbeat before hearing the response
  -- This means it processes a useful NACK and then an unhelpful NACK
  periodicAll 10
  periodicOne 1 10
  dispatchAll

  periodicAll 10
  periodicOne 1 10
  dispatchAll

  periodicAll 10
  periodicOne 1 10
  dispatchAll

  stateAll
  assertStateSync
