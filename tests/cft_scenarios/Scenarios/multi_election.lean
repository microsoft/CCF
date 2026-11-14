-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "multi_election" do
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
  assertCommitIdx 0 6

  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"

  replicate 2 ["helloworld"]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll

  replicate 2 ["salutonmondo"]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll

  -- Node 0 is idle/disconnected for too long, so Node 1 takes over
  periodicOne 1 110
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync

  -- NB: Node 1 i now primary in term 2. There is no primary in term 1,
  -- and attempting to replicate in it will produce an error
  replicate 3 ["my world now"]
  replicate 3 [signature]
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync

  replicate 3 ["im in charge"]
  replicate 3 [signature]
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync

  -- Node 1 is partitioned for a while
  disconnect 0 1
  disconnect 1 2

  -- While 1 was partitioned, it continued to receive transactions!
  replicate 3 ["i think i am still in charge"]
  replicate 3 ["i am going to continue like i am the primary"]
  replicate 3 ["until i am told otherwise"]

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  -- The partition lasts long enough that Node 0 starts an election
  periodicOne 0 110

  -- It passes the election
  periodicAll 10
  dispatchAll

  -- The network heals
  connect 0 1
  connect 1 2

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  -- Election has now succeeded, and new primary can replicate in term 3
  replicate 4 ["look at me i am the primary now"]
  replicate 4 [signature]

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll

  assertStateSync
