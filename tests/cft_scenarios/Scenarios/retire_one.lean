-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "retire_one" do
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

  -- # ... with the same logs up to index 11
  replicate 2 ["txAtIdx1"]
  replicate 2 ["txAtIdx2"]
  replicate 2 ["txAtIdx3"]
  replicate 2 ["txAtIdx4"]
  replicate 2 ["txAtIdx5"]
  replicate 2 ["txAtIdx6"]
  replicate 2 [signature]
  periodicAll 30
  dispatchAll

  assertCommitIdx 0 11
  assertCommitIdx 1 4

  periodicAll 30
  dispatchAll
  assertStateSync

  assertCommitIdx 0 11
  assertCommitIdx 1 11

  -- # the leader 0 reconfigures to remove 1 at index 12
  swapNodes 2 (retire := [1])

  periodicAll 30
  dispatchAll

  stateAll
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  -- # Index 13 is a signature, index 14 some random transaction and index 15 is a signature.
  replicate 2 [signature]
  assertCommitIdx 0 11

  replicate 2 ["txAt10"]
  assertCommitIdx 0 11

  replicate 2 [signature]
  assertCommitIdx 0 11

  periodicAll 30
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 1 "membership_state" "Retired"
  assertDetail 1 "retirement_phase" "Signed"

  -- # leader 0 commits 15
  assertCommitIdx 0 15
  assertCommitIdx 1 11

  -- Since the retirement of 1 is now committed, 0 emits a retired_committed transaction
  -- followed by a signature
  cleanupNodes 2 [1]
  replicate 2 [signature]
  -- 0 commits immediately, now that 1 is out of configuration
  assertCommitIdx 0 17

  periodicAll 30
  dispatchAll
  -- 1 does not get notified, because its RC is committed
  assertCommitIdx 1 11
  -- 1 does not know its retirement is committed, let alone retired_committed
  assertDetail 1 "membership_state" "Retired"
  assertDetail 1 "retirement_phase" "Signed"

  -- and so it would attempt to become candidate
  -- periodic_all,100
  -- assert_is_candidate,1

  -- but the operator shuts it down
  disconnect 0 1

  -- and so 1 can continue
  replicate 2 ["some_tx"]
  replicate 2 [signature]
  assertCommitIdx 0 19
