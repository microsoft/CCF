-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "check_quorum_012_0" do
  startNode 0
  replicate 2 [signature]
  swapNodes 2 (trust := [1, 2])
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  -- All nodes believe that the only configuration is {0,1,2}
  assertStateSync
  assertAbsentConfig 0 1
  assertConfig 0 3 [0, 1, 2]

  disconnectNode 0
  swapNodes 2 (retire := [1, 2])
  replicate 2 [signature]

  -- Only node 0 knows about config {0}, as it is partitioned from nodes 1 and 2
  assertConfig 0 3 [0, 1, 2]
  assertConfig 0 5 [0]

  assertConfig 1 3 [0, 1, 2]
  assertAbsentConfig 1 5
  assertConfig 2 3 [0, 1, 2]
  assertAbsentConfig 2 5

  -- Node 0 should step down via CheckQuorum
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"

  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertDetail 0 "leadership_state" "Follower"
  assertDetail 1 "leadership_state" "Leader"
