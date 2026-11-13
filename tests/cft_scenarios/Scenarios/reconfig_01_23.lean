-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Reconfigures from [0, 1] to [2, 3], with 0 staying leader while the reconfiguration is in-progress
initialize scenario "reconfig_01_23" do
  startNode 0
  emitSignature 2
  assertCommitIdx 0 2

  trustNode 2 1
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertCommitIdx 1 4
  -- Initial network state [0, 1], all nodes in sync

  -- Reconfig [0, 1] -> [2, 3]
  swapNodes 2 (retire := [0, 1]) (trust := [2, 3])
  emitSignature 2
  -- 0 knows its retirement is signed
  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "retirement_phase" "Signed"

  -- 0 replicates, and commits the reconfiguration
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertDetail 0 "retirement_phase" "Completed"
  -- 0 has now committed its retirement and that of 1, but stays on as Leader
  -- to produce a retired_committed
  assertDetail 0 "leadership_state" "Leader"
  cleanupNodes 2 [0, 1]
  emitSignature 2

  periodicAll 10
  dispatchAll
  assertCommitIdx 0 8
  -- With retired_committed committed, 0 now steps down
  assertDetail 0 "leadership_state" "None"
  assertDetail 0 "retirement_phase" "RetiredCommitted"

  -- One of the continuing nodes has become leader
  emitSignature 3
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 2 9
  assertCommitIdx 3 9

  -- 0 becomes a follower again, because it receives messages
  -- from 2 before 2 realises 0 is retired committed.
  -- But 0 does not attempt to run for election
  -- because it knows it is retired committed
  assertDetail 0 "retirement_phase" "RetiredCommitted"
  assertDetail 0 "leadership_state" "Follower"
  periodicOne 0 150
  assertDetail 0 "retirement_phase" "RetiredCommitted"
  assertDetail 0 "leadership_state" "Follower"

  -- the network continues
  replicate 3 "some_tx"
  emitSignature 3
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 2 11
  assertCommitIdx 3 11
