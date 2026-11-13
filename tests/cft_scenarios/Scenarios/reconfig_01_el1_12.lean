-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Reconfigures from [0, 1] to [1, 2], with 1 becoming leader while the reconfiguration is in-progress
initialize scenario "reconfig_01_el1_12" do
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

  -- Reconfig [0, 1] -> [1, 2]
  swapNodes 2 (retire := [0]) (trust := [2])
  emitSignature 2

  -- Leader (0) replicates
  periodicOne 0 10
  dispatchOne 0

  -- But node 1 runs for election before ack/cmt
  periodicOne 1 150
  dispatchAll
  dispatchAll
  -- 1 wins the election, but has not committed the reconfiguration
  assertDetail 1 "leadership_state" "Leader"
  assertCommitIdx 1 4

  -- 1 signs to extend, observes retirement committed
  emitSignature 3
  periodicAll 10
  dispatchAll
  assertCommitIdx 1 7
  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 2 "leadership_state" "Follower"

  -- Now that the retirement of 0 is committed, 1 schedules retired_committed for 0
  cleanupNodes 3 [0]
  emitSignature 3
  periodicAll 10
  dispatchAll
  dispatchAll
  -- retired_committed committed
  assertCommitIdx 1 9

  -- the operator shuts down 0
  disconnect 0 1
  disconnect 0 2

  -- the network continues
  replicate 3 "some_tx"
  emitSignature 3
  periodicAll 10
  dispatchAll
  dispatchAll
  assertCommitIdx 1 11
