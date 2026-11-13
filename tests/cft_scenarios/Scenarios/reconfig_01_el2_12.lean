-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Reconfigures from [0, 1] to [1, 2], with 2 becoming leader while the reconfiguration is in-progress
initialize scenario "reconfig_01_el2_12" do
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
  -- Need to "catch up" 2 to give it a configuration
  -- otherwise it will not be able to run for election
  periodicOne 2 10
  dispatchOne 2
  periodicOne 0 10
  dispatchOne 0

  -- But node 2 runs for election before ack/cmt
  periodicOne 2 150
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchAll
  dispatchAll
  -- which it wins, since it is sufficiently up to date
  assertDetail 2 "leadership_state" "Leader"

  -- 2 signs to extend, observes retirement committed
  emitSignature 3
  periodicAll 10
  dispatchAll
  assertCommitIdx 2 7
  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Leader"

  -- Now that the retirement of 0 is committed, 2 schedules retired_committed
  cleanupNodes 3 [0]
  emitSignature 3
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  -- retired_committed committed
  assertCommitIdx 2 9

  -- the operator shuts down 0
  disconnect 0 1
  disconnect 0 2

  -- the network continues
  replicate 3 "some_tx"
  emitSignature 3
  periodicAll 10
  dispatchAll
  dispatchAll
  assertCommitIdx 2 11
