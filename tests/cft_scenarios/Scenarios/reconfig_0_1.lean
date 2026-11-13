-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "reconfig_0_1" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  -- Reconfig [0] -> [1]
  swapNodes 2 (retire := [0]) (trust := [1])
  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "retirement_phase" "Ordered"

  -- Sign reconfig
  emitSignature 2
  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "retirement_phase" "Signed"

  -- Commit signature
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  -- RTX of 0 is now committed, 0 emits a retired_committed transaction
  -- followed by a signature
  cleanupNodes 2 [0]
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6

  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "retirement_phase" "RetiredCommitted"

  -- 1 steps up as leader
  assertDetail 1 "leadership_state" "Leader"

  -- 1 commits a transaction
  replicate 3 "some_tx"
  emitSignature 3
  assertCommitIdx 1 8
