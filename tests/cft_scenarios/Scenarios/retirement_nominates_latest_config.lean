-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- When peers tie on match index, nomination breaks ties by the latest
-- configuration each peer belongs to, even when retired peers have higher IDs.
initialize scenario "retirement_nominates_latest_config" do
  startNode 0
  replicate 2 [signature]

  trustNodes 2 [1, 2, 3]
  replicate 2 [signature]
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync
  assertCommitIdx 0 4
  assertConfig 0 3 [0, 1, 2, 3]

  -- Retire node 3 and commit its retirement without confirming retired_committed
  -- yet, so node 3 remains in all_other_nodes with match_idx 6 but is absent
  -- from all remaining active configurations.
  swapNodes 2 (retire := [3])
  replicate 2 [signature]
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertConfig 0 5 [0, 1, 2]
  assertDetail 3 "retirement_phase" "Completed"

  -- Append an uncommitted reconfiguration retiring node 2 (while keeping node 3
  -- retired): node 2 is absent from the newest configuration (at 7) but present
  -- in configuration 5, while node 1 is in configuration 7. All three peers
  -- still share match_idx 6.
  swapNodes 2 (retire := [2, 3])
  assertConfig 0 7 [0, 1]

  nominateSuccessor 0
  assertPending 0 1 1
  assertPending 0 2 0
  assertPending 0 3 0

  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Candidate"
  assertDetail 1 "current_view" 3

  dispatchAll
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 3
  loopUntilSync
