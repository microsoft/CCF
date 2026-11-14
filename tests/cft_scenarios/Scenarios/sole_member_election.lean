-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node which is the only member of its configuration wins an election
-- without asking for a vote. The primary, node 2, retires itself and node 0.
-- Node 1 learns that the configuration which leaves it alone is committed,
-- times out, and becomes primary at once.
-- Found by `cft_model_driver --explore`, from
-- `retired_committed_delayed_nomination`.
initialize scenario "sole_member_election" do
  startNode 0
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicOne 0 10
  dispatchSingle 0 2
  periodicOne 2 100
  dispatchSingle 2 1
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  dispatchSingle 2 1
  dispatchSingle 1 2
  swapNodes 3 [0, 2] []
  replicate 3 [signature]
  periodicOne 2 10
  dispatchSingle 2 1
  dispatchSingle 1 2
  periodicOne 2 10
  dispatchSingle 2 1
  periodicOne 1 100

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 3
  assertDetail 1 "leadership_state" "Leader"
  assertCommitIdx 1 5
  assertDetail 2 "leadership_state" "Leader"
  assertCommitIdx 2 5
