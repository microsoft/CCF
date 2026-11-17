-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node ignores a nomination until its election timer starts, which is when
-- it holds a signature while it is in its latest configuration. Node 1 is
-- added and removed between two signatures, so no signature finds it in its
-- latest configuration, though the second one covers the configuration which
-- added it, and that configuration is still active.
-- Found by `cft_model_driver --explore`.
initialize scenario "nominate_node_removed_before_signature" do
  startNode 0
  replicate 2 [signature]

  -- 1 and 2 join at 2.3, 1 retires at 2.4, and 0 signs at 2.5
  swapNodes 2 [] [1, 2]
  swapNodes 2 (retire := [1])
  replicate 2 [signature]

  -- Only 1 receives the entries, so 0 commits none of them
  disconnect 0 2
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  assertLastTxid 1 "2.5"
  assertDetail 1 "retirement_phase" "Signed"
  assertCommitIdx 0 2
  assertConfig 0 3 [0, 1, 2]

  -- 0 nominates 1, which has the most entries, and 1 ignores it
  nominateSuccessor 0
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 1 "current_view" 2

  -- 2 catches up, and 0 commits the retirement of 1
  reconnect 0 2
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 5
  assertAbsentConfig 0 3
  assertLastTxid 2 "2.5"
