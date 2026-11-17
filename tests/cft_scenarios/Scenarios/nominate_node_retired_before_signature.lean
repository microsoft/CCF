-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node which is never in its latest configuration when it holds a signature
-- does not start its election timer, and ignores a nomination. Node 0 replaces
-- itself with node 1 before it first signs. Its retirement is committed, and
-- not confirmed, when node 1 is elected and nominates it.
-- Found by `cft_model_driver --explore`.
initialize scenario "nominate_node_retired_before_signature" do
  startNode 0

  -- 0 retires and 1 joins at 2.2, before 0 signs at 2.3
  swapNodes 2 [0] [1]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 3
  assertDetail 0 "retirement_phase" "Completed"

  -- 0 stands down for want of an acknowledgement, and 1 is elected in term 3
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  dispatchAll
  assertCommitIdx 1 3
  periodicOne 1 100
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 3

  -- 1 nominates 0, the only node which it knows, and 0 ignores it
  nominateSuccessor 1
  dispatchAll
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 0 "current_view" 3
  assertDetail 1 "leadership_state" "Leader"
