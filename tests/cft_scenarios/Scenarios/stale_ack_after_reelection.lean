-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A primary ignores an acknowledgement from an earlier term in which it was
-- also primary. Node 4 is elected in term 3, and the acknowledgement of node 1
-- is held. Node 0 is elected in term 4, and node 4 again in term 5. Only then
-- does the acknowledgement arrive.
-- Found by `cft_model_driver --explore`, from `fancy_election_2`.
initialize scenario "stale_ack_after_reelection" do
  startNode 0
  trustNode 2 1
  trustNode 2 4
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicOne 4 110
  dispatchAll
  holdNth 1 4 0
  periodicOne 0 110
  dispatchAll
  periodicOne 4 110
  dispatchAll
  dispatchHeld 0

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 4
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 4
  assertDetail 4 "leadership_state" "Leader"
  assertCommitIdx 4 4
