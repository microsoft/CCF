-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- The signature which follows the removal of a node is rolled back on that
-- node, and the removal is not.
-- No acknowledgement is delivered before the end, so nothing commits, and a
-- node which becomes primary keeps the entries after its last signature.
initialize scenario "retirement_signature_rollback" do
  startNode 0
  trustNodes 2 [1, 2, 3, 4]
  replicate 2 [signature]
  dispatchAll
  periodicOne 0 10
  dispatchOne 0
  -- Initial network state [0, 1, 2, 3, 4], with nothing committed

  -- 1 is elected in term 3, with the votes of 0 and 2
  periodicOne 1 100
  dispatchOne 1
  dispatchSingle 0 1
  dispatchSingle 2 1
  dispatchOne 1
  dispatchSingle 0 1
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Leader"

  -- 1 removes 4 at index 4, which every node receives
  swapNodes 3 [4] []
  periodicOne 1 10
  dispatchOne 1
  assertDetail 4 "retirement_phase" "Ordered"

  -- 1 signs at index 5, and only 4 receives the signature
  replicate 3 [signature]
  periodicOne 1 10
  dispatchSingle 1 4
  assertDetail 4 "retirement_phase" "Signed"
  assertLastTxid 4 "3.5"

  -- 2 holds the removal without its signature. It is elected in term 4, with
  -- the votes of 0 and 3, and keeps the removal
  periodicOne 2 100
  dispatchOne 2
  dispatchSingle 0 2
  dispatchSingle 3 2
  dispatchOne 2
  dispatchSingle 0 2
  dispatchSingle 3 2
  dispatchOne 2
  assertDetail 2 "leadership_state" "Leader"
  assertLastTxid 2 "3.4"

  -- 2 appends a transaction at index 5, which replaces the signature on 4
  replicate 4 ["x"]
  periodicOne 2 10
  dispatchSingle 2 4
  assertLastTxid 4 "4.5"
  assertDetail 4 "membership_state" "Retired"
  assertDetail 4 "retirement_phase" "Ordered"
  assertCommitIdx 4 0
