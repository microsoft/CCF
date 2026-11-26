-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A follower acknowledges a heartbeat which ends before an entry of a later
-- term that it still holds. Nothing is committed, so a node which is elected
-- keeps the transaction after its last signature. Node 1 appends an entry in
-- term 3 after that transaction, and node 0 is then elected in term 4 without
-- it. The first heartbeat of node 0 ends at the transaction, whose term node 1
-- knows already, and before the entry of term 3.
initialize scenario "heartbeat_before_stale_suffix" do
  startNode 0
  trustNode 2 1
  replicate 2 [signature, "x"]
  dispatchAll
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "2.4"
  -- Initial network state [0, 1]. The acknowledgements of 1 are lost, so
  -- nothing is committed
  dropPending 1

  -- 1 is elected in term 3, and keeps 2.4, which is not signed
  periodicOne 1 100
  dispatchOne 1
  dispatchOne 0
  dispatchOne 1
  dispatchOne 0
  assertDetail 1 "leadership_state" "Leader"
  assertLastTxid 1 "2.4"
  dropPending 1

  -- 1 appends 3.5, which 0 does not receive
  replicate 3 ["y"]
  assertLastTxid 1 "3.5"

  -- 0 is elected in term 4, and keeps 2.4 too
  periodicOne 0 100
  dispatchOne 0
  dispatchOne 1
  dispatchOne 0
  dispatchOne 1
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertLastTxid 0 "2.4"
  assertPending 1 0 0

  -- The first heartbeat of 0 ends at 2.4. 1 acknowledges it, and keeps 3.5
  dispatchOne 0
  assertLastTxid 1 "3.5"
  assertPending 1 0 1
  dispatchOne 1

  -- 0 signs at 4.5, which replaces 3.5 on 1, and commits
  replicate 4 [signature]
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "4.5"
  dispatchOne 1
  periodicOne 0 10
  dispatchOne 0

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 5
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 5
